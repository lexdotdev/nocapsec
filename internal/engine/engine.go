// Package engine runs bounded verification.
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/authstate"
	"github.com/lexdotdev/nocapsec/internal/browser"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/oast"
	"github.com/lexdotdev/nocapsec/internal/policy"
	"github.com/lexdotdev/nocapsec/internal/validators"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// ErrNotImplemented means a Task has no Run func.
var ErrNotImplemented = errors.New("engine: not implemented")

// Limits caps work per target.
type Limits struct {
	HTTPReplay int
	Timing     int
	Browser    int
	OAST       int
}

// For returns a capability limit.
func (l Limits) For(c Capability) int {
	switch c {
	case CapHTTPReplay:
		return l.HTTPReplay
	case CapTiming:
		return l.Timing
	case CapBrowser:
		return l.Browser
	case CapOAST:
		return l.OAST
	default:
		return 0
	}
}

func DefaultLimits() Limits {
	return Limits{HTTPReplay: 5, Timing: 1, Browser: 2, OAST: 8}
}

// Config wires engine dependencies.
type Config struct {
	Limits    Limits
	Resolver  policy.Resolver
	Store     artifacts.ArtifactStore
	AuthStore authstate.Store
	// Browser runs client proofs.
	Browser browser.BrowserRunner
	// OAST handles callbacks.
	OAST oast.OAST
	// InternalAssessment allows blocked ranges.
	InternalAssessment bool
	// Logger receives events.
	Logger Logger
}

func (c Config) withDefaults() Config {
	d := DefaultLimits()
	if c.Limits.HTTPReplay == 0 {
		c.Limits.HTTPReplay = d.HTTPReplay
	}
	if c.Limits.Timing == 0 {
		c.Limits.Timing = d.Timing
	}
	if c.Limits.Browser == 0 {
		c.Limits.Browser = d.Browser
	}
	if c.Limits.OAST == 0 {
		c.Limits.OAST = d.OAST
	}
	if c.Resolver == nil {
		c.Resolver = policy.NewSystemResolver()
	}
	if c.Store == nil {
		c.Store = artifacts.NewStore()
	}
	if c.Logger == nil {
		c.Logger = nopLogger{}
	}
	return c
}

// Engine owns verification pools.
type Engine struct {
	dispatcher         Dispatcher
	jobs               *jobStore
	resolver           policy.Resolver
	store              artifacts.ArtifactStore
	authStore          authstate.Store
	browser            browser.BrowserRunner
	oast               oast.OAST
	clock              validators.Clock
	logger             Logger
	metrics            *Metrics
	internalAssessment bool
	closed             atomic.Bool
}

// New wires the engine.
func New(cfg Config) (*Engine, error) {
	cfg = cfg.withDefaults()
	return &Engine{
		dispatcher:         newDispatcher(cfg.Limits),
		jobs:               newJobStore(),
		resolver:           cfg.Resolver,
		store:              cfg.Store,
		authStore:          cfg.AuthStore,
		browser:            cfg.Browser,
		oast:               cfg.OAST,
		clock:              validators.WallClock{},
		logger:             cfg.Logger,
		metrics:            NewMetrics(),
		internalAssessment: cfg.InternalAssessment,
	}, nil
}

// ErrClosed is returned by Verify after Close.
var ErrClosed = errors.New("engine: closed")

// Verify returns a terminal report.
func (e *Engine) Verify(ctx context.Context, raw []byte) (verdict.Report, error) {
	if e.closed.Load() {
		return verdict.Report{}, ErrClosed
	}

	finding, err := evidence.Parse(raw)
	if err != nil {
		r := e.invalidReport(err)
		e.metrics.RecordVerdict(r.Verdict)
		return r, nil
	}

	e.logger.Info("verify_start", "finding_id", finding.FindingID, "type", finding.Type)

	jobID, err := generateRandomHex()
	if err != nil {
		return verdict.Report{}, err
	}

	artRefs := e.persistEarlyArtifacts(ctx, jobID, finding)

	pe := e.buildEnforcer(finding)

	if reason, policyErr := checkEvidencePolicy(finding, pe); policyErr != nil {
		r := verdict.Reasoned(finding.FindingID, finding.Type, verdict.Rejected, reason).Stamp(e.clock.Now())
		r.TargetOrigin = finding.Target.ExpectedOrigin
		r.Artifacts = artRefs
		e.metrics.RecordVerdict(r.Verdict)
		e.logger.Info("verify_done", "finding_id", finding.FindingID, "verdict", string(r.Verdict))
		return r, nil //nolint:nilerr // rejected verdict
	}

	if reason := e.checkAuthIfRequired(ctx, finding); reason != "" {
		r := verdict.Reasoned(finding.FindingID, finding.Type, verdict.Inconclusive, reason).Stamp(e.clock.Now())
		r.Artifacts = artRefs
		e.metrics.RecordVerdict(r.Verdict)
		e.logger.Info("verify_done", "finding_id", finding.FindingID, "verdict", string(r.Verdict))
		return r, nil
	}

	report, err := e.planAndDispatch(ctx, finding, pe, raw, jobID, artRefs)
	if err != nil {
		return verdict.Report{}, err
	}
	e.metrics.RecordVerdict(report.Verdict)
	e.logger.Info("verify_done", "finding_id", finding.FindingID, "verdict", string(report.Verdict))
	return report, nil
}

// Metrics returns counters.
func (e *Engine) Metrics() *Metrics { return e.metrics }

func (e *Engine) invalidReport(err error) verdict.Report {
	var ie *evidence.InvalidError
	if errors.As(err, &ie) {
		return verdict.Reasoned("", "", verdict.Invalid, ie.Reason).Stamp(e.clock.Now())
	}
	return verdict.Reasoned("", "", verdict.Invalid, "parse_error").Stamp(e.clock.Now())
}

func (e *Engine) persistEarlyArtifacts(ctx context.Context, jobID string, f *evidence.Finding) verdict.ArtifactRefs {
	refs := verdict.ArtifactRefs{}
	if ref, err := e.store.Put(ctx, jobID, artifacts.KindEvidence, f.Evidence); err == nil {
		refs["evidence"] = ref
	}
	if data, err := json.Marshal(f.Target); err == nil {
		if ref, err := e.store.Put(ctx, jobID, artifacts.KindPolicySnapshot, data); err == nil {
			refs["policy"] = ref
		}
	}
	return refs
}

func (e *Engine) buildEnforcer(f *evidence.Finding) validators.PolicyEnforcer {
	return EnforcerFromTarget(targetPolicy{
		AllowedSchemes:     f.Target.AllowedSchemes,
		AllowedHosts:       f.Target.AllowedHosts,
		AllowedPorts:       f.Target.AllowedPorts,
		ExpectedOrigin:     f.Target.ExpectedOrigin,
		InternalAssessment: e.internalAssessment,
	}, e.resolver)
}

func (e *Engine) checkAuthIfRequired(ctx context.Context, f *evidence.Finding) string {
	if !f.Auth.Required || f.Auth.AuthStateID == "" || e.authStore == nil {
		return ""
	}
	return e.checkAuth(ctx, f.Auth.AuthStateID)
}

func (e *Engine) planAndDispatch(ctx context.Context, finding *evidence.Finding, pe validators.PolicyEnforcer, raw []byte, jobID string, artRefs verdict.ArtifactRefs) (verdict.Report, error) {
	v, ok := validators.Lookup(finding.Type)
	if !ok {
		return verdict.Reasoned(finding.FindingID, finding.Type, verdict.Invalid, "no_validator").Stamp(e.clock.Now()), nil
	}

	nonce, err := generateRandomHex()
	if err != nil {
		return verdict.Report{}, err
	}

	job := validators.Job{Finding: *finding, Nonce: nonce}
	env := validators.Env{
		Policy:    pe,
		Artifacts: e.store,
		AuthStore: e.authStore,
		Browser:   e.browser,
		OAST:      e.oast,
		Clock:     e.clock,
	}

	var vResult validators.Result
	var vErr error
	task := Task{
		Capability: v.Cap(),
		Target:     finding.Target.AllowedHosts[0],
		Run: func(ctx context.Context) error {
			vResult, vErr = v.Validate(ctx, job, env)
			return nil
		},
	}

	e.metrics.RecordPool(v.Cap())
	if dispErr := e.dispatcher.Dispatch(ctx, task); dispErr != nil {
		r := verdict.Reasoned(finding.FindingID, finding.Type, verdict.Inconclusive, "dispatch_error").Stamp(e.clock.Now())
		r.Artifacts = artRefs
		return r, nil //nolint:nilerr // dispatch failure -> Inconclusive
	}

	if ref, putErr := e.store.Put(ctx, jobID, artifacts.KindHTTPExchange, raw); putErr == nil {
		artRefs["http_exchange"] = ref
	}

	report := evaluate(finding, vResult, vErr, e.clock.Now())
	report.Artifacts = artRefs
	return report, nil
}

// checkAuth returns an auth failure reason.
func (e *Engine) checkAuth(ctx context.Context, authStateID string) string {
	_, err := e.authStore.Get(ctx, authStateID)
	if err != nil {
		if errors.Is(err, authstate.ErrExpired) {
			return "auth_expired"
		}
		if errors.Is(err, authstate.ErrNotFound) {
			return "auth_not_found"
		}
		return "auth_healthcheck_failed"
	}
	return ""
}

// evaluate maps validation to a report.
func evaluate(f *evidence.Finding, res validators.Result, err error, now time.Time) verdict.Report {
	pol := verdict.PolicySummary{
		SchemeOK:            true,
		InitialOriginPinned: true,
		FinalOriginOK:       true,
		Redirects:           res.Redirects,
	}

	if err != nil {
		var re *policy.RejectionError
		if errors.As(err, &re) {
			return verdict.Reasoned(f.FindingID, f.Type, verdict.Rejected, re.Reason).Stamp(now)
		}
		return verdict.Reasoned(f.FindingID, f.Type, verdict.Inconclusive, "operational_error").Stamp(now)
	}

	switch res.Verdict {
	case verdict.Verified:
		return verdict.Proven(f.FindingID, f.Type, f.Target.ExpectedOrigin, res.Proof, pol).Stamp(now)
	case verdict.NotReproduced:
		return verdict.Unproven(f.FindingID, f.Type, f.Target.ExpectedOrigin, pol).Stamp(now)
	case verdict.Rejected:
		return verdict.Reasoned(f.FindingID, f.Type, verdict.Rejected, "policy_violation").Stamp(now)
	case verdict.Invalid:
		return verdict.Reasoned(f.FindingID, f.Type, verdict.Invalid, "validator_invalid").Stamp(now)
	default:
		return verdict.Reasoned(f.FindingID, f.Type, verdict.Inconclusive, "unknown_verdict").Stamp(now)
	}
}

// checkEvidencePolicy gates request URLs.
func checkEvidencePolicy(f *evidence.Finding, pe validators.PolicyEnforcer) (string, error) {
	urls := extractURLs(f)
	for _, u := range urls {
		if _, err := pe.CheckURL(u, policy.PhaseInitial); err != nil {
			var re *policy.RejectionError
			if errors.As(err, &re) {
				return re.Reason, err
			}
			return "policy_check_failed", err
		}
	}
	return "", nil
}

// extractURLs gathers request URLs.
func extractURLs(f *evidence.Finding) []string {
	var urls []string
	if reqs := evidence.ExtractRequests(f); len(reqs) > 0 {
		for _, r := range reqs {
			if r.URL != "" {
				urls = append(urls, r.URL)
			}
		}
	}
	return urls
}

// generateRandomHex returns 128-bit hex.
func generateRandomHex() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Handler returns the HTTP API.
func (e *Engine) Handler() http.Handler {
	return newServer(e).handler()
}

// Close drains in-flight tasks.
func (e *Engine) Close() error {
	e.closed.Store(true)
	e.logger.Info("engine_close", "status", "draining")
	err := e.dispatcher.Close()
	e.logger.Info("engine_close", "status", "done")
	return err
}
