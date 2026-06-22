package engine

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/policy"
	"github.com/lexdotdev/nocapsec/internal/validators"
)

// enforcer wraps a policy.Checker.
type enforcer struct {
	checker *policy.Checker
}

// NewEnforcer builds a PolicyEnforcer.
func NewEnforcer(p policy.URLPolicy, r policy.Resolver) validators.PolicyEnforcer {
	return &enforcer{checker: policy.NewChecker(p, r)}
}

func (e *enforcer) CheckURL(raw string, phase policy.Phase) (*policy.SafeURL, error) {
	return e.checker.CheckURL(raw, phase)
}

func (e *enforcer) CheckRedirect(from, to string) error {
	return e.checker.CheckRedirect(from, to)
}

// BrowserProxyFor starts a policy proxy.
func (e *enforcer) BrowserProxyFor(job validators.Job) (string, func(), error) {
	checker := e.checker
	if len(job.BrowserAllowedOrigins) > 0 {
		p := checker.Policy
		p.AllowExternalFinal = true
		p.ExternalFinalOrigins = append(append([]policy.Origin{}, p.ExternalFinalOrigins...), job.BrowserAllowedOrigins...)
		checker = policy.NewChecker(p, checker.Resolver)
	}
	proxy, err := policy.NewConnectProxy(checker)
	if err != nil {
		return "", nil, err
	}
	proxy.Start()
	cleanup := func() {
		_ = proxy.Shutdown(context.Background())
	}
	return proxy.URL(), cleanup, nil
}

func (e *enforcer) Checker() *policy.Checker { return e.checker }

// EnforcerFromTarget builds target policy.
func EnforcerFromTarget(t targetPolicy, r policy.Resolver) validators.PolicyEnforcer {
	p := policy.URLPolicy{
		AllowedSchemes:     t.AllowedSchemes,
		AllowedHosts:       t.AllowedHosts,
		AllowedPorts:       t.AllowedPorts,
		ExpectedOrigin:     t.ExpectedOrigin,
		AllowRedirects:     true,
		MaxRedirects:       5,
		BlockPrivateIPs:    !t.InternalAssessment,
		BlockLoopback:      !t.InternalAssessment,
		BlockLinkLocal:     !t.InternalAssessment,
		BlockMulticast:     true,
		BlockUnspecified:   true,
		BlockCloudMetadata: !t.InternalAssessment,
		InternalAssessment: t.InternalAssessment,
	}
	return NewEnforcer(p, r)
}

// targetPolicy is the needed target subset.
type targetPolicy struct {
	AllowedSchemes     []string
	AllowedHosts       []string
	AllowedPorts       []int
	ExpectedOrigin     string
	InternalAssessment bool
}
