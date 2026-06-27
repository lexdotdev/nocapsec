package validators

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/httpx"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type crlfResponseSplitting struct{}

func (crlfResponseSplitting) Type() string    { return "crlf.response_splitting" }
func (crlfResponseSplitting) Cap() Capability { return CapHTTPReplay }

// Validate proves parsed-header injection.
func (crlfResponseSplitting) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	cand, ctl, reps, ok := crlfArms(job)
	if !ok {
		return Result{Verdict: verdict.Invalid}, nil
	}
	bundle := httpx.NewClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL owns timeout

	var headerName string
	var redirects []string
	for i := range reps {
		name, hops, candOnly, err := crlfReplay(ctx, bundle, cand, ctl, job.Nonce)
		if err != nil {
			return Result{Verdict: verdict.Inconclusive}, err
		}
		if !candOnly {
			if i == 0 {
				return Result{Verdict: verdict.NotReproduced}, nil
			}
			return Result{Verdict: verdict.Inconclusive}, nil // later-rep instability
		}
		headerName, redirects = name, hops
	}

	return Result{
		Verdict: verdict.Verified,
		Proof: proofJSON(crlfProofBlock{
			InjectedHeader:        headerName,
			Nonce:                 job.Nonce,
			Repetitions:           reps,
			HeaderInCandidate:     true,
			HeaderAbsentInControl: true,
		}),
		Redirects: redirects,
	}, nil
}

// crlfArms builds nonce/control arms.
func crlfArms(job Job) (cand, ctl evidence.Request, reps int, ok bool) {
	var ev sqliBooleanEvidence
	if json.Unmarshal(job.Finding.Evidence, &ev) != nil {
		return cand, ctl, 0, false
	}
	var proof crlfProof
	if json.Unmarshal(job.Finding.Proof, &proof) != nil {
		return cand, ctl, 0, false
	}
	control, okC := ev.Injection.Payloads["control"]
	split, okS := ev.Injection.Payloads["split"]
	if ev.BaseRequest.Method == "" || ev.BaseRequest.URL == "" ||
		!ev.Injection.Location.valid() || !okC || !okS || !hasNonceSlot(split) {
		return cand, ctl, 0, false
	}
	var err1, err2 error
	cand, err1 = injectValue(ev.BaseRequest, ev.Injection.Location, replaceNonceSlot(split, job.Nonce))
	ctl, err2 = injectValue(ev.BaseRequest, ev.Injection.Location, control)
	if err1 != nil || err2 != nil {
		return cand, ctl, 0, false
	}
	reps = proof.Repetitions
	if reps < 1 {
		reps = 2
	}
	return cand, ctl, reps, true
}

// crlfReplay checks candidate-only signal.
func crlfReplay(ctx context.Context, bundle *httpx.ClientBundle, cand, ctl evidence.Request, nonce string) (header string, redirects []string, candOnly bool, err error) {
	candCap, err := httpx.Replay(ctx, bundle, cand)
	if err != nil {
		return "", nil, false, err
	}
	ctlCap, err := httpx.Replay(ctx, bundle, ctl)
	if err != nil {
		return "", nil, false, err
	}
	name, candHas := splitSignal(candCap.RespHeaders, nonce)
	_, ctlHas := splitSignal(ctlCap.RespHeaders, nonce)
	return name, formatRedirects(candCap.Redirects), candHas && !ctlHas, nil
}

// splitSignal finds a parsed nonce header.
func splitSignal(headers []evidence.Header, nonce string) (string, bool) {
	needle := strings.ToLower(nonce)
	for _, h := range headers {
		if strings.Contains(strings.ToLower(h.Name), needle) {
			return h.Name, true
		}
		if strings.TrimSpace(h.Value) == nonce {
			return h.Name, true
		}
	}
	return "", false
}

type crlfProof struct {
	Repetitions int `json:"repetitions"`
}

type crlfProofBlock struct {
	InjectedHeader        string `json:"injected_header"`
	Nonce                 string `json:"nonce"`
	Repetitions           int    `json:"repetitions"`
	HeaderInCandidate     bool   `json:"header_in_candidate"`
	HeaderAbsentInControl bool   `json:"header_absent_in_control"`
}
