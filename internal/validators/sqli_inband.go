package validators

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"

	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/httpx"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

type sqliInband struct{}

func (sqliInband) Type() string    { return "sqli.inband" }
func (sqliInband) Cap() Capability { return CapHTTPReplay }

func (sqliInband) Validate(ctx context.Context, job Job, env Env) (Result, error) {
	ev, proof, ok := decodeInband(job)
	if !ok {
		return Result{Verdict: verdict.Invalid}, nil
	}
	control, inband, ok := inbandPayloads(ev)
	if !ok {
		return Result{Verdict: verdict.Invalid}, nil
	}

	reps := proof.Repetitions
	if reps < 1 {
		reps = 2
	}

	bundle := httpx.NewClient(env.Policy.Checker()) //nolint:contextcheck // CheckURL drives its own resolver timeout

	var lastProduct string
	var lastRedirects []string
	for i := range reps {
		expr, product, err := newComputedMarker()
		if err != nil {
			return Result{Verdict: verdict.Inconclusive}, err
		}
		inb, ctl, ok := inbandArms(ev, control, inband, expr)
		if !ok {
			return Result{Verdict: verdict.Invalid}, nil
		}
		inbandHas, controlHas, redirects, err := replayInbandPair(ctx, bundle, inb, ctl, product)
		if err != nil {
			return Result{Verdict: verdict.Inconclusive}, err
		}
		// The database must compute the product (inband) and the benign
		// control must not surface it.
		if !inbandHas || controlHas {
			if i == 0 {
				return Result{Verdict: verdict.NotReproduced}, nil
			}
			// Later-rep instability -> inconclusive.
			return Result{Verdict: verdict.Inconclusive}, nil
		}
		lastProduct, lastRedirects = product, redirects
	}

	return Result{
		Verdict: verdict.Verified,
		Proof: proofJSON(sqliInbandProofBlock{
			ComputedMarker:        lastProduct,
			Repetitions:           reps,
			MarkerInInband:        true,
			MarkerAbsentInControl: true,
		}),
		Redirects: lastRedirects,
	}, nil
}

// decodeInband unmarshals evidence + proof.
func decodeInband(job Job) (sqliBooleanEvidence, sqliInbandProof, bool) {
	var ev sqliBooleanEvidence // same shape: base_request + injection
	if err := json.Unmarshal(job.Finding.Evidence, &ev); err != nil {
		return ev, sqliInbandProof{}, false
	}
	var proof sqliInbandProof
	if err := json.Unmarshal(job.Finding.Proof, &proof); err != nil {
		return ev, proof, false
	}
	return ev, proof, true
}

// inbandPayloads returns the control/inband values
// after validating shape and the marker slot.
func inbandPayloads(ev sqliBooleanEvidence) (control, inband string, ok bool) {
	control, okC := ev.Injection.Payloads["control"]
	inband, okI := ev.Injection.Payloads["inband"]
	if ev.BaseRequest.Method == "" || ev.BaseRequest.URL == "" ||
		!ev.Injection.Location.valid() || !okC || !okI || !hasMarkerSlot(inband) {
		return "", "", false
	}
	return control, inband, true
}

// inbandArms plants the computed expression into the
// inband arm and the benign value into the control.
func inbandArms(ev sqliBooleanEvidence, control, inband, expr string) (inb, ctl evidence.Request, ok bool) {
	inb, err1 := injectValue(ev.BaseRequest, ev.Injection.Location, replaceMarkerSlot(inband, expr))
	ctl, err2 := injectValue(ev.BaseRequest, ev.Injection.Location, replaceMarkerSlot(control, expr))
	if err1 != nil || err2 != nil {
		return evidence.Request{}, evidence.Request{}, false
	}
	return inb, ctl, true
}

// replayInbandPair sends both arms and reports where
// the DB-computed product surfaced.
func replayInbandPair(
	ctx context.Context, bundle *httpx.ClientBundle, inb, ctl evidence.Request, product string,
) (inbandHas, controlHas bool, redirects []string, err error) {
	inbandCap, err := httpx.Replay(ctx, bundle, inb)
	if err != nil {
		return false, false, nil, err
	}
	controlCap, err := httpx.Replay(ctx, bundle, ctl)
	if err != nil {
		return false, false, nil, err
	}
	inbandHas = strings.Contains(string(inbandCap.RespBody), product)
	controlHas = strings.Contains(string(controlCap.RespBody), product)
	return inbandHas, controlHas, formatRedirects(inbandCap.Redirects), nil
}

type sqliInbandProof struct {
	ExpectedMarkerInInband        bool `json:"expected_marker_in_inband"`
	ExpectedMarkerAbsentInControl bool `json:"expected_marker_absent_in_control"`
	Repetitions                   int  `json:"repetitions"`
}

type sqliInbandProofBlock struct {
	ComputedMarker        string `json:"computed_marker"`
	Repetitions           int    `json:"repetitions"`
	MarkerInInband        bool   `json:"marker_in_inband"`
	MarkerAbsentInControl bool   `json:"marker_absent_in_control"`
}

// newComputedMarker returns a SQL arithmetic
// expression "A*B" and the decimal product the
// database must compute. The operands are sent; the
// product never is, so reflection cannot fake it.
func newComputedMarker() (expr, product string, err error) {
	a, err := randOperand()
	if err != nil {
		return "", "", err
	}
	b, err := randOperand()
	if err != nil {
		return "", "", err
	}
	expr = strconv.FormatInt(a, 10) + "*" + strconv.FormatInt(b, 10)
	product = strconv.FormatInt(a*b, 10)
	return expr, product, nil
}

// randOperand returns a 5-digit operand, so the
// product is ~10 digits (well within int64 and
// unlikely to appear by chance).
func randOperand() (int64, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(90000))
	if err != nil {
		return 0, err
	}
	return 10000 + n.Int64(), nil
}

func init() { Register(sqliInband{}) }
