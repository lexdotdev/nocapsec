package engine

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/policy"
	"github.com/lexdotdev/nocapsec/internal/validators"
)

// enforcer satisfies validators.PolicyEnforcer by delegating to a policy.Checker
// built from the finding's target policy and a resolver.
type enforcer struct {
	checker *policy.Checker
}

// NewEnforcer builds a PolicyEnforcer from a URLPolicy and a Resolver.
func NewEnforcer(p policy.URLPolicy, r policy.Resolver) validators.PolicyEnforcer {
	return &enforcer{checker: policy.NewChecker(p, r)}
}

func (e *enforcer) CheckURL(raw string, phase policy.Phase) (*policy.SafeURL, error) {
	return e.checker.CheckURL(raw, phase)
}

func (e *enforcer) CheckRedirect(from, to string) error {
	return e.checker.CheckRedirect(from, to)
}

// BrowserProxyFor starts a local CONNECT proxy enforcing policy on every
// tunnel. Returns the proxy URL, a cleanup func, and any error.
func (e *enforcer) BrowserProxyFor(_ validators.Job) (string, func(), error) {
	proxy, err := policy.NewConnectProxy(e.checker)
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

// EnforcerFromTarget builds a PolicyEnforcer from target scope fields.
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

// targetPolicy is the subset of evidence.Target the enforcer reads.
type targetPolicy struct {
	AllowedSchemes     []string
	AllowedHosts       []string
	AllowedPorts       []int
	ExpectedOrigin     string
	InternalAssessment bool
}
