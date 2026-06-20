package engine

import (
	"context"

	"github.com/lexdotdev/nocapsec/internal/policy"
	"github.com/lexdotdev/nocapsec/internal/validators"
)

// enforcer is a PolicyEnforcer backed by
// a policy.Checker.
type enforcer struct {
	checker *policy.Checker
}

// NewEnforcer builds a PolicyEnforcer from
// policy and resolver.
func NewEnforcer(p policy.URLPolicy, r policy.Resolver) validators.PolicyEnforcer {
	return &enforcer{checker: policy.NewChecker(p, r)}
}

func (e *enforcer) CheckURL(raw string, phase policy.Phase) (*policy.SafeURL, error) {
	return e.checker.CheckURL(raw, phase)
}

func (e *enforcer) CheckRedirect(from, to string) error {
	return e.checker.CheckRedirect(from, to)
}

// BrowserProxyFor starts a local CONNECT proxy
// enforcing policy.
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

// EnforcerFromTarget builds a PolicyEnforcer
// from target scope.
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

// targetPolicy is the evidence.Target subset
// the enforcer reads.
type targetPolicy struct {
	AllowedSchemes     []string
	AllowedHosts       []string
	AllowedPorts       []int
	ExpectedOrigin     string
	InternalAssessment bool
}
