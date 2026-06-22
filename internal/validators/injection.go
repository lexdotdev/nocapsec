package validators

import (
	"fmt"
	"strings"

	"github.com/lexdotdev/nocapsec/internal/evidence"
)

// Injection slot kinds.
const (
	kindQuery    = "query"
	kindForm     = "form"
	kindJSONBody = "json_body"
	kindHeader   = "header"
)

// InjectionLocation names a declared request slot.
type InjectionLocation struct {
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	JSONPointer string `json:"json_pointer"`
}

// valid reports whether loc names a usable slot.
func (loc InjectionLocation) valid() bool {
	switch loc.Kind {
	case kindQuery, kindForm, kindHeader:
		return loc.Name != ""
	case kindJSONBody:
		return loc.JSONPointer != ""
	default:
		return false
	}
}

// injectionEvidence: one slot with per-arm values.
type injectionEvidence struct {
	Location InjectionLocation `json:"location"`
	Payloads map[string]string `json:"payloads"`
}

// injectValue plants value into the declared slot.
func injectValue(req evidence.Request, loc InjectionLocation, value string) (evidence.Request, error) {
	switch loc.Kind {
	case kindQuery:
		return injectQuery(req, loc.Name, value)
	case kindJSONBody:
		return injectJSONBody(req, loc.JSONPointer, value)
	case kindForm:
		patched, err := injectFormField(req.Body, loc.Name, value)
		if err != nil {
			return evidence.Request{}, err
		}
		out := req
		out.Body = patched
		return out, nil
	case kindHeader:
		return injectHeader(req, loc.Name, value)
	default:
		return evidence.Request{}, fmt.Errorf("unsupported injection kind %q", loc.Kind)
	}
}

// injectHeader writes value into the declared header,
// which must already exist in base_request. A Host
// header reaches the wire via buildRequest.
func injectHeader(req evidence.Request, name, value string) (evidence.Request, error) {
	out := req
	hs := make([]evidence.Header, len(req.Headers))
	copy(hs, req.Headers)
	found := false
	for i := range hs {
		if strings.EqualFold(hs[i].Name, name) {
			hs[i].Value = value
			found = true
		}
	}
	if !found {
		return evidence.Request{}, fmt.Errorf("missing header %q", name)
	}
	out.Headers = hs
	return out, nil
}
