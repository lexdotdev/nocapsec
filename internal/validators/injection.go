package validators

import (
	"fmt"

	"github.com/lexdotdev/nocapsec/internal/evidence"
)

// Injection slot kinds.
const (
	kindQuery    = "query"
	kindForm     = "form"
	kindJSONBody = "json_body"
)

// InjectionLocation names a single declared slot in a request.
type InjectionLocation struct {
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	JSONPointer string `json:"json_pointer"`
}

// valid reports whether loc names a usable slot.
func (loc InjectionLocation) valid() bool {
	switch loc.Kind {
	case kindQuery, kindForm:
		return loc.Name != ""
	case kindJSONBody:
		return loc.JSONPointer != ""
	default:
		return false
	}
}

// injectionEvidence is the engine-owned contrast: one slot, per-arm values.
type injectionEvidence struct {
	Location InjectionLocation `json:"location"`
	Payloads map[string]string `json:"payloads"`
}

// injectValue plants value into the single declared location of req.
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
	default:
		return evidence.Request{}, fmt.Errorf("unsupported injection kind %q", loc.Kind)
	}
}
