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
	// kindJSONOperator plants a JSON fragment.
	kindJSONOperator = "json_operator"
	kindHeader       = "header"
	// kindURLToken: raw value at a {{name}} URL token.
	kindURLToken = "url_token"
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
	case kindQuery, kindForm, kindHeader, kindURLToken:
		return loc.Name != ""
	case kindJSONBody, kindJSONOperator:
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
		return injectJSONValue(req, loc.JSONPointer, value)
	case kindJSONOperator:
		return injectJSONOperator(req, loc.JSONPointer, value)
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
	case kindURLToken:
		return injectURLToken(req, loc.Name, value)
	default:
		return evidence.Request{}, fmt.Errorf("unsupported injection kind %q", loc.Kind)
	}
}

// injectURLToken fills a URL token.
func injectURLToken(req evidence.Request, name, value string) (evidence.Request, error) {
	if strings.ContainsAny(value, "\r\n") {
		return evidence.Request{}, errHeaderCRLF
	}
	if !hasSlot(req.URL, name) {
		return evidence.Request{}, fmt.Errorf("missing url token {{%s}}", name)
	}
	out := req
	out.URL = replaceSlot(req.URL, name, value)
	return out, nil
}

var errHeaderCRLF = fmt.Errorf("header value contains CR or LF")

func injectHeader(req evidence.Request, name, value string) (evidence.Request, error) {
	if strings.ContainsAny(value, "\r\n") {
		return evidence.Request{}, errHeaderCRLF
	}
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
