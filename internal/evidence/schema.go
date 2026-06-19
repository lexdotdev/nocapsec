package evidence

import "encoding/json"

// schema.go holds the per-type evidence/proof shape registry. Adding a
// vulnerability type means adding its entry below.

// ftype is the JSON shape a field must have.
type ftype uint8

const (
	fString ftype = iota
	fNumber
	fBool
	fObject
	fArray
	fRequest // object with non-empty method + url
)

// field is one key in an object schema.
type field struct {
	name     string
	typ      ftype
	required bool
}

// objSchema validates a JSON object: field types, required keys, and (strict)
// rejection of unknown keys.
type objSchema struct {
	fields []field
	strict bool
}

// typeSchema is the per-type evidence/proof contract. requests and
// requestArrays are dotted paths to request objects, canonicalized for replay.
type typeSchema struct {
	evidence      objSchema
	proof         objSchema
	requests      []string
	requestArrays []string
}

// req/opt build fields tersely.
func req(name string, t ftype) field { return field{name, t, true} }
func opt(name string, t ftype) field { return field{name, t, false} }

// typeSchemas is the registry evidence/proof is validated against. A type
// absent here has no validator and yields invalid.
var typeSchemas = map[string]typeSchema{
	"path_traversal.file_read": {
		evidence: objSchema{strict: true, fields: []field{
			req("request", fRequest),
			req("vulnerable_parameter", fString),
			req("expected_markers", fArray),
			req("negative_control", fRequest),
		}},
		proof: objSchema{strict: true, fields: []field{
			req("require_marker", fBool),
			req("require_negative_control_absent", fBool),
		}},
		requests: []string{"request", "negative_control"},
	},

	"xss.reflected": {
		evidence: objSchema{strict: true, fields: []field{
			req("entrypoint", fRequest),
			req("payload_marker", fString),
			req("trigger", fObject),
			opt("vulnerable_parameter", fString),
		}},
		proof: objSchema{strict: true, fields: []field{
			req("accepted_signals", fArray),
			req("expected_message_contains", fString),
			req("expected_execution_origin", fString),
			opt("allow_iframe_execution", fBool),
			opt("timeout_ms", fNumber),
		}},
		requests: []string{"entrypoint"},
	},

	"xss.stored": {
		evidence: objSchema{strict: true, fields: []field{
			req("setup", fArray),
			req("trigger", fRequest),
			req("vulnerable_parameter", fString),
			req("payload_marker", fString),
		}},
		proof: objSchema{strict: true, fields: []field{
			req("accepted_signals", fArray),
			req("expected_message_contains", fString),
			req("expected_execution_origin", fString),
			req("timeout_ms", fNumber),
		}},
		requests:      []string{"trigger"},
		requestArrays: []string{"setup"},
	},

	"xss.blind": {
		evidence: objSchema{strict: true, fields: []field{
			req("request", fRequest),
			req("mutation_slots", fObject),
			opt("payload_marker", fString),
		}},
		proof: objSchema{strict: true, fields: []field{
			req("expected_signal", fString),
			req("expected_path_contains", fString),
			opt("poll_window_seconds", fNumber),
		}},
		requests: []string{"request"},
	},

	"open_redirect": {
		evidence: objSchema{strict: true, fields: []field{
			req("entrypoint", fRequest),
			req("redirect_parameter", fString),
			req("expected_initial_origin", fString),
			req("expected_final_origin", fString),
			opt("redirect_kind", fString),
			opt("max_hops", fNumber),
		}},
		proof: objSchema{strict: true, fields: []field{
			req("expected_signal", fString),
			req("require_initial_target_origin", fBool),
			req("require_final_external_origin", fBool),
			opt("timeout_ms", fNumber),
		}},
		requests: []string{"entrypoint"},
	},

	"sqli.time_based": {
		evidence: objSchema{strict: true, fields: []field{
			req("requests", fObject),
			req("vulnerable_parameter", fString),
			opt("expected_low_delay_ms", fNumber),
			opt("expected_high_delay_ms", fNumber),
			opt("dbms_hint", fString),
		}},
		proof: objSchema{strict: true, fields: []field{
			opt("repetitions", fNumber),
			opt("randomize_order", fBool),
			opt("min_median_delta_ms", fNumber),
			opt("max_status_code_drift", fBool),
			opt("require_body_similarity", fBool),
			opt("timeout_ms", fNumber),
		}},
		requests: []string{"requests.control", "requests.delay_low", "requests.delay_high"},
	},

	"sqli.boolean_based": {
		evidence: objSchema{strict: true, fields: []field{
			req("requests", fObject),
			req("vulnerable_parameter", fString),
		}},
		proof: objSchema{strict: true, fields: []field{
			req("expected_true_similarity_to_baseline", fBool),
			req("expected_false_difference", fBool),
			req("compare", fArray),
			req("repetitions", fNumber),
		}},
		requests: []string{"requests.baseline", "requests.true_condition", "requests.false_condition"},
	},

	"ssrf.oast": {
		evidence: objSchema{strict: true, fields: []field{
			req("request", fRequest),
			req("injection_location", fObject),
			opt("expected_protocols", fArray),
		}},
		proof: objSchema{strict: true, fields: []field{
			req("expected_signal", fString),
			req("poll_window_seconds", fNumber),
			opt("require_source_not_verifier", fBool),
		}},
		requests: []string{"request"},
	},

	"xxe.oast": {
		evidence: objSchema{strict: true, fields: []field{
			req("request", fRequest),
			req("mutation_slots", fObject),
		}},
		proof: objSchema{strict: true, fields: []field{
			req("expected_signal", fString),
			req("poll_window_seconds", fNumber),
		}},
		requests: []string{"request"},
	},

	"command_injection.time_based": {
		evidence: objSchema{strict: true, fields: []field{
			req("requests", fObject),
			req("vulnerable_parameter", fString),
		}},
		proof: objSchema{strict: true, fields: []field{
			opt("repetitions", fNumber),
			opt("min_median_delta_ms", fNumber),
			opt("require_body_similarity", fBool),
		}},
		requests: []string{"requests.control", "requests.delay_low", "requests.delay_high"},
	},

	"command_injection.oast": {
		evidence: objSchema{strict: true, fields: []field{
			req("request", fRequest),
			req("mutation_slots", fObject),
		}},
		proof: objSchema{strict: true, fields: []field{
			req("expected_signal", fString),
		}},
		requests: []string{"request"},
	},

	"idor.read": {
		evidence: objSchema{strict: true, fields: []field{
			req("resource_owner_auth_state_id", fString),
			req("attacker_auth_state_id", fString),
			req("setup_resource", fRequest),
			req("attack_request", fRequest),
		}},
		proof: objSchema{strict: true, fields: []field{
			req("expected_marker", fString),
			req("require_owner_control", fBool),
		}},
		requests: []string{"setup_resource", "attack_request"},
	},
}

// checkObject validates raw against s, returning a stable *InvalidError on the
// first violation. where names the object for diagnostics ("evidence").
func checkObject(raw json.RawMessage, s objSchema, where string) error {
	m, err := decodeObject(raw)
	if err != nil {
		return invalid(ReasonWrongType, where, err)
	}
	known := make(map[string]ftype, len(s.fields))
	for _, f := range s.fields {
		known[f.name] = f.typ
		if f.required {
			if _, ok := m[f.name]; !ok {
				return invalid(ReasonMissingField, joinField(where, f.name), nil)
			}
		}
	}
	for k, v := range m {
		t, ok := known[k]
		if !ok {
			if s.strict {
				return invalid(ReasonUnknownField, joinField(where, k), nil)
			}
			continue
		}
		if err := checkType(v, t, joinField(where, k)); err != nil {
			return err
		}
	}
	return nil
}

// checkType verifies raw matches t.
func checkType(raw json.RawMessage, t ftype, where string) error {
	var ok bool
	switch t {
	case fString:
		var s string
		ok = json.Unmarshal(raw, &s) == nil
	case fNumber:
		var n float64
		ok = json.Unmarshal(raw, &n) == nil
	case fBool:
		var b bool
		ok = json.Unmarshal(raw, &b) == nil
	case fArray:
		var a []json.RawMessage
		ok = json.Unmarshal(raw, &a) == nil
	case fObject:
		_, err := decodeObject(raw)
		ok = err == nil
	case fRequest:
		return checkRequest(raw, where)
	}
	if !ok {
		return invalid(ReasonWrongType, where, nil)
	}
	return nil
}

// checkRequest verifies raw is a request object with a non-empty method + url.
func checkRequest(raw json.RawMessage, where string) error {
	var r Request
	if err := json.Unmarshal(raw, &r); err != nil {
		return invalid(ReasonBadRequest, where, err)
	}
	if r.Method == "" || r.URL == "" {
		return invalid(ReasonBadRequest, where, nil)
	}
	return rejectInlinedCredential(r.Headers, where)
}

// decodeObject unmarshals raw into a key->raw map, erroring if it is not a JSON
// object.
func decodeObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// joinField builds a dotted diagnostic path ("evidence.request").
func joinField(where, name string) string {
	if where == "" {
		return name
	}
	return where + "." + name
}
