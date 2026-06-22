package evidence

import (
	"encoding/json"
	"strings"
	"testing"
)

// Schema examples must parse.
func TestSchemaExamplesParse(t *testing.T) {
	types := schemaTypes()
	if len(types) == 0 {
		t.Fatal("no schemas loaded")
	}
	for _, typ := range types {
		doc, ok := schemaDoc(typ)
		if !ok {
			t.Errorf("%s: no doc", typ)
			continue
		}
		var d struct {
			Examples []json.RawMessage `json:"examples"`
		}
		if err := json.Unmarshal(doc, &d); err != nil {
			t.Errorf("%s: schema not JSON: %v", typ, err)
			continue
		}
		if len(d.Examples) == 0 {
			t.Errorf("%s: schema has no examples", typ)
			continue
		}
		f, err := Parse(d.Examples[0])
		if err != nil {
			t.Errorf("%s: example does not parse: %v", typ, err)
			continue
		}
		if f.Type != typ {
			t.Errorf("%s: example has type %q", typ, f.Type)
		}
	}
}

func TestDoc(t *testing.T) {
	out, err := Doc("ssrf.oast")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ssrf.oast", "injection_location", "shared $defs", "\"request\""} {
		if !strings.Contains(out, want) {
			t.Errorf("Doc(ssrf.oast) missing %q", want)
		}
	}
	if _, err := Doc("SSRF.OAST"); err != nil {
		t.Errorf("type lookup should be case-insensitive: %v", err)
	}
	if _, err := Doc("not_a_type"); err == nil {
		t.Error("expected error for unknown type")
	}
}

func TestDocList(t *testing.T) {
	list := DocList()
	for _, typ := range schemaTypes() {
		if !strings.Contains(list, typ) {
			t.Errorf("DocList missing %q", typ)
		}
	}
}
