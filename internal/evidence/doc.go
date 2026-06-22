package evidence

import (
	"fmt"
	"strings"
)

// Doc returns schema plus shared defs.
func Doc(typ string) (string, error) {
	doc, ok := schemaDoc(strings.ToLower(strings.TrimSpace(typ)))
	if !ok {
		return "", fmt.Errorf("unknown finding type %q; run `nocapsec doc` to list types", typ)
	}
	var b strings.Builder
	b.Write(doc)
	if !strings.HasSuffix(string(doc), "\n") {
		b.WriteString("\n")
	}
	b.WriteString("\n" + strings.Repeat("─", 72) + "\n")
	b.WriteString("shared $defs (referenced by \"$ref\" above):\n\n")
	b.Write(commonDefsDoc)
	b.WriteString("\n")
	return b.String(), nil
}

// DocList lists every finding type with a schema.
func DocList() string {
	var b strings.Builder
	b.WriteString("nocapsec doc <type> — print the JSON Schema for a finding type.\n\ntypes:\n")
	for _, t := range schemaTypes() {
		fmt.Fprintf(&b, "  %s\n", t)
	}
	return b.String()
}
