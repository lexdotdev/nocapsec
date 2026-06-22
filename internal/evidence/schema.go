package evidence

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"sort"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
)

//go:embed schemas/*.json
var schemaFS embed.FS

type compiledSchema struct {
	doc      []byte
	resolved *jsonschema.Resolved
}

var (
	schemaRegistry map[string]*compiledSchema
	commonDefsDoc  []byte
)

func init() {
	if err := loadSchemas(); err != nil {
		panic("evidence: loading schemas: " + err.Error())
	}
}

// loadSchemas resolves all schemas.
func loadSchemas() error {
	commonDefs, err := loadCommonDefs()
	if err != nil {
		return err
	}

	entries, err := fs.ReadDir(schemaFS, "schemas")
	if err != nil {
		return err
	}
	schemaRegistry = make(map[string]*compiledSchema)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || name == "common.json" || !strings.HasSuffix(name, ".json") {
			continue
		}
		raw, err := schemaFS.ReadFile("schemas/" + name)
		if err != nil {
			return err
		}
		merged, err := mergeDefs(raw, commonDefs)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		var s jsonschema.Schema
		if err := json.Unmarshal(merged, &s); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		resolved, err := s.Resolve(nil)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		schemaRegistry[strings.TrimSuffix(name, ".json")] = &compiledSchema{doc: raw, resolved: resolved}
	}
	return nil
}

func loadCommonDefs() (map[string]json.RawMessage, error) {
	raw, err := schemaFS.ReadFile("schemas/common.json")
	if err != nil {
		return nil, err
	}
	var common struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &common); err != nil {
		return nil, err
	}
	commonDefsDoc, err = json.MarshalIndent(map[string]any{"$defs": common.Defs}, "", "  ")
	if err != nil {
		return nil, err
	}
	return common.Defs, nil
}

// mergeDefs lets local $defs override.
func mergeDefs(raw []byte, common map[string]json.RawMessage) ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	defs := make(map[string]json.RawMessage, len(common))
	maps.Copy(defs, common)
	if local, ok := doc["$defs"]; ok {
		var lm map[string]json.RawMessage
		if err := json.Unmarshal(local, &lm); err != nil {
			return nil, err
		}
		maps.Copy(defs, lm)
	}
	db, err := json.Marshal(defs)
	if err != nil {
		return nil, err
	}
	doc["$defs"] = db
	return json.Marshal(doc)
}

// hasSchema reports whether a type has a schema.
func hasSchema(typ string) bool {
	_, ok := schemaRegistry[typ]
	return ok
}

// validateInstance runs the type schema.
func validateInstance(typ string, instance any) error {
	cs, ok := schemaRegistry[typ]
	if !ok {
		return fmt.Errorf("no schema for type %q", typ)
	}
	return cs.resolved.Validate(instance)
}

// schemaTypes returns sorted types with a schema.
func schemaTypes() []string {
	out := make([]string, 0, len(schemaRegistry))
	for t := range schemaRegistry {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// schemaDoc returns a type's schema document.
func schemaDoc(typ string) ([]byte, bool) {
	cs, ok := schemaRegistry[typ]
	if !ok {
		return nil, false
	}
	return cs.doc, true
}
