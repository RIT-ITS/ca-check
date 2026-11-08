package server

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"ca-chain-check/internal/analyze"
	"ca-chain-check/internal/config"
	"ca-chain-check/internal/probe"
	"ca-chain-check/internal/truststore"
	"ca-chain-check/web"
)

// TestOpenAPIMatchesTypes keeps web/openapi.json in step with the Go types
// the API encodes: every JSON field must be in the schema and the schema
// must not list fields the API never sends.
func TestOpenAPIMatchesTypes(t *testing.T) {
	raw, err := web.FS.ReadFile("openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("openapi.json: %v", err)
	}
	for schema, v := range map[string]any{
		"CheckRequest":     probe.Request{},
		"CheckResponse":    probe.Response{},
		"Resolution":       probe.Resolution{},
		"IPResult":         probe.IPResult{},
		"AltResult":        probe.AltResult{},
		"TLSInfo":          probe.TLSInfo{},
		"Consistency":      probe.Consistency{},
		"Analysis":         analyze.Result{},
		"Check":            analyze.Check{},
		"Path":             analyze.Path{},
		"Certificate":      analyze.CertInfo{},
		"KeyEntry":         analyze.KeyEntry{},
		"PendingDistrust":  config.PendingDistrust{},
		"StoreResult":      analyze.StoreResult{},
		"Revocation":       analyze.Revocation{},
		"RevocationSource": analyze.RevocationSource{},
		"Staple":           analyze.Staple{},
		"TrustStoreInfo":   truststore.Info{},
	} {
		s, ok := spec.Components.Schemas[schema]
		if !ok {
			t.Errorf("schema %s missing", schema)
			continue
		}
		want := jsonFields(reflect.TypeOf(v))
		var got []string
		for k := range s.Properties {
			got = append(got, k)
		}
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("schema %s properties\n got  %v\n want %v", schema, got, want)
		}
	}
}

// jsonFields lists the exported JSON field names of a struct, following
// embedded structs and skipping `json:"-"`.
func jsonFields(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" {
			out = append(out, jsonFields(f.Type)...)
			continue
		}
		if name == "" {
			name = f.Name
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
