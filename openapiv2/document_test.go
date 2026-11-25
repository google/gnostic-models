// Copyright 2026 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openapi_v2

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/gnostic-models/compiler"
)

func TestParseAndResolveReferences(t *testing.T) {
	for _, in := range []string{"", " \n\t ", "# comment\n", "-", "[1]", "[a,b,c]", "swagger: '2.0'\ninfo: {title: x, version: '1'}\npaths: {}\ndefinitions: [a,b,c]\n"} {
		if _, err := ParseDocument([]byte(in)); err == nil {
			t.Fatalf("ParseDocument(%q) succeeded, expected error", in)
		}
	}

	tupleDoc, err := ParseDocument([]byte("swagger: '2.0'\ninfo: {title: x, version: '1'}\npaths: {}\ndefinitions:\n  T: {type: array, items: [{type: string}, {type: integer}]}\n"))
	if err != nil || len(tupleDoc.GetDefinitions().GetAdditionalProperties()) != 1 || len(tupleDoc.GetDefinitions().GetAdditionalProperties()[0].GetValue().GetItems().GetSchema()) != 2 {
		t.Fatalf("tuple items parse failed: doc=%v err=%v", tupleDoc, err)
	}

	var k9, diamond strings.Builder
	k9.WriteString("swagger: '2.0'\ninfo: {title: x, version: '1'}\npaths: {}\ndefinitions:\n")
	for i := 0; i < 9; i++ {
		fmt.Fprintf(&k9, "  S%d:\n    type: object\n    properties:\n", i)
		for j := 0; j < 9; j++ {
			if i != j {
				fmt.Fprintf(&k9, "      p%d: {$ref: '#/definitions/S%d'}\n", j, j)
			}
		}
	}
	diamond.WriteString("swagger: '2.0'\ninfo: {title: x, version: '1'}\npaths: {}\ndefinitions:\n")
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&diamond, "  D%d: {type: object, properties: {a: {$ref: '#/definitions/D%d'}, b: {$ref: '#/definitions/D%d'}}}\n", i, i+1, i+1)
	}
	diamond.WriteString("  D20: {type: string}\n")

	p := filepath.Join(t.TempDir(), "spec.yaml")
	hdr := "swagger: '2.0'\ninfo: {title: x, version: '1'}\n"
	cases := []struct{ name, spec, wantErr string }{
		{"self_schema", hdr + "paths: {}\ndefinitions:\n  A: {$ref: '#/definitions/A'}\n", "circular $ref"},
		{"two_hop_schema", hdr + "paths: {}\ndefinitions:\n  A: {$ref: '#/definitions/B'}\n  B: {$ref: '#/definitions/A'}\n", "circular $ref"},
		{"prop_cycle", hdr + "paths: {}\ndefinitions:\n  Node: {type: object, properties: {next: {$ref: '#/definitions/Node'}}}\n", "circular $ref"},
		{"items_cycle", hdr + "paths: {}\ndefinitions:\n  Node: {type: array, items: {$ref: '#/definitions/Node'}}\n", "circular $ref"},
		{"addl_props_cycle", hdr + "paths: {}\ndefinitions:\n  Node: {type: object, additionalProperties: {$ref: '#/definitions/Node'}}\n", "circular $ref"},
		{"allof_cycle", hdr + "paths: {}\ndefinitions:\n  Node: {allOf: [{$ref: '#/definitions/Node'}]}\n", "circular $ref"},
		{"jsonref_param_cycle", hdr + "x-p: {$ref: '#/x-p'}\npaths:\n  /i:\n    get:\n      parameters: [{$ref: '#/x-p'}]\n      responses: {'200': {description: ok}}\n", "circular $ref"},
		{"pathitem_cycle", hdr + "x-pi:\n  a: {$ref: '#/x-pi/b'}\n  b: {$ref: '#/x-pi/a'}\npaths:\n  /i: {$ref: '#/x-pi/a'}\n", "circular $ref"},
		{"seq_pointer", hdr + "paths: {}\ndefinitions:\n  A: {$ref: '#/definitions/B/required/z'}\n  B: {type: object, required: [x, y, z]}\n", "could not resolve"},
		{"bad_url_escape", hdr + "paths: {}\ndefinitions:\n  A: {$ref: '%zz'}\n", "no such file"},
		{"dense_k9", k9.String(), "circular $ref"},
		{"diamond_limit", diamond.String(), "exceeded maximum $ref expansions"},
		{"backtrack_dag", hdr + "paths: {}\ndefinitions:\n  Leaf: {type: string}\n  Mid: {type: object, properties: {x: {$ref: '#/definitions/Leaf'}}}\n  Root: {type: object, properties: {a: {$ref: '#/definitions/Mid'}, b: {$ref: '#/definitions/Leaf'}}}\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			compiler.ClearCaches()
			if err := os.WriteFile(p, []byte(tc.spec), 0644); err != nil {
				t.Fatal(err)
			}
			doc, err := ParseDocument([]byte(tc.spec))
			if err != nil {
				t.Fatalf("ParseDocument failed: %v", err)
			}
			_, err = doc.ResolveReferences(p)
			if (tc.wantErr == "") != (err == nil) || (tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("ResolveReferences err = %v, want %q", err, tc.wantErr)
			}
		})
	}

	compiler.DisableInfoCache()
	defer compiler.EnableInfoCache()
	badSpec := hdr + "paths: {}\ndefinitions:\n  A: {$ref: '#/definitions/B/required/z'}\n  B: {type: object, required: [x, y, z]}\n"
	if err := os.WriteFile(p, []byte(badSpec), 0644); err != nil {
		t.Fatal(err)
	}
	doc, err := ParseDocument([]byte(badSpec))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := doc.ResolveReferences(p); err == nil {
		t.Fatal("expected error with infoCache disabled")
	}
}
