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

package discovery_v1

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/gnostic-models/compiler"
)

func TestParseAndResolveReferences(t *testing.T) {
	for _, in := range []string{"", " \n\t ", "# comment\n", "-", "[1]", "[a,b,c]"} {
		if _, err := ParseDocument([]byte(in)); err == nil {
			t.Fatalf("ParseDocument(%q) succeeded, expected error", in)
		}
	}

	p := filepath.Join(t.TempDir(), "disco.yaml")
	hdr := "discoveryVersion: v1\nkind: discovery#restDescription\n"
	cases := []struct{ name, spec, wantErr string }{
		{"schema_self", hdr + "schemas:\n  A: {$ref: '#/schemas/A'}\n", "circular $ref"},
		{"schema_prop", hdr + "schemas:\n  A: {type: object, properties: {next: {$ref: '#/schemas/A'}}}\n", "circular $ref"},
		{"param_self", hdr + "parameters:\n  P: {$ref: '#/parameters/P'}\n", "circular $ref"},
		{"request_self", hdr + "methods:\n  m:\n    request: {$ref: '#/methods/m/request'}\n", "circular $ref"},
		{"valid_dag", hdr + "schemas:\n  Leaf: {type: string}\n  Root: {type: object, properties: {a: {$ref: '#/schemas/Leaf'}, b: {$ref: '#/schemas/Leaf'}}}\n", ""},
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
}
