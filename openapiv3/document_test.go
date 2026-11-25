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

package openapi_v3

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/gnostic-models/compiler"
)

func TestParseAndResolveReferences(t *testing.T) {
	for _, in := range []string{"", " \n\t ", "# comment\n", "-", "[1]", "[a,b,c]", "openapi: '3.0.0'\ninfo: {title: x, version: '1'}\npaths: [a,b,c]\n"} {
		if _, err := ParseDocument([]byte(in)); err == nil {
			t.Fatalf("ParseDocument(%q) succeeded, expected error", in)
		}
	}

	tupleDoc, err := ParseDocument([]byte("openapi: '3.0.0'\ninfo: {title: x, version: '1'}\npaths: {}\ncomponents:\n  schemas:\n    T: {type: array, items: [{type: string}, {type: integer}]}\n"))
	if err != nil || len(tupleDoc.GetComponents().GetSchemas().GetAdditionalProperties()) != 1 || len(tupleDoc.GetComponents().GetSchemas().GetAdditionalProperties()[0].GetValue().GetSchema().GetItems().GetSchemaOrReference()) != 2 {
		t.Fatalf("tuple items parse failed: doc=%v err=%v", tupleDoc, err)
	}

	p := filepath.Join(t.TempDir(), "spec.yaml")
	hdr := "openapi: '3.0.0'\ninfo: {title: x, version: '1'}\n"
	cases := []struct{ name, spec, wantErr string }{
		{"self_ref", hdr + "paths: {}\ncomponents:\n  schemas:\n    A: {$ref: '#/components/schemas/A'}\n", "circular $ref"},
		{"two_hop_ref", hdr + "paths: {}\ncomponents:\n  schemas:\n    A: {$ref: '#/components/schemas/B'}\n    B: {$ref: '#/components/schemas/A'}\n", "circular $ref"},
		{"callback_post_cycle", hdr + "paths:\n  /t: {$ref: '#/x-pi/loop'}\nx-pi:\n  loop:\n    post:\n      responses: {}\n      callbacks:\n        cb:\n          '{$url}': {$ref: '#/x-pi/loop'}\n", "circular $ref"},
		{"callback_get_cycle", hdr + "paths:\n  /t: {$ref: '#/x-pi/loop'}\nx-pi:\n  loop:\n    get:\n      responses: {}\n      callbacks:\n        cb:\n          '{$url}': {$ref: '#/x-pi/loop'}\n", "circular $ref"},
		{"seq_pointer", hdr + "paths: {}\ncomponents:\n  schemas:\n    A: {$ref: '#/components/schemas/B/required/z'}\n    B: {type: object, required: [x, y, z]}\n", "could not resolve"},
		{"bad_url_escape", hdr + "paths: {}\ncomponents:\n  schemas:\n    A: {$ref: '%zz#/x'}\n", "no such file"},
		{"callback_backtrack_dag", hdr + "paths:\n  /t: {$ref: '#/x-pi/root'}\nx-pi:\n  leaf:\n    get: {responses: {}}\n  mid:\n    post:\n      responses: {}\n      callbacks:\n        c1:\n          '{$url}': {$ref: '#/x-pi/leaf'}\n  root:\n    put:\n      responses: {}\n      callbacks:\n        a:\n          '{$url}': {$ref: '#/x-pi/mid'}\n        b:\n          '{$url}': {$ref: '#/x-pi/leaf'}\n", ""},
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
