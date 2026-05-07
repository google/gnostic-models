// Copyright 2024 Google LLC. All Rights Reserved.
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
)

// TestReferenceResolveReferencesCircular verifies that a circular $ref in an
// OpenAPI v3 Reference does not cause unbounded recursion (stack overflow).
// Instead, it must return an error containing "circular reference".
func TestReferenceResolveReferencesCircular(t *testing.T) {
	// Write a minimal OpenAPI v3 document with a circular reference:
	// RefA → RefB → RefA.
	spec := `openapi: "3.0.0"
info:
  title: Circular ref test
  version: "1.0"
paths: {}
components:
  schemas:
    RefA:
      $ref: "#/components/schemas/RefB"
    RefB:
      $ref: "#/components/schemas/RefA"
`
	dir := t.TempDir()
	specFile := filepath.Join(dir, "circular.yaml")
	if err := os.WriteFile(specFile, []byte(spec), 0644); err != nil {
		t.Fatalf("writing spec file: %v", err)
	}

	// Build a Reference whose XRef creates a cycle.
	m := &Reference{XRef: "#/components/schemas/RefA"}
	_, err := m.ResolveReferences(specFile)
	if err == nil {
		t.Fatal("expected an error for circular $ref but got nil")
	}
	if !strings.Contains(err.Error(), "circular reference") {
		t.Errorf("expected 'circular reference' in error, got: %v", err)
	}
}

// TestReferenceResolveReferencesNonCircular verifies that a valid (non-circular)
// $ref resolves without error.
func TestReferenceResolveReferencesNonCircular(t *testing.T) {
	spec := `openapi: "3.0.0"
info:
  title: Non-circular ref test
  version: "1.0"
paths: {}
components:
  schemas:
    MyString:
      type: string
      description: a simple string schema
`
	dir := t.TempDir()
	specFile := filepath.Join(dir, "valid.yaml")
	if err := os.WriteFile(specFile, []byte(spec), 0644); err != nil {
		t.Fatalf("writing spec file: %v", err)
	}

	m := &Reference{XRef: "#/components/schemas/MyString"}
	_, err := m.ResolveReferences(specFile)
	if err != nil {
		t.Errorf("unexpected error resolving valid $ref: %v", err)
	}
}
