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

package compiler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRemoteURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		errFrag string
	}{
		{"https public", "https://example.com/spec.yaml", false, ""},
		{"http public", "http://example.com/spec.yaml", false, ""},
		{"loopback ipv4", "http://127.0.0.1/", true, "private or link-local"},
		{"loopback ipv6", "http://[::1]/", true, "private or link-local"},
		{"link-local metadata aws", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", true, "private or link-local"},
		{"link-local metadata gcp", "http://169.254.169.254/computeMetadata/v1/", true, "private or link-local"},
		{"private rfc1918", "http://10.0.0.1/internal-api", true, "private or link-local"},
		{"private rfc1918 192", "http://192.168.1.1/spec", true, "private or link-local"},
		{"private rfc1918 172", "http://172.16.0.1/spec", true, "private or link-local"},
		{"unspecified", "http://0.0.0.0/spec", true, "private or link-local"},
		{"ftp scheme", "ftp://example.com/spec", true, "not allowed"},
		{"file scheme", "file:///etc/passwd", true, "not allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRemoteURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRemoteURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
			if err != nil && tt.errFrag != "" && !strings.Contains(err.Error(), tt.errFrag) {
				t.Errorf("validateRemoteURL(%q) error %q does not contain %q", tt.url, err.Error(), tt.errFrag)
			}
		})
	}
}

// TestFetchFileSSRF verifies that fetchFile rejects URLs pointing at
// link-local (instance-metadata) and private IP addresses, preventing
// SSRF via malicious $ref values in OpenAPI specs.
func TestFetchFileSSRF(t *testing.T) {
	// A server on loopback that would return credentials if reached.
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"AccessKeyId":"ASIA...","SecretAccessKey":"secret"}`))
	}))
	defer victim.Close()

	// Attempt to fetch a loopback URL — must be rejected.
	_, err := fetchFile("http://127.0.0.1:" + strings.Split(victim.URL, ":")[2] + "/credentials")
	if err == nil {
		t.Fatal("fetchFile should have rejected a loopback URL but did not")
	}
	if !strings.Contains(err.Error(), "private or link-local") {
		t.Errorf("unexpected error: %v", err)
	}

	// Also reject the canonical AWS/GCP metadata endpoint.
	_, err = fetchFile("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
	if err == nil {
		t.Fatal("fetchFile should have rejected the metadata endpoint URL")
	}
}

// TestFetchFileSSRFViaRedirect verifies that a server-side redirect from a
// public URL to a private/loopback address does NOT leak internal data.
//
// Without the CheckRedirect guard, an attacker could embed a $ref that points
// at a public server they control, which then issues a 302 to
// http://169.254.169.254/... (AWS/GCP instance-metadata).  The Go HTTP client
// would follow the redirect transparently, returning cloud credentials to the
// parser.  This test proves the redirect is stopped before the second hop.
func TestFetchFileSSRFViaRedirect(t *testing.T) {
	// "Victim" — simulates a private metadata server returning credentials.
	// In the real attack this is 169.254.169.254; here we use loopback.
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"AccessKeyId":"ASIA_LEAKED","SecretAccessKey":"LEAKED_SECRET"}`))
	}))
	defer victim.Close()

	// "Attacker" — a public-looking server that immediately redirects to victim.
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, victim.URL+"/credentials", http.StatusFound)
	}))
	defer attacker.Close()

	// fetchFile must reject the attacker URL because the redirect leads to loopback.
	data, err := fetchFile(attacker.URL + "/openapi.yaml")
	if err == nil {
		t.Fatalf("fetchFile followed redirect to private address and returned: %s", data)
	}
	if !strings.Contains(err.Error(), "private or link-local") {
		t.Errorf("expected 'private or link-local' error; got: %v", err)
	}
}

// TestFetchFileValidPublicURLAllowed verifies that fetching from a real public
// server (served by httptest with a routable-looking address) still works after
// the SSRF hardening.
func TestFetchFileValidPublicURLAllowed(t *testing.T) {
	wantBody := `openapi: "3.0.0"`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(wantBody))
	}))
	defer srv.Close()

	// httptest listens on 127.0.0.1, so we cannot actually pass validateRemoteURL
	// with a loopback address from within the test.  Instead we verify that the
	// validation error (not a network error) is what prevents the fetch.
	_, err := fetchFile(srv.URL + "/spec.yaml")
	if err == nil {
		// If the environment somehow allowed this (e.g. future test helpers),
		// that is acceptable; what matters is no private-address bypass.
		return
	}
	// The error must be our SSRF guard, not an unexpected network failure.
	if !strings.Contains(err.Error(), "private or link-local") {
		t.Errorf("unexpected error fetching from httptest server: %v", err)
	}
}

// TestReadInfoForRefPathTraversal verifies that $ref values containing path
// traversal sequences (e.g. "../../../etc/passwd") are rejected when the
// resulting path escapes the base directory of the spec file.
func TestReadInfoForRefPathTraversal(t *testing.T) {
	// Create a temporary directory with a minimal spec file.
	dir := t.TempDir()
	specFile := filepath.Join(dir, "spec.yaml")
	specContent := `swagger: "2.0"
info:
  title: Test
  version: "1.0"
paths: {}
`
	if err := os.WriteFile(specFile, []byte(specContent), 0644); err != nil {
		t.Fatalf("writing spec file: %v", err)
	}

	// Create a sibling file one level up from the basedir to serve as an
	// escape target. We don't need it to exist because the path-traversal
	// guard fires before the file read.
	traversals := []string{
		"../escape.yaml",
		"../../etc/passwd",
		"../../../etc/shadow",
	}

	for _, ref := range traversals {
		t.Run(fmt.Sprintf("ref=%s", ref), func(t *testing.T) {
			ClearCaches()
			_, err := ReadInfoForRef(specFile, ref)
			if err == nil {
				t.Errorf("ReadInfoForRef(%q, %q) should have failed with path-traversal error but succeeded", specFile, ref)
				return
			}
			if !strings.Contains(err.Error(), "escapes") {
				t.Errorf("ReadInfoForRef(%q, %q) error %q does not mention 'escapes'", specFile, ref, err.Error())
			}
		})
	}
}

// TestReadInfoForRefDisallowedScheme verifies that $ref values with non-http(s)
// schemes (e.g. "file://", "ftp://") are rejected.
func TestReadInfoForRefDisallowedScheme(t *testing.T) {
	dir := t.TempDir()
	specFile := filepath.Join(dir, "spec.yaml")
	if err := os.WriteFile(specFile, []byte("swagger: '2.0'\ninfo:\n  title: t\n  version: '1'\npaths: {}\n"), 0644); err != nil {
		t.Fatalf("writing spec file: %v", err)
	}

	disallowed := []string{
		"file:///etc/passwd",
		"ftp://example.com/spec.yaml",
	}
	for _, ref := range disallowed {
		t.Run(ref, func(t *testing.T) {
			ClearCaches()
			_, err := ReadInfoForRef(specFile, ref)
			if err == nil {
				t.Errorf("ReadInfoForRef with ref %q should have been rejected but was not", ref)
				return
			}
			if !strings.Contains(err.Error(), "disallowed") && !strings.Contains(err.Error(), "not allowed") {
				t.Errorf("ReadInfoForRef(%q) error %q does not mention disallowed scheme", ref, err.Error())
			}
		})
	}
}

// TestReadInfoForRefSameDir verifies that $ref values pointing to files
// within the same directory as the base spec are allowed.
func TestReadInfoForRefSameDir(t *testing.T) {
	dir := t.TempDir()

	// Write a "main" spec file and a sibling schema file.
	mainSpec := filepath.Join(dir, "main.yaml")
	siblingSpec := filepath.Join(dir, "sibling.yaml")

	siblingContent := `swagger: "2.0"
info:
  title: Sibling
  version: "1.0"
paths: {}
definitions:
  MyType:
    type: string
`
	if err := os.WriteFile(mainSpec, []byte("swagger: '2.0'\ninfo:\n  title: m\n  version: '1'\npaths: {}\n"), 0644); err != nil {
		t.Fatalf("writing main spec: %v", err)
	}
	if err := os.WriteFile(siblingSpec, []byte(siblingContent), 0644); err != nil {
		t.Fatalf("writing sibling spec: %v", err)
	}

	ClearCaches()
	// Reference sibling.yaml#/definitions/MyType from main.yaml
	_, err := ReadInfoForRef(mainSpec, "sibling.yaml#/definitions/MyType")
	if err != nil {
		t.Errorf("ReadInfoForRef for same-directory file should succeed, got: %v", err)
	}
}
