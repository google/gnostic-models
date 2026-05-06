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
	"net/http"
	"net/http/httptest"
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
