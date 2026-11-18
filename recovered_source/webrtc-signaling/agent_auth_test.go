package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtractAgentCredential(t *testing.T) {
	const correctSecret = "ci-agent-secret-48921849128491028491"
	const wrongSecret = "wrong-agent-secret"

	tests := []struct {
		name          string
		url           string
		authorization string
		want          string
	}{
		{
			name:          "bearer correct",
			url:           "/register_agent",
			authorization: "Bearer " + correctSecret,
			want:          correctSecret,
		},
		{
			name:          "bearer wrong",
			url:           "/register_agent",
			authorization: "Bearer " + wrongSecret,
			want:          wrongSecret,
		},
		{
			name: "missing credential",
			url:  "/register_agent",
			want: "",
		},
		{
			name:          "empty bearer credential",
			url:           "/register_agent",
			authorization: "Bearer ",
			want:          "",
		},
		{
			name:          "malformed authorization does not fall back",
			url:           "/register_agent?token=" + correctSecret,
			authorization: "Basic " + correctSecret,
			want:          "",
		},
		{
			name: "legacy token accepted",
			url:  "/register_agent?token=" + correctSecret,
			want: correctSecret,
		},
		{
			name: "legacy secret accepted",
			url:  "/register_agent?secret=" + correctSecret,
			want: correctSecret,
		},
		{
			name: "token has priority over legacy secret",
			url: "/register_agent?token=" +
				correctSecret +
				"&secret=" +
				wrongSecret,
			want: correctSecret,
		},
		{
			name:          "bearer has priority over query token",
			url:           "/register_agent?token=" + wrongSecret,
			authorization: "Bearer " + correctSecret,
			want:          correctSecret,
		},
		{
			name:          "wrong bearer cannot be rescued by correct token",
			url:           "/register_agent?token=" + correctSecret,
			authorization: "Bearer " + wrongSecret,
			want:          wrongSecret,
		},
		{
			name:          "malformed bearer cannot be rescued by correct token",
			url:           "/register_agent?token=" + correctSecret,
			authorization: "BearerX " + correctSecret,
			want:          "",
		},
		{
			name:          "bearer credential trims surrounding whitespace",
			url:           "/register_agent",
			authorization: "Bearer   " + correctSecret + "   ",
			want:          correctSecret,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(
				http.MethodGet,
				tt.url,
				nil,
			)

			if tt.authorization != "" {
				req.Header.Set(
					"Authorization",
					tt.authorization,
				)
			}

			got := extractAgentCredential(req)

			if got != tt.want {
				t.Fatalf(
					"extractAgentCredential() = %q, want %q",
					got,
					tt.want,
				)
			}
		})
	}
}

func TestAgentCredentialValidationMatrix(t *testing.T) {
	const expectedSecret = "ci-agent-secret-48921849128491028491"

	tests := []struct {
		name          string
		url           string
		authorization string
		wantValid     bool
	}{
		{
			name:          "correct bearer authenticates",
			url:           "/register_agent",
			authorization: "Bearer " + expectedSecret,
			wantValid:     true,
		},
		{
			name:          "wrong bearer rejected",
			url:           "/register_agent",
			authorization: "Bearer wrong-secret",
			wantValid:     false,
		},
		{
			name:      "missing credential rejected",
			url:       "/register_agent",
			wantValid: false,
		},
		{
			name:      "correct legacy token authenticates",
			url:       "/register_agent?token=" + expectedSecret,
			wantValid: true,
		},
		{
			name:      "correct legacy secret authenticates",
			url:       "/register_agent?secret=" + expectedSecret,
			wantValid: true,
		},
		{
			name:          "correct bearer overrides wrong legacy token",
			url:           "/register_agent?token=wrong-secret",
			authorization: "Bearer " + expectedSecret,
			wantValid:     true,
		},
		{
			name:          "wrong bearer overrides correct legacy token",
			url:           "/register_agent?token=" + expectedSecret,
			authorization: "Bearer wrong-secret",
			wantValid:     false,
		},
		{
			name:          "malformed authorization blocks query fallback",
			url:           "/register_agent?token=" + expectedSecret,
			authorization: "Basic " + expectedSecret,
			wantValid:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(
				http.MethodGet,
				tt.url,
				nil,
			)

			if tt.authorization != "" {
				req.Header.Set(
					"Authorization",
					tt.authorization,
				)
			}

			credential := extractAgentCredential(req)
			gotValid := credential == expectedSecret

			if gotValid != tt.wantValid {
				t.Fatalf(
					"validation result = %v, want %v; credential=%q",
					gotValid,
					tt.wantValid,
					credential,
				)
			}
		})
	}
}
