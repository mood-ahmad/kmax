package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

const integrationAgentSecret = "ci-agent-secret-48921849128491028491"

func setupAgentWSSIntegrationServer(t *testing.T) (*httptest.Server, func()) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "agent-wss-integration-*")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}

	dataDir := tmpDir + "/data"
	downloadsDir := tmpDir + "/downloads"
	assetsDir := tmpDir + "/assets"

	if err := os.MkdirAll(assetsDir, 0755); err != nil {
		_ = os.RemoveAll(tmpDir)
		t.Fatalf("failed to create assets directory: %v", err)
	}

	// Production-style authentication:
	// authentication enabled, DEV_MODE disabled, secure AGENT_SECRET set.
	t.Setenv("AGENT_SECRET", integrationAgentSecret)
	t.Setenv("DEV_MODE", "false")
	t.Setenv("DEBUG", "false")

	store := NewPersistenceStore(dataDir)
	hub := NewHub(store)

	// noAuth=false is required so /register_agent enforces AGENT_SECRET.
	auth := NewAuthManager(false, store)

	apiServer := NewAPIServer(
		hub,
		auth,
		store,
		assetsDir,
		downloadsDir,
	)

	mux := http.NewServeMux()
	apiServer.RegisterRoutes(mux)

	server := httptest.NewTLSServer(mux)

	cleanup := func() {
		server.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return server, cleanup
}

func websocketURL(serverURL string, query string) string {
	url := "wss" + strings.TrimPrefix(serverURL, "https") + "/register_agent"

	if query != "" {
		url += "?" + query
	}

	return url
}

func integrationDialer(server *httptest.Server) *websocket.Dialer {
	return &websocket.Dialer{
		TLSClientConfig: server.Client().Transport.(*http.Transport).TLSClientConfig,
		HandshakeTimeout: 5 * time.Second,
	}
}

func TestAgentWSSIntegrationBearerRegistration(t *testing.T) {
	server, cleanup := setupAgentWSSIntegrationServer(t)
	defer cleanup()

	dialer := integrationDialer(server)

	headers := http.Header{}
	headers.Set(
		"Authorization",
		"Bearer "+integrationAgentSecret,
	)

	conn, response, err := dialer.Dial(
		websocketURL(server.URL, "id=ci-bearer-agent"),
		headers,
	)
	if err != nil {
		status := 0
		if response != nil {
			status = response.StatusCode
		}

		t.Fatalf(
			"correct Bearer credential failed WebSocket connection: status=%d err=%v",
			status,
			err,
		)
	}
	defer conn.Close()

	registerMessage := map[string]interface{}{
		"action":    "register",
		"type":      "register",
		"device_id": "ci-bearer-agent",
		"device_info": map[string]interface{}{
			"android_model":   "CI Integration Device",
			"android_version": "CI",
			"app_version":     "integration-test",
		},
	}

	if err := conn.WriteJSON(registerMessage); err != nil {
		t.Fatalf("failed to send Agent register message: %v", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("failed to set WebSocket read deadline: %v", err)
	}

	var responseMessage map[string]interface{}

	if err := conn.ReadJSON(&responseMessage); err != nil {
		t.Fatalf(
			"failed to read successful Agent registration response: %v",
			err,
		)
	}

	if responseMessage["message_type"] != "agent_register_ok" {
		encoded, _ := json.Marshal(responseMessage)

		t.Fatalf(
			"expected message_type=agent_register_ok, got %s",
			string(encoded),
		)
	}

	if responseMessage["status"] != "valid" {
		t.Fatalf(
			"expected registration status=valid, got %v",
			responseMessage["status"],
		)
	}

	if responseMessage["action"] != "registered" {
		t.Fatalf(
			"expected action=registered, got %v",
			responseMessage["action"],
		)
	}

	if responseMessage["device_id"] != "ci-bearer-agent" {
		t.Fatalf(
			"expected device_id=ci-bearer-agent, got %v",
			responseMessage["device_id"],
		)
	}
}

func TestAgentWSSIntegrationWrongBearerRejected(t *testing.T) {
	server, cleanup := setupAgentWSSIntegrationServer(t)
	defer cleanup()

	dialer := integrationDialer(server)

	headers := http.Header{}
	headers.Set(
		"Authorization",
		"Bearer definitely-wrong-agent-secret",
	)

	conn, response, err := dialer.Dial(
		websocketURL(server.URL, "id=ci-wrong-secret-agent"),
		headers,
	)

	// The server performs the WebSocket upgrade first and then rejects
	// the Agent with a WebSocket policy-violation close frame.
	if err != nil {
		if response != nil &&
			response.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf(
				"unexpected HTTP rejection before WebSocket policy check: status=%d err=%v",
				response.StatusCode,
				err,
			)
		}

		return
	}

	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("failed to set WebSocket read deadline: %v", err)
	}

	_, _, readErr := conn.ReadMessage()

	if readErr == nil {
		t.Fatal(
			"wrong Bearer credential was not rejected",
		)
	}

	closeErr, ok := readErr.(*websocket.CloseError)
	if !ok {
		t.Fatalf(
			"expected WebSocket CloseError for wrong secret, got %T: %v",
			readErr,
			readErr,
		)
	}

	if closeErr.Code != websocket.ClosePolicyViolation {
		t.Fatalf(
			"expected WebSocket close code 1008 for wrong secret, got %d",
			closeErr.Code,
		)
	}

	if !strings.Contains(
		closeErr.Text,
		"Unauthorized agent secret",
	) {
		t.Fatalf(
			"expected Unauthorized agent secret close reason, got %q",
			closeErr.Text,
		)
	}
}

func TestAgentWSSIntegrationMissingCredentialRejected(t *testing.T) {
	server, cleanup := setupAgentWSSIntegrationServer(t)
	defer cleanup()

	dialer := integrationDialer(server)

	conn, response, err := dialer.Dial(
		websocketURL(server.URL, "id=ci-missing-secret-agent"),
		nil,
	)

	if err != nil {
		if response != nil &&
			response.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf(
				"unexpected HTTP rejection before WebSocket policy check: status=%d err=%v",
				response.StatusCode,
				err,
			)
		}

		return
	}

	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("failed to set WebSocket read deadline: %v", err)
	}

	_, _, readErr := conn.ReadMessage()

	if readErr == nil {
		t.Fatal(
			"missing Agent credential was not rejected",
		)
	}

	closeErr, ok := readErr.(*websocket.CloseError)
	if !ok {
		t.Fatalf(
			"expected WebSocket CloseError for missing credential, got %T: %v",
			readErr,
			readErr,
		)
	}

	if closeErr.Code != websocket.ClosePolicyViolation {
		t.Fatalf(
			"expected WebSocket close code 1008 for missing credential, got %d",
			closeErr.Code,
		)
	}

	if !strings.Contains(
		closeErr.Text,
		"Unauthorized agent secret",
	) {
		t.Fatalf(
			"expected Unauthorized agent secret close reason, got %q",
			closeErr.Text,
		)
	}
}

func TestAgentWSSIntegrationLegacyTokenRegistration(t *testing.T) {
	server, cleanup := setupAgentWSSIntegrationServer(t)
	defer cleanup()

	dialer := integrationDialer(server)

	conn, response, err := dialer.Dial(
		websocketURL(
			server.URL,
			"id=ci-legacy-agent&token="+integrationAgentSecret,
		),
		nil,
	)

	if err != nil {
		status := 0
		if response != nil {
			status = response.StatusCode
		}

		t.Fatalf(
			"legacy token credential failed WebSocket connection: status=%d err=%v",
			status,
			err,
		)
	}
	defer conn.Close()

	registerMessage := map[string]interface{}{
		"action":    "register",
		"device_id": "ci-legacy-agent",
		"device_info": map[string]interface{}{
			"android_model":   "CI Legacy Device",
			"android_version": "CI",
			"app_version":     "legacy-integration-test",
		},
	}

	if err := conn.WriteJSON(registerMessage); err != nil {
		t.Fatalf(
			"failed to send legacy Agent register message: %v",
			err,
		)
	}

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("failed to set WebSocket read deadline: %v", err)
	}

	var responseMessage map[string]interface{}

	if err := conn.ReadJSON(&responseMessage); err != nil {
		t.Fatalf(
			"failed to read legacy Agent registration response: %v",
			err,
		)
	}

	if responseMessage["message_type"] != "agent_register_ok" {
		t.Fatalf(
			"legacy registration did not return agent_register_ok: %v",
			responseMessage,
		)
	}

	if responseMessage["status"] != "valid" {
		t.Fatalf(
			"legacy registration status is not valid: %v",
			responseMessage,
		)
	}
}

func TestAgentWSSIntegrationBearerPreventsQueryDowngrade(t *testing.T) {
	server, cleanup := setupAgentWSSIntegrationServer(t)
	defer cleanup()

	dialer := integrationDialer(server)

	headers := http.Header{}
	headers.Set(
		"Authorization",
		"Bearer wrong-bearer-secret",
	)

	conn, response, err := dialer.Dial(
		websocketURL(
			server.URL,
			"id=ci-downgrade-test&token="+integrationAgentSecret,
		),
		headers,
	)

	if err != nil {
		if response != nil &&
			response.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf(
				"unexpected HTTP rejection before WebSocket policy check: status=%d err=%v",
				response.StatusCode,
				err,
			)
		}

		return
	}

	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("failed to set WebSocket read deadline: %v", err)
	}

	_, _, readErr := conn.ReadMessage()

	if readErr == nil {
		t.Fatal(
			"wrong Bearer credential incorrectly fell back to correct query token",
		)
	}

	closeErr, ok := readErr.(*websocket.CloseError)
	if !ok {
		t.Fatalf(
			"expected WebSocket CloseError, got %T: %v",
			readErr,
			readErr,
		)
	}

	if closeErr.Code != websocket.ClosePolicyViolation {
		t.Fatalf(
			"expected close code 1008, got %d",
			closeErr.Code,
		)
	}
}
