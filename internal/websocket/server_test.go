package websocket

import (
	"net/http/httptest"
	"testing"
)

func TestCheckOrigin(t *testing.T) {
	t.Setenv("VAOS_WS_ALLOWED_ORIGINS", "")

	sameOrigin := httptest.NewRequest("GET", "http://kernel.example/ws", nil)
	sameOrigin.Header.Set("Origin", "https://kernel.example")
	if !checkOrigin(sameOrigin) {
		t.Fatal("same-host origin should be allowed")
	}

	crossOrigin := httptest.NewRequest("GET", "http://kernel.example/ws", nil)
	crossOrigin.Header.Set("Origin", "https://attacker.example")
	if checkOrigin(crossOrigin) {
		t.Fatal("cross-origin websocket should be rejected")
	}

	t.Setenv("VAOS_WS_ALLOWED_ORIGINS", "https://console.example")
	configured := httptest.NewRequest("GET", "http://kernel.example/ws", nil)
	configured.Header.Set("Origin", "https://console.example")
	if !checkOrigin(configured) {
		t.Fatal("configured origin should be allowed")
	}
}
