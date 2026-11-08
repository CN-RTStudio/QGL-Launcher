package main

import (
	"testing"
)

func TestTextComponent_Plain(t *testing.T) {
	raw := []byte(`{"text":"hello world"}`)
	safe, reasons := SanitizeTextComponent(raw)
	if !safe {
		t.Fatalf("plain should be safe: %v", reasons)
	}
}

func TestTextComponent_OpenURL(t *testing.T) {
	good := []byte(`{"text":"x","clickEvent":{"action":"open_url","value":"https://example.com/"}}`)
	if safe, _ := SanitizeTextComponent(good); !safe {
		t.Fatal("https click should pass")
	}
	bad := []byte(`{"text":"x","clickEvent":{"action":"open_url","value":"javascript:alert(1)"}}`)
	safe, reasons := SanitizeTextComponent(bad)
	if safe {
		t.Fatal("javascript: scheme must be blocked")
	}
	if reasons[0] != "click-bad-url-scheme" {
		t.Fatalf("reason = %s", reasons[0])
	}
}

func TestTextComponent_RunCommand(t *testing.T) {
	ok := []byte(`{"text":"x","clickEvent":{"action":"run_command","value":"/help"}}`)
	if safe, _ := SanitizeTextComponent(ok); !safe {
		t.Fatal("/help should be whitelisted")
	}
	bad := []byte(`{"text":"x","clickEvent":{"action":"run_command","value":"/op Notch"}}`)
	if safe, _ := SanitizeTextComponent(bad); safe {
		t.Fatal("/op must be blocked")
	}
}

func TestTextComponent_DeepNest(t *testing.T) {
	inner := `{"text":"x"}`
	for i := 0; i < 20; i++ {
		inner = `{"text":"x","extra":[` + inner + `]}`
	}
	safe, reasons := SanitizeTextComponent([]byte(inner))
	if safe {
		t.Fatal("20-deep nesting must be blocked")
	}
	if reasons[0] != "too-deep" {
		t.Fatalf("reason = %s", reasons[0])
	}
}

func TestValidateChatJSON_Malformed(t *testing.T) {
	if err := ValidateChatJSON([]byte(`{not json`)); err == nil {
		t.Fatal("malformed json must error")
	}
}
