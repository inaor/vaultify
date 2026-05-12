package vault

import (
	"reflect"
	"testing"
)

func TestParseOpItemListJSON(t *testing.T) {
	top := []byte(`[{"id":"a1","title":"vee-openai-key"}]`)
	got := parseOpItemListJSON(top)
	want := []opItemListRow{{ID: "a1", Title: "vee-openai-key"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("top-level array: got %#v want %#v", got, want)
	}
	wrapped := []byte(`{"items":[{"id":"b2","title":"vee-anthropic-key"}]}`)
	got2 := parseOpItemListJSON(wrapped)
	want2 := []opItemListRow{{ID: "b2", Title: "vee-anthropic-key"}}
	if !reflect.DeepEqual(got2, want2) {
		t.Fatalf("wrapped items: got %#v want %#v", got2, want2)
	}
	if parseOpItemListJSON([]byte(`{}`)) != nil {
		t.Fatal("empty object should yield nil")
	}
}

func TestParseVeeItemCredentialAndUsername(t *testing.T) {
	raw := []byte(`{"fields":[{"id":"credential","value":"sk-test"},{"id":"username","value":"gpt-4.1-mini"}]}`)
	has, model := parseVeeItemCredentialAndUsername(raw)
	if !has || model != "gpt-4.1-mini" {
		t.Fatalf("has=%v model=%q", has, model)
	}
	has2, _ := parseVeeItemCredentialAndUsername([]byte(`{"fields":[{"id":"credential","value":"  "}]}`))
	if has2 {
		t.Fatal("empty credential should not count as key")
	}
}
