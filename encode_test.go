package securelogin

import "testing"

func TestMarshalUnmarshal(t *testing.T) {
	unmarshalled, err := UnmarshalToken(token)
	if err != nil {
		t.Fatalf("Unexected error: %s", err)
	}

	mu := MarshalToken(unmarshalled)
	if token != mu {
		t.Errorf("Expected:\t%s\nGot:\t\t\t%s", token, mu)
	}
}
