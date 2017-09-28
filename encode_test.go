package securelogin

import (
	"bytes"
	"testing"
)

func TestMarshalUnmarshal(t *testing.T) {
	unmarshalled, err := Unmarshal([]byte(token))
	fatal(t, err)

	mu := Marshal(unmarshalled)
	if token != string(mu) {
		t.Errorf("Expected:\t%s\nGot:\t\t\t%s", token, mu)
	}
}

func TestEncode(t *testing.T) {
	unmarshalled, err := Unmarshal([]byte(token))
	fatal(t, err)

	buf := new(bytes.Buffer)
	enc := NewEncoder(buf)
	err = enc.Encode(unmarshalled)
	fatal(t, err)

	if token != buf.String() {
		t.Errorf("Expected:\t%s\nGot:\t\t\t%s", token, buf)
	}
}

func fatal(t *testing.T, err error) {
	if err != nil {
		t.Fatalf("Unexected error: %s", err)
	}
}
