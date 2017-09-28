package securelogin

import (
	"encoding/base64"
	"io"
	"strings"
)

var base64Encode = base64.StdEncoding.EncodeToString

type Encoder struct {
	w io.Writer
}

func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{w}
}

func (e *Encoder) Encode(t Token) error {
	data := Marshal(t)

	_, err := e.w.Write(data)
	return err
}

// Marshal returns encoded Token as defied by the spec.
func Marshal(t Token) []byte {
	return []byte(MarshalString(t))
}

// MarshalString returns encoded Token as defied by the spec to string.
func MarshalString(t Token) string {
	return escapeJoin([]string{
		string(t.rawPayload),
		escapeJoin([]string{
			base64Encode(t.Signature),
			base64Encode(t.HMACSignature),
		}),
		escapeJoin([]string{
			base64Encode(t.PublicKey),
			base64Encode(t.HMACSecret),
		}),
		t.Email,
	})
}

func escapeJoin(s []string) string {
	var escaped = make([]string, len(s))

	for i := 0; i < len(s); i++ {
		escaped[i] = strings.Replace(s[i], ",", "%2C", -1)
	}

	return strings.Join(escaped, ",")
}
