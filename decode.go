package securelogin

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var base64Decode = base64.StdEncoding.DecodeString

// Decoder reads and decodes sltoken from an input stream.
type Decoder struct {
	r io.Reader
}

// NewDecoder returns a new decoder that reads from r.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{r}
}

// Decode reads sltoken encoded data and returns a Token.
func (dec *Decoder) Decode(t *Token) error {
	all, err := ioutil.ReadAll(dec.r)
	if err != nil {
		return err
	}

	*t, err = Unmarshal(all)
	return err
}

// Unmarshal parses encoded sltoken and returns Token and an error.
func Unmarshal(data []byte) (Token, error) {
	return UnmarshalString(string(data))
}

// UnmarshalString parses given string and constructs a Token from it or fails
// with an error.
func UnmarshalString(s string) (Token, error) {
	var t Token
	data, err := unescapeSplit(s, 4)
	if err != nil {
		return t, wrap("token", err)
	}

	t.rawPayload = []byte(data[0])
	t.Email = data[3]

	// payload
	payload, err := unescapeSplit(data[0], 4)
	if err != nil {
		return t, wrap("payload", err)
	}

	t.Provider = payload[0]
	t.Client = payload[1]
	t.Scope, err = url.ParseQuery(payload[2])
	if err != nil {
		return t, wrap("payload", "parsing scope failed")
	}

	expire, err := strconv.ParseInt(payload[3], 10, 64)
	if err != nil {
		return t, wrap("payload", "invalid expire time")
	}
	t.ExpireAt = time.Unix(expire, 0)

	// signatures
	signatures, err := decodeKeys(data[1])
	if err != nil {
		return t, wrap("signatures", err)
	}
	t.Signature = signatures[0]
	t.HMACSignature = signatures[1]

	// keys
	keys, err := decodeKeys(data[2])
	if err != nil {
		return t, wrap("keys", err)
	}
	t.PublicKey = keys[0]
	t.HMACSecret = keys[1]

	return t, nil
}

func unescapeSplit(s string, count int) ([]string, error) {
	var (
		elements = strings.Split(s, ",")
		err      error
	)

	for i := 0; i < len(elements); i++ {
		elements[i] = strings.Replace(elements[i], "%2C", ",", -1)
	}

	if len(elements) != count {
		err = fmt.Errorf("expected %d elements, got %d", count, len(elements))
	}

	return elements, err
}

func decodeKeys(s string) ([2][]byte, error) {
	var decoded = [2][]byte{}

	keys, err := unescapeSplit(s, 2)
	if err != nil {
		return decoded, err
	}

	decoded[0], err = base64Decode(keys[0])
	if err != nil {
		return decoded, err
	}

	decoded[1], err = base64Decode(keys[1])
	return decoded, err
}

func wrap(what string, err interface{}) error {
	return fmt.Errorf("token unmarshal failed: in %s %s", what, err)
}
