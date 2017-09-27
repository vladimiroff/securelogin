package securelogin

import (
	"crypto/hmac"
	"crypto/sha512"
	"errors"
	"net/url"

	"golang.org/x/crypto/ed25519"
)

// Verify encoded token.
//
// This is just a convenient function which unmarshals a token and then calls
// Verify on it with given options.
func Verify(token string, opts ...Option) (Token, error) {
	t, err := UnmarshalToken(token)
	if err != nil {
		return t, err
	}

	return t, t.Verify(opts...)
}

func verifyHMAC(message, signature, secret []byte) bool {
	mac := hmac.New(sha512.New, secret)
	mac.Write(message)
	return hmac.Equal(signature, mac.Sum(nil)[:32])
}

func verifySignature(message, signature, pubkey []byte) bool {
	if len(pubkey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pubkey, message, signature)
}

func verifyScope(cfg Config, scope url.Values) error {
	if cfg.change {
		_, hasTo := scope["to"]
		if !(len(scope) == 2 && hasTo && has(scope, "mode", "change")) {
			return errors.New("not mode=change token")
		}
	} else if !scopesMatch(scope, cfg.scope) {
		return errors.New("invalid scope")
	}

	return nil
}

func has(store url.Values, key, value string) bool {
	values, ok := store[key]
	if !ok {
		return false
	}

	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func scopesMatch(a, b url.Values) bool {
	if len(a) != len(b) {
		return false
	}

	for key, value := range a {
		if !slicesMatch(value, b[key]) {
			return false
		}
	}

	return true
}

func slicesMatch(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i, value := range a {
		if value != b[i] {
			return false
		}
	}

	return true
}
