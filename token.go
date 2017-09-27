// Package securelogin implements the SecureLogin protocol.
//
// SecureLogin is an authentication protocol created by Sakurity. The Draft RFC
// Specification for it can be read at:
//
//   https://github.com/sakurity/securelogin-spec/blob/master/index.md
package securelogin

import (
	"errors"
	"net/url"
	"time"
)

// Token is the core of SecureLogin Protocol.
type Token struct {

	// rawPayload is the first argument before decoding. It's being used
	// for shared secret and Ed25519 signature verifying.
	rawPayload []byte

	// Provider is the origin of the app where this token should authenticate for.
	Provider string

	// Client is the front-end this token should authenticate with. Equals
	// to provider unless when used to authorize specific scope or in a
	// Connect request.
	Client string

	// Scope defines what the user is allowed to do with this token. It's
	// expected to be empty during sign-(in|up).
	Scope url.Values

	// ExpireAt is expiration time of the token in order to prevent replay
	// attacks. Clients however are allowed to ignore or extend it.
	ExpireAt time.Time

	//PublicKey for verifying Ed25519 signature. Could be overridden by
	//options during verification.
	PublicKey []byte

	// HMACSecret is the key used to sign the payload. Could be overridden
	// by options during verification.
	HMACSecret []byte

	//Signature to be verified by the Ed25519 signature algorithm.
	Signature []byte

	// HMACSignature of the signed payload.
	HMACSignature []byte

	// Email of the user. The protocol does not confirm user email and does
	// not intend to do so.
	Email string
}

// Verify token with given options.
func (t Token) Verify(opts ...Option) error {
	var cfg = NewConfig(opts...)

	if len(cfg.publicKey) > 0 {
		t.PublicKey = cfg.publicKey
	}

	if !verifySignature(t.rawPayload, t.Signature, t.PublicKey) {
		return errors.New("invalid signature")
	}

	if cfg.hmac {
		if len(cfg.hmacSecret) > 0 {
			t.HMACSecret = cfg.hmacSecret
		}
		if !verifyHMAC(t.rawPayload, t.HMACSignature, t.HMACSecret) {
			return errors.New("invalid HMAC signature")
		}
	}

	if _, ok := cfg.origins[t.Provider]; !ok {
		return errors.New("invalid provider")
	}

	if !cfg.connect {
		if _, ok := cfg.origins[t.Client]; !ok {
			return errors.New("invalid client")
		}
	}

	if cfg.expire && time.Now().UTC().After(t.ExpireAt) {
		return errors.New("expired token")
	}

	return verifyScope(cfg, t.Scope)
}
