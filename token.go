package securelogin

import (
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
