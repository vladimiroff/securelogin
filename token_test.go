package securelogin

import (
	"fmt"
	"net/url"
	"testing"
	"time"
)

var (
	accessAllScope = url.Values{"access": []string{"all"}}
	changeScope    = url.Values{
		"to":   []string{"..."},
		"mode": []string{"change"},
	}
	badChangeScope = url.Values{
		"to":   []string{"..."},
		"mode": []string{"nochange"},
	}
	multiModeScope = url.Values{
		"to":   []string{"..."},
		"mode": []string{"nochange", "change"},
	}
	noModeChangeScope = url.Values{
		"to":     []string{"..."},
		"nomode": []string{"change"},
	}
)

func TestTokenVerify(t *testing.T) {
	var cases = []struct {
		opt []Option
		mod tokmod
		err string
	}{
		{[]Option{o}, tokAlive, ""},
		{[]Option{o}, tokExpired, "expired token"},
		{[]Option{o}, tokInvalidSignature, "invalid signature"},
		{[]Option{o, WithPublicKey([]byte("wrong"))}, tokAlive, "invalid signature"},
		{[]Option{o}, tokSmallPublicKey, "invalid signature"},
		{[]Option{o}, tokInvalidProvider, "invalid provider"},
		{[]Option{o}, tokInvalidClient, "invalid client"},
		{[]Option{o, WithHMAC, WithSecret([]byte("wrong"))}, tokAlive, "invalid HMAC signature"},
		{[]Option{o, WithHMAC}, tokInvalidHMAC, "invalid HMAC signature"},
		{[]Option{o, WithConnect}, tokInvalidClient, ""},
		{[]Option{o, WithoutExpire}, tokNoMod, ""},
		{[]Option{o, WithChange}, tokAlive, "not mode=change token"},
		{[]Option{o, WithChange}, tokScopeChange(changeScope), ""},
		{[]Option{o, WithChange}, tokScopeChange(multiModeScope), ""},
		{[]Option{o, WithChange}, tokScopeChange(badChangeScope), "not mode=change token"},
		{[]Option{o, WithChange}, tokScopeChange(noModeChangeScope), "not mode=change token"},
		{[]Option{o, WithScope(changeScope)}, tokScopeChange(badChangeScope), "invalid scope"},
		{[]Option{o, WithScope(changeScope)}, tokScopeChange(accessAllScope), "invalid scope"},
		{[]Option{o, WithScope(multiModeScope)}, tokScopeChange(changeScope), "invalid scope"},
	}

	token, err := UnmarshalString(token)
	if err != nil {
		t.Skipf("UnmarshalToken has failed with %q, skipping Verify")
	}

	for i, c := range cases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			token := c.mod(token)
			err := token.Verify(c.opt...)
			if c.err == "" {
				if err != nil {
					t.Fatalf("Unexpected error: %s", err)
				}
			} else {
				if err == nil {
					t.Fatalf("Expected error; got nil")
				}
				if c.err != err.Error() {
					t.Fatalf("Expected error %s; got %s", c.err, err)
				}
			}
		})
	}
}

var o = WithOrigins("https://cobased.com")

type tokmod func(Token) Token

func tokNoMod(t Token) Token {
	return t
}

func tokAlive(t Token) Token {
	t.ExpireAt = time.Now().Add(1 * time.Hour)
	return t
}

func tokExpired(t Token) Token {
	t.ExpireAt = time.Now().Add(-1 * time.Hour)
	return t
}

func tokInvalidSignature(t Token) Token {
	t.Signature = []byte{0xD, 0xE, 0xD, 0xB, 0xE, 0xE, 0xE, 0xF}
	return t
}

// This shouldn't even call ed25519.Verify, but fail on checking size of the key
func tokSmallPublicKey(t Token) Token {
	t.PublicKey = t.PublicKey[:len(t.PublicKey)-2]
	return t
}

func tokInvalidHMAC(t Token) Token {
	t.HMACSignature = []byte{0xD, 0xE, 0xD, 0xB, 0xE, 0xE, 0xE, 0xF}
	return t
}

func tokInvalidProvider(t Token) Token {
	t.Provider = "evilcorp.com"
	return t
}

func tokInvalidClient(t Token) Token {
	t = tokAlive(t)
	t.Client = "evilcorp.com"
	return t
}

func tokScopeChange(scope url.Values) func(t Token) Token {
	return func(t Token) Token {
		t = tokAlive(t)
		t.Scope = scope
		return t
	}
}
