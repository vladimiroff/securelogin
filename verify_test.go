package securelogin

import "testing"
import "time"

const (
	domain = "https://cobased.com"
	token  = "https://cobased.com%2Chttps://cobased.com%2C%2C1498731060," +
		"E5faDp1F3F4AGN2z5NgwZ/e0WB+ukZO3eMRWvTTZc4erts8mMzSy+CxGdz3OW1Xff8p6m" +
		"DAPfnSK0QqSAAHmAA==%2CcIZjUTqMWYgzYGrsYEHptNiaaLapWiqgPPsG1PI/Rsw=," +
		"kdbjcc08YBKWdCY56lQJIi92wcGOW+KcMvbSgHN6WbU=%2C1OVh/+xHRCaebQ9Lz6k" +
		"OTkTRrVm1xgvxGthABCwCQ8k=,homakov@gmail.com"
)

func TestSuccessfulVerify(t *testing.T) {
	tok, err := Verify([]byte(token), WithOrigins(domain), WithoutExpire)
	if err != nil {
		t.Errorf("Unexpected error: %s", err)
	}

	if tok.Client != domain {
		fail(t, "client", domain, tok.Client)
	}

	if tok.Provider != domain {
		fail(t, "provider", domain, tok.Provider)
	}

	expectedExpireAt := time.Date(2017, 6, 29, 10, 11, 0, 0, time.UTC)
	if !tok.ExpireAt.Equal(expectedExpireAt) {
		fail(t, "token", expectedExpireAt, tok.ExpireAt)
	}
}

func TestEmptyTokenDoesntVerify(t *testing.T) {
	_, err := Verify([]byte{})
	if err == nil {
		t.Fatalf("Empty token shouldn't Verify")
	}

	_, err = Verify(nil)
	if err == nil {
		t.Fatalf("Empty token shouldn't Verify")
	}
}

func fail(t *testing.T, name, expected, got interface{}) {
	t.Errorf("Expected %s to be %q; got %q", name, expected, got)
}
