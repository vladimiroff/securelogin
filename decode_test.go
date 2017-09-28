package securelogin

import (
	"fmt"
	"strings"
	"testing"
)

const (
	decTruncToken = "https://cobased.com%2Chttps://cobased.com%2C%2C1498731060,"
	decBadPayload = "https://cobased.com%2Chttps://cobased.com%2C1498731060," +
		"E5faDp1F3F4AGN2z5NgwZ/e0WB+ukZO3eMRWvTTZc4erts8mMzSy+CxGdz3OW1Xff8p6m" +
		"DAPfnSK0QqSAAHmAA==%2CcIZjUTqMWYgzYGrsYEHptNiaaLapWiqgPPsG1PI/Rsw=," +
		"kdbjcc08YBKWdCY56lQJIi92wcGOW+KcMvbSgHN6WbU=%2C1OVh/+xHRCaebQ9Lz6k" +
		"OTkTRrVm1xgvxGthABCwCQ8k=,homakov@gmail.com"
	decBadScope = "https://cobased.com%2Chttps://cobased.com%2C%%2C1498731060," +
		"E5faDp1F3F4AGN2z5NgwZ/e0WB+ukZO3eMRWvTTZc4erts8mMzSy+CxGdz3OW1Xff8p6m" +
		"DAPfnSK0QqSAAHmAA==%2CcIZjUTqMWYgzYGrsYEHptNiaaLapWiqgPPsG1PI/Rsw=," +
		"kdbjcc08YBKWdCY56lQJIi92wcGOW+KcMvbSgHN6WbU=%2C1OVh/+xHRCaebQ9Lz6k" +
		"OTkTRrVm1xgvxGthABCwCQ8k=,homakov@gmail.com"
	decBadExpireAt = "https://cobased.com%2Chttps://cobased.com%2C%2Ctoday," +
		"E5faDp1F3F4AGN2z5NgwZ/e0WB+ukZO3eMRWvTTZc4erts8mMzSy+CxGdz3OW1Xff8p6m" +
		"DAPfnSK0QqSAAHmAA==%2CcIZjUTqMWYgzYGrsYEHptNiaaLapWiqgPPsG1PI/Rsw=," +
		"kdbjcc08YBKWdCY56lQJIi92wcGOW+KcMvbSgHN6WbU=%2C1OVh/+xHRCaebQ9Lz6k" +
		"OTkTRrVm1xgvxGthABCwCQ8k=,homakov@gmail.com"
	decBadSignatures = "https://cobased.com%2Chttps://cobased.com%2C%2C1498731060," +
		"E5faDp1F3F4AGN2z5NgwZ/e0WB+ukZO3eMRWvTTZc4erts8mMzSy+CxGdz3OW1Xff8p6m" +
		"DAPfnSK0QqSAAHmAA==%2CcIZjUTqMWYgzYGrsYEHptNiaaLapWiqgPPsG1PI/Rsw," +
		"kdbjcc08YBKWdCY56lQJIi92wcGOW+KcMvbSgHN6WbU=%2C1OVh/+xHRCaebQ9Lz6k" +
		"OTkTRrVm1xgvxGthABCwCQ8k=,homakov@gmail.com"
	decBadKeys = "https://cobased.com%2Chttps://cobased.com%2C%2C1498731060," +
		"E5faDp1F3F4AGN2z5NgwZ/e0WB+ukZO3eMRWvTTZc4erts8mMzSy+CxGdz3OW1Xff8p6m" +
		"DAPfnSK0QqSAAHmAA==%2CcIZjUTqMWYgzYGrsYEHptNiaaLapWiqgPPsG1PI/Rsw=," +
		"kdbjcc08YBKWdCY56lQJIi92wcGOW+KcMvbSgHN6WbU%2C1OVh/+xHRCaebQ9Lz6k" +
		"OTkTRrVm1xgvxGthABCwCQ8k=,homakov@gmail.com"
	decMissingKey = "https://cobased.com%2Chttps://cobased.com%2C%2C1498731060," +
		"E5faDp1F3F4AGN2z5NgwZ/e0WB+ukZO3eMRWvTTZc4erts8mMzSy+CxGdz3OW1Xff8p6m" +
		"DAPfnSK0QqSAAHmAA==%2CcIZjUTqMWYgzYGrsYEHptNiaaLapWiqgPPsG1PI/Rsw=," +
		"kdbjcc08YBKWdCY56lQJIi92wcGOW+KcMvbSgHN6WbU=,homakov@gmail.com"
)

var decodeCases = []struct {
	str string
	err error
}{
	{token, nil},
	{"", wrap("token", "expected 4 elements, got 1")},
	{decTruncToken, wrap("token", "expected 4 elements, got 2")},
	{decBadPayload, wrap("payload", "expected 4 elements, got 3")},
	{decBadScope, wrap("payload", "parsing scope failed")},
	{decBadExpireAt, wrap("payload", "invalid expire time")},
	{decBadSignatures, wrap("signatures", "illegal base64 data at input byte 40")},
	{decBadKeys, wrap("keys", "illegal base64 data at input byte 40")},
	{decMissingKey, wrap("keys", "expected 2 elements, got 1")},
}

func TestUnmarshal(t *testing.T) {
	for i, c := range decodeCases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			_, err := Unmarshal([]byte(c.str))
			compareErrors(t, c.err, err)
		})
	}
}

func TestDecoder(t *testing.T) {
	for i, c := range decodeCases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			tok := new(Token)
			dec := NewDecoder(strings.NewReader(c.str))
			err := dec.Decode(tok)
			compareErrors(t, c.err, err)
		})
	}
}

func compareErrors(t *testing.T, expected, actual error) {
	if expected == nil {
		fatal(t, actual)
	} else {
		if actual == nil {
			t.Fatalf("Expected error; got nil")
		}
		if expected.Error() != actual.Error() {
			t.Fatalf("Expected error %q; got %q", expected, actual)
		}
	}
}
