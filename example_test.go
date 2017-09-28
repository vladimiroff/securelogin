package securelogin_test

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/vladimiroff/securelogin"
)

const domain = "https://cobased.com"

var sltoken = []byte("https://cobased.com%2Chttps://cobased.com%2C%2C1498731060," +
	"E5faDp1F3F4AGN2z5NgwZ/e0WB+ukZO3eMRWvTTZc4erts8mMzSy+CxGdz3OW1Xff8p6m" +
	"DAPfnSK0QqSAAHmAA==%2CcIZjUTqMWYgzYGrsYEHptNiaaLapWiqgPPsG1PI/Rsw=," +
	"kdbjcc08YBKWdCY56lQJIi92wcGOW+KcMvbSgHN6WbU=%2C1OVh/+xHRCaebQ9Lz6k" +
	"OTkTRrVm1xgvxGthABCwCQ8k=,homakov@gmail.com")

func ExampleVerify() {
	t, err := securelogin.Verify(sltoken, securelogin.WithOrigins(domain), securelogin.WithoutExpire)
	if err != nil {
		fmt.Printf("verify failed: %s", err)
		return
	}

	fmt.Printf("logged in as %s\n", t.Email)
	// Output: logged in as homakov@gmail.com
}

func ExampleToken_Verify_expired() {
	t, err := securelogin.Unmarshal(sltoken)
	if err != nil {
		fmt.Printf("unmarshal failed: %s", err)
		return
	}

	// Expired one hour ago
	t.ExpireAt = time.Now().Add(-1 * time.Hour)

	err = t.Verify(securelogin.WithOrigins(domain))
	fmt.Printf("%s\n", err)
	// Output: expired token
}

func ExampleToken_Verify() {
	t, err := securelogin.Unmarshal(sltoken)
	if err != nil {
		fmt.Printf("unmarshal failed: %s", err)
		return
	}

	err = t.Verify(securelogin.WithOrigins(domain), securelogin.WithoutExpire)
	fmt.Printf("successful verify: %t", err == nil)
	// Output: successful verify: true
}

func ExampleDecoder() {
	var t securelogin.Token
	dec := securelogin.NewDecoder(bytes.NewReader(sltoken))

	if err := dec.Decode(&t); err != nil {
		fmt.Printf("decode failed: %s", err)
		return
	}

	fmt.Printf("token of %s\n", t.Email)
	// Output: token of homakov@gmail.com

}

func ExampleEncoder() {
	t, err := securelogin.Unmarshal(sltoken)
	if err != nil {
		fmt.Printf("unmarshal failed: %s", err)
		return
	}

	enc := securelogin.NewEncoder(os.Stdout)
	if err = enc.Encode(t); err != nil {
		fmt.Printf("encode failed: %s", err)
		return
	}

	// Output: https://cobased.com%2Chttps://cobased.com%2C%2C1498731060,E5faDp1F3F4AGN2z5NgwZ/e0WB+ukZO3eMRWvTTZc4erts8mMzSy+CxGdz3OW1Xff8p6mDAPfnSK0QqSAAHmAA==%2CcIZjUTqMWYgzYGrsYEHptNiaaLapWiqgPPsG1PI/Rsw=,kdbjcc08YBKWdCY56lQJIi92wcGOW+KcMvbSgHN6WbU=%2C1OVh/+xHRCaebQ9Lz6kOTkTRrVm1xgvxGthABCwCQ8k=,homakov@gmail.com

}
