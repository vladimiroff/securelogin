package securelogin_test

import (
	"fmt"

	"github.com/vladimiroff/securelogin"
)

const (
	domain = "https://cobased.com"
	token  = "https://cobased.com%2Chttps://cobased.com%2C%2C1498731060," +
		"E5faDp1F3F4AGN2z5NgwZ/e0WB+ukZO3eMRWvTTZc4erts8mMzSy+CxGdz3OW1Xff8p6m" +
		"DAPfnSK0QqSAAHmAA==%2CcIZjUTqMWYgzYGrsYEHptNiaaLapWiqgPPsG1PI/Rsw=," +
		"kdbjcc08YBKWdCY56lQJIi92wcGOW+KcMvbSgHN6WbU=%2C1OVh/+xHRCaebQ9Lz6k" +
		"OTkTRrVm1xgvxGthABCwCQ8k=,homakov@gmail.com"
)

func ExampleVerify() {
	t, err := securelogin.Verify(token, securelogin.WithOrigins(domain), securelogin.WithoutExpire)
	if err != nil {
		fmt.Printf("verify failed: %s", err)
		return
	}

	fmt.Printf("logged in as %s\n", t.Email)
	// Output: logged in as homakov@gmail.com
}
