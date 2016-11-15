package federator

import (
	"fmt"
	"regexp"
	"strings"
)

type Role string

// String creates a prettier representation of the raw RoleArn/PrincipalArn
//  string for presenting to the user
func (r Role) String() string {
	//doesn't match all valid characters according to doco
	//http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-limits.html
	re := regexp.MustCompile("arn:aws:iam::(\\d+):role/(\\w+)")
	parts := re.FindStringSubmatch(string(r))

	return fmt.Sprintf("%s - %s", parts[1], parts[2])
}

func (r Role) RoleArn() string {
	return strings.Split(string(r), ",")[0]
}

func (r Role) PrincipalArn() string {
	return strings.Split(string(r), ",")[1]
}

func (r Role) AccountId() string {
	re := regexp.MustCompile("arn:aws:iam::(\\d+):role")
	a := re.FindStringSubmatch(string(r))

	return a[1]
}

func (r Role) RoleName() string {
	re := regexp.MustCompile("arn:aws:iam::\\d+:role/(\\w+)")
	a := re.FindStringSubmatch(string(r))

	return a[1]
}
