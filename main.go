package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/aidan-/aws-cli-federator/federator"
	"github.com/go-ini/ini"
	"github.com/howeyc/gopass"
)

type configuration struct {
	version *bool
	verbose *bool
	path    string
	cfg     *ini.File

	account string
	profile string
}

var Version = "1.0.0"

var c configuration //arguments
var l *log.Logger

func init() {
	c.version = flag.Bool("version", false, "prints cli version information")
	c.verbose = flag.Bool("v", false, "print debug messages to STDOUT")

	flag.StringVar(&c.path, "path", "", "set path to aws-federator configuration")
	flag.StringVar(&c.account, "account", "", "set which AWS account configuration should be used")
	flag.StringVar(&c.account, "acct", "", "set which AWS account configuration should be used (shorthand)")
	flag.StringVar(&c.profile, "profile", "", "set which AWS credential profile the temporary credentials should be written to. Defaults to 'default'")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		os.Exit(1)
	}
}

func (c *configuration) loadConfigurationFile() error {
	if c.path == "" {
		usr, err := user.Current()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Unable to get current user information: %s\n", err)
			os.Exit(1)
		}

		l.Printf("Found user's homedirectory: %s\n", usr.HomeDir)
		c.path = filepath.Join(usr.HomeDir, ".aws/federatedcli")
	}

	l.Printf("Loading configuration from file: %s\n", c.path)
	cfg, err := ini.Load(c.path)
	if err != nil {
		return err
	}
	cfg.BlockMode = false
	c.cfg = cfg

	return nil
}

// findAccount looks through the loaded configuration file to locate a
//   matching account declaration with the account name loaded from the CLI.
// It returns the configuration block if there is a match and false if there
//   is not.
func (c configuration) matchAccount() (*ini.Section, bool) {
	for _, acct := range c.cfg.Sections() {
		if acct.Name() == c.account {
			return acct, true
		}
	}

	return &ini.Section{}, false
}

func main() {
	flag.Parse()

	if *c.version {
		fmt.Fprintf(os.Stderr, "%s version %s\n", filepath.Base(os.Args[0]), Version)
		os.Exit(0)
	}

	l = log.New(ioutil.Discard, "", log.LstdFlags)
	if *c.verbose {
		l.SetOutput(os.Stderr)
	}

	if c.account == "" {
		c.account = "default"
	}

	if err := c.loadConfigurationFile(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Unable to parse configuration file: %s\n", err)
		os.Exit(1)
	}

	acct, found := c.matchAccount()
	if !found {
		fmt.Fprintf(os.Stderr, "ERROR: Could not find configuration matching provided account name '%s'\n", c.account)
		os.Exit(1)
	}

	if !acct.HasKey("sp_identity_url") {
		fmt.Fprintf(os.Stderr, "ERROR: Account configuration '%s' does not have an 'sp_identity_url' defined\n", c.account)
		os.Exit(1)
	}
	spIdentityURL := acct.Key("sp_identity_url").String()

	//get username
	user := ""
	if acct.HasKey("username") {
		user = acct.Key("username").String()
	} else {
		reader := bufio.NewReader(os.Stdin)
		fmt.Fprint(os.Stderr, "Enter Username: ")
		u, _ := reader.ReadString('\n')
		user = strings.TrimSpace(u)
	}

	//get password
	pass := ""
	if acct.HasKey("password") {
		pass = acct.Key("password").String()
	} else {
		fmt.Fprint(os.Stderr, "Enter Password: ")
		var err error
		p, err := gopass.GetPasswd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Could not get password: %s\n", err)
			os.Exit(1)
		}
		pass = string(p)
		//pass = strings.TrimSpace(p)
	}

	aws, err := federator.New(user, pass, spIdentityURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to initialize federator: %s\n", err)
		os.Exit(1)
	}

	if err = aws.Login(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Authentication failure: %s\n", err)
		os.Exit(1)
	}

	roles, err := aws.GetRoles()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Could not retrieve roles: %s\n", err)
	}

	var roleToAssume federator.Role
	if acct.HasKey("assume_role") {
		for _, r := range roles {
			if acct.Key("assume_role").String() == string(r) {
				roleToAssume = r
				break
			}
		}
		if roleToAssume == "" {
			//couldn't find the role
			fmt.Fprintf(os.Stderr, "ERROR: Unable to find role '%s'.  Perhaps your federator configuration is incorrect?\n", acct.Key("assume_role").String())
			os.Exit(1)
		}
	} else {
		if len(roles) == 1 {
			roleToAssume = roles[0]
		} else {
			roleMap := make(map[string]federator.Role) // mapping of pretty names to roles
			var printableRoles []string                // slice for sorting matched pretty names
			var unmatchedRoles []string                // slice for sorting unmatched pretty names

			// iterate over available roles to build up a map of 'printable role name' -> role arn
			// capture the key names in string arrays for order sorting
			accountMap, err := c.cfg.GetSection("account_map") // mapping of accountId's to pretty names
			if err == nil {
				for _, role := range roles {
					if accountMap.HasKey(role.AccountId()) {
						an := accountMap.Key(role.AccountId()).String()
						roleMap[fmt.Sprintf("%s:role/%s", an, role.RoleName())] = role
						printableRoles = append(printableRoles, fmt.Sprintf("%s:role/%s", an, role.RoleName()))
					} else {
						roleMap[fmt.Sprintf("%s", role.RoleArn())] = role
						unmatchedRoles = append(unmatchedRoles, role.RoleArn())
					}
				}
			} else {
				for _, role := range roles {
					roleMap[fmt.Sprintf("%s", role.RoleArn())] = role
				}
			}

			// sort the role keys alphabetically and append the unmatchedRoles to the printableRoles array to ensure they appear last
			sort.Strings(printableRoles)
			sort.Strings(unmatchedRoles)

			for _, k := range unmatchedRoles {
				printableRoles = append(printableRoles, k)
			}

			for n, r := range printableRoles {
				fmt.Fprintf(os.Stderr, "%d) %s\n", n+1, r)
			}

			var i int // user selection
			fmt.Fprintf(os.Stderr, "Enter the ID# of the role you want to assume: ")

			_, err = fmt.Scanf("%d", &i)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: Invalid selection made.\n")
				os.Exit(1)
			}

			if i > len(roles)+1 {
				fmt.Fprintf(os.Stderr, "ERROR: Invalid ID selection, but in range from %d to %d.\n", 1, len(roles)+1)
				os.Exit(1)
			}

			roleToAssume = roleMap[printableRoles[i-1]]
		}
	}

	l.Printf("User has selected ARN: %s\n", roleToAssume)
	l.Printf("Attempting to AssumeRoleWithSAML\n")
	creds, err := aws.AssumeRole(roleToAssume)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to assume role: %s", err)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "-------------------------------------------------------")
	// output temporary credentials to stdout instead of writing to credentials file
	if c.profile == "" {
		fmt.Fprintf(os.Stderr, "Temporary credentials successfully generated. Set the following environment variables to being using them:\n\n")
		if runtime.GOOS == "windows" {
			fmt.Printf("set AWS_ACCESS_KEY_ID=%s\n", creds.AccessKeyId)
			fmt.Printf("set AWS_SECRET_ACCESS_KEY=%s\n", creds.SecretAccessKey)
			fmt.Printf("set AWS_SESSION_TOKEN=%s\n", creds.SessionToken)
		} else {
			fmt.Printf("export AWS_ACCESS_KEY_ID=%s\n", creds.AccessKeyId)
			fmt.Printf("export AWS_SECRET_ACCESS_KEY=%s\n", creds.SecretAccessKey)
			fmt.Printf("export AWS_SESSION_TOKEN=%s\n", creds.SessionToken)
		}
	} else {
		if err := WriteAWSCredentials(creds, c.profile); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to write credentials: %s", err)
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "Temporary credentials successfully saved to credential profile '%s'.\nYou can use these credentials with the AWS CLI by including the '--profile %s' flag.\n", c.profile, c.profile)

	}
	fmt.Fprintf(os.Stderr, "\nThese credentials will remain valid until %s\n", creds.Expiration.String())
}

func WriteAWSCredentials(c federator.Credentials, p string) error {
	usr, err := user.Current()
	if err != nil {
		return fmt.Errorf("Unable to get current user information: %s\n", err)
	}

	cpath := filepath.Join(usr.HomeDir, ".aws/credentials")

	l.Printf("Writing to AWS credentials file: %s\n", cpath)
	cfg, err := ini.Load(cpath)
	if err != nil {
		return err
	}

	if _, err := cfg.GetSection(p); err != nil {
		if _, err := cfg.NewSection(p); err != nil {
			return fmt.Errorf("Unable to create credential profile: %s", err)
		}
	}

	prof, err := cfg.GetSection(p)
	if err != nil {
		return fmt.Errorf("Unable to retrieve recently created profile: %s", err)
	}

	//aws_access_key_id
	if _, err := prof.NewKey("aws_access_key_id", c.AccessKeyId); err != nil {
		return fmt.Errorf("Unable to write aws_access_key_id to credential file: %s", err)
	}

	//aws_secret_access_key
	if _, err := prof.NewKey("aws_secret_access_key", c.SecretAccessKey); err != nil {
		return fmt.Errorf("Unable to write aws_secret_access_key to credential file: %s", err)
	}

	//aws_session_token
	if _, err := prof.NewKey("aws_session_token", c.SessionToken); err != nil {
		return fmt.Errorf("Unable to write aws_session_token to credential file: %s", err)
	}

	if err := cfg.SaveTo(filepath.Join(usr.HomeDir, ".aws/credentials")); err != nil {
		return fmt.Errorf("Unable to save configuration to disk: %s", err)
	}

	return nil
}
