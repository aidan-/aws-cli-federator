package federator

import (
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/RobotsAndPencils/go-saml"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"golang.org/x/net/html"
)

type Federator struct {
	Username    string
	Password    string
	SPEntityUrl string

	http           *http.Client
	samlResponse   *saml.Response
	samlResponse64 string
}

type loginForm struct {
	URL    string
	Values url.Values
}

type Credentials struct {
	AccessKeyId     string
	Expiration      time.Time
	SecretAccessKey string
	SessionToken    string
}

func New(u, p, sp string) (Federator, error) {
	if _, err := url.ParseRequestURI(sp); err != nil {
		return Federator{}, fmt.Errorf("Invalid SPEntityUrl provided: %s\n", err)
	}

	fed := Federator{
		Username:    u,
		Password:    p,
		SPEntityUrl: sp,
	}

	j, err := cookiejar.New(nil)
	if err != nil {
		return fed, fmt.Errorf("Could not create cookiejar: %s", err)
	}

	c := &http.Client{
		Jar: j,
	}
	fed.http = c

	return fed, nil
}

func (a *Federator) Login() error {
	resp, err := a.http.Get(a.SPEntityUrl)
	if err != nil {
		return fmt.Errorf("Could not retrieve IDP login form: %s", err)
	}

	form, err := a.followFormSubmissionsToAWS(resp)
	if err != nil {
		return fmt.Errorf("Unable to get SAMLResponse: %s", err)
	}

	if _, exists := form.Values["SAMLResponse"]; !exists {
		return fmt.Errorf("Authentication failed.  Reached AWS SP without SAMLResponse.")
	}

	sr, err := saml.ParseEncodedResponse(form.Values["SAMLResponse"][0])
	if err != nil {
		return fmt.Errorf("Unable to parse SAML response: %s\n", err)
	}

	a.samlResponse = sr
	a.samlResponse64 = form.Values["SAMLResponse"][0]

	return nil
}

func (a *Federator) GetRoles() ([]Role, error) {
	var r []Role

	roles := a.samlResponse.GetAttributeValues("https://aws.amazon.com/SAML/Attributes/Role")
	if len(roles) < 1 {
		return r, fmt.Errorf("No AWS roles specific in SAMLResponse\n")
	}

	for _, role := range roles {
		r = append(r, Role(role))
	}

	return r, nil
}

func (a *Federator) AssumeRole(r Role) (Credentials, error) {
	if a.samlResponse == nil {
		return Credentials{}, fmt.Errorf("You must call Login before assuming a role")
	}

	svc := sts.New(session.New())
	params := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:  aws.String(r.PrincipalArn()),
		RoleArn:       aws.String(r.RoleArn()),
		SAMLAssertion: aws.String(a.samlResponse64),
	}

	resp, err := svc.AssumeRoleWithSAML(params)
	if err != nil {
		return Credentials{}, fmt.Errorf("Unable to assume role: %s", err)
	}

	return Credentials{
		AccessKeyId:     *resp.Credentials.AccessKeyId,
		Expiration:      *resp.Credentials.Expiration,
		SecretAccessKey: *resp.Credentials.SecretAccessKey,
		SessionToken:    *resp.Credentials.SessionToken,
	}, nil
}

func (a *Federator) fillForm(r *http.Response) (loginForm, error) {
	fv := loginForm{}
	fv.Values = make(url.Values)

	//defer r.Body.Close()
	z := html.NewTokenizer(r.Body)

NodeLoop:
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			// end of document, we are done.
			break NodeLoop
		} else if tt == html.SelfClosingTagToken || tt == html.StartTagToken {
			t := z.Token()
			if t.Data == "form" {
				action, err := findAttrVal("action", t.Attr)
				if err != nil {
					// form doesnt have action field
					break
				}
				fv.URL, err = getAbsoluteFormURL(r.Request.URL, action)
				if err != nil {
					//invalid action given
					//should we abort or continue?
					break
				}
			} else if t.Data == "input" {
				name, err := findAttrVal("name", t.Attr)
				if err != nil {
					continue //element doesnt have name key
				}
				switch {
				case strings.Contains(strings.ToLower(name), "user"):
					fv.Values.Add(name, a.Username)
				case strings.Contains(strings.ToLower(name), "pass"):
					fv.Values.Add(name, a.Password)
				default:
					value, err := findAttrVal("value", t.Attr)
					if err != nil {
						continue //element doesnt have value key
					}
					fv.Values.Add(name, value)
				}
			}
		}
	}

	return fv, nil
}

// followFormSubmissionsToSP parses a http.Response object for form fields.
//  When form fields are found, the method will attempt to substitute configured
//  username and password values into their respective form fields.
//  Once the redirects have reached the AWS SAML SP, the method will return
//  the filled form that should contain the SAMLResponse field.
func (a Federator) followFormSubmissionsToAWS(r *http.Response) (loginForm, error) {
	cur := r
	count := 0 //basic checker to ensure we are not stuck in a post loop
	lastForm := loginForm{}
	for {
		// arbitrary number to try and detect a redirect loop
		if count >= 6 {
			return loginForm{}, fmt.Errorf("Could not reach AWS SP due to redirect loop")
		}

		login, err := a.fillForm(cur)
		if err != nil {
			fmt.Printf("Error getting login form.  Cannot continue.\n")
		}

		// check if the form has been posted already (possible wrong password)
		if lastForm.URL == login.URL {
			if match := reflect.DeepEqual(lastForm.Values, login.Values); match {
				return loginForm{}, fmt.Errorf("Invalid username or password")
			}
		}
		lastForm = login

		url, err := url.Parse(login.URL)
		if err != nil {
			return loginForm{}, fmt.Errorf("Invalid login url")
		}

		// redirects have taken us to the AWS saml endpoint, it has been successful
		if url.Host == "signin.aws.amazon.com" {
			lastForm = login
			break
		}

		resp, err := a.http.PostForm(login.URL, login.Values)
		if err != nil {
			fmt.Printf("Failed to post form: %s", err)
			return loginForm{}, err
		}

		count++
		cur = resp
	}

	return lastForm, nil
}

func findAttrVal(key string, a []html.Attribute) (string, error) {
	for _, attr := range a {
		if key == attr.Key {
			return attr.Val, nil
		}
	}
	return "", fmt.Errorf("No attribute %s", key)
}

func getAbsoluteFormURL(u *url.URL, action string) (string, error) {
	switch action {
	case "?":
		u.RawQuery = ""
		// split uri on
		return u.String(), nil
	case "":
		//exact uri
		return u.String(), nil
	default:
		//this is either a relative or abolsute URI given
		au, err := url.Parse(action)
		if err != nil {
			return "", fmt.Errorf("Could not parse action:%s", err)
		}

		if au.IsAbs() {
			return action, nil
		} else {
			u.Path = action
			u.RawQuery = ""
			return u.String(), nil
		}
	}
}
