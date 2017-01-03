# AWS CLI Federator [![Build Status](https://travis-ci.org/aidan-/aws-cli-federator.svg?branch=master)](https://travis-ci.org/aidan-/aws-cli-federator)
Based off the [original AWS blog post](https://blogs.aws.amazon.com/security/post/Tx1LDN0UBGJJ26Q/How-to-Implement-Federated-API-and-CLI-Access-Using-SAML-2-0-and-AD-FS), this small yet useful utility enables the generation and management of temporary IAM credentials via CLI using a SAML/ADFS federation provider.

This particular implementation was written in Go to ease dependency management and simplify the installation procedure for non-developers.  It is compatible with both Windows and Unix based systems, and should work with a wide variety of SAML/ADFS IDP's.

`aws-cli-federator` assumes you have [IAM SAML Federation](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-saml.html) configured and working.  

## Getting Started
Precompiled packages are available on the [releases](https://github.com/aidan-/aws-cli-federator/releases) page.  After downloading, place the binary in your `$PATH` for added convienice.

### Usage
Before you can start generating temporary credentials, you'll need to create a basic `federatedcli` configuration file under your `.aws` directory. (This file is `~/.aws/federatedcli` on Unix systems and `%userprofile%/.aws/federatedcli` for Windows) 
```
[default]
sp_identity_url = <url to IDP initiated SP login>
```

You can then generate temporary credentials by running the `aws-cli-federator` utility:

```
$ aws-cli-federator
Enter Username: aidan
Enter Password:
1) arn:aws:iam::123456789123:role/GlobalAdmin
2) arn:aws:iam::123456789123:role/ReadOnly
3) arn:aws:iam::123456789123:role/DBAdministration
4) arn:aws:iam::123456789123:role/NetworkAdministrator
Enter the ID# of the role you want to assume: 3
-------------------------------------------------------
Temporary credentials successfully generated. Set the following environment variables to being using them:

export AWS_ACCESS_KEY_ID=<redacted>
export AWS_SECRET_ACCESS_KEY=<redacted>
export AWS_SESSION_TOKEN=<redacted>

These credentials will remain valid until 2017-01-03 03:29:22 +0000 UTC
```

If you log into multiple accounts using different IDP URL's, you can add multiple `sp_identity_url`'s (under unique section names) and request credentials like so:

```
$ aws-cli-federator -account <account name>
```

This tool can also write the generated temporary credentials to the `~/.aws/credentials` file using the `-profile <section name>` flag.  The section and credentials will be created if they do not already exist and overwritten if they do.

```
$ aws-cli-federator -acount <account name> -profile <profile name>
```

If your IDP federates authentication to a number of different accounts, it can get difficult to keep track of which account number is which account.  To simplify this, you can add a list of alias' to the `federatedcli` configuration file to overwrite the account number with a more memerable name.

```
[account_map]
123456789123 = production
317261927392 = development
```

Lastly, if you are constantly generating a lot of temporary credentials you might be interested to know that `aws-cli-federator` outputs all output to `stderr` except for the environment variables.  This allows you to quickly set the environment variables in your current terminal session like so:

```
$ eval `aws-cli-federator`
```

## Building
You can build the tool from source by running `make` in the base directory.  The output binary will be located in the `./build/` directory.

## IDP Compatibility
This utility tries to remain agnostic and should work with most SAML/SHIB/ADFS identity providers.  I personally run this against a fairly generic [SimpleSAMLphp](https://simplesamlphp.org/) configuration.

## Contributing / Issues
If you have any feature suggestions or bug fixes, please open an issue or a pull request! 

If you have an issue, please include as much information as possible including running the utility in debug mode (`-v` flag).