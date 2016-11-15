# AWS CLI Federator
Based off the [original AWS blog post](https://blogs.aws.amazon.com/security/post/Tx1LDN0UBGJJ26Q/How-to-Implement-Federated-API-and-CLI-Access-Using-SAML-2-0-and-AD-FS), this small yet useful utility enables the generation and management of temporary IAM credentials using a SAML/ADFS federation provider.

This particular implementation was written in Go to ease dependency management and simplify the installation procedure for non-developers.  It is compatible with both Windows and Unix based systems, and should work with a wide variety of SAML/ADFS IDP's.

More coming soon.
