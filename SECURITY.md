# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** through
[GitHub Security Advisories](https://github.com/manuxio/easyOidcProvider/security/advisories/new)
— do not open a public issue for anything you believe is exploitable.

You can expect an acknowledgement within a few days. Please include enough
detail to reproduce the problem (configuration, request flow, versions).

## Supported versions

The latest released minor version receives security fixes.

## Design notes relevant to security

- **Fail closed, everywhere.** A directory, database or seed source that
  cannot answer is a rejection, never a pass — at login and at every refresh.
- **No secrets in the image.** Keytabs, bind passwords and connection strings
  are mounted or injected at run time; the published image contains code only.
- **PKCE S256 is mandatory** and cannot be disabled for public clients.
- **Anti-enumeration.** Unknown users burn the same password-verification work
  as wrong passwords, and the login page never says which factor failed.
- **Rate limiting** with a per-username cool-down guards the password form.
