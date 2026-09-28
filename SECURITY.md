# Security Policies and Procedures

This document outlines security procedures and general policies for the
`Identity` project.

- [Security Policies and Procedures](#security-policies-and-procedures)
  - [Disclosing a security issue](#disclosing-a-security-issue)
  - [Vulnerability management](#vulnerability-management)
  - [Dependency vulnerability exceptions](#dependency-vulnerability-exceptions)
  - [Suggesting changes](#suggesting-changes)

## Disclosing a security issue

The `Identity` maintainers take all security issues in the project
seriously. Thank you for improving the security of `Identity`. We
appreciate your dedication to responsible disclosure and will make every effort
to acknowledge your contributions.

`Identity` leverages GitHub's private vulnerability reporting.

To learn more about this feature and how to submit a vulnerability report,
review [GitHub's documentation on private reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).

Here are some helpful details to include in your report:

- a detailed description of the issue
- the steps required to reproduce the issue
- versions of the project that may be affected by the issue
- if known, any mitigations for the issue

A maintainer will acknowledge the report within three (3) business days, and
will send a more detailed response within an additional three (3) business days
indicating the next steps in handling your report.

If you've been unable to successfully draft a vulnerability report via GitHub or
have not received a response during the alloted response window, please reach out via
[security@agntcy.org](mailto:security@agntcy.org) contact email.

After the initial reply to your report, the maintainers will endeavor to keep
you informed of the progress towards a fix and full announcement, and may ask
for additional information or guidance.

## Vulnerability management

When the maintainers receive a disclosure report, they will assign it to a
primary handler.

This person will coordinate the fix and release process, which involves the
following steps:

- confirming the issue
- determining affected versions of the project
- auditing code to find any potential similar problems
- preparing fixes for all releases under maintenance

## Dependency vulnerability exceptions

Exceptions in `osv-scanner.toml` must identify a specific advisory and explain
why the affected code is not used. They must be revalidated before expiry or
when the relevant dependencies or build targets change.

### GO-2026-5932: unused OpenPGP packages

The root Go module requires `golang.org/x/crypto`, but does not import its
deprecated `openpgp` package or any of its subpackages, including through
transitive dependencies or tests. This advisory has no fixed version, so
upgrading `x/crypto` does not resolve the module-level finding.

On 2026-09-28, `CGO_ENABLED=0 govulncheck -test -show verbose ./...` reported
zero vulnerable imported packages and zero reachable vulnerabilities in the
root module. The client and both Go tooling modules were also scanned and
reported no vulnerabilities. The exception applies only to the root module
and expires on 2026-12-31.

The required test job runs `bash scripts/security/check-no-openpgp.sh`, which
checks the host dependency graph and the Linux, macOS, and Windows graphs for
both amd64 and arm64, including tests. The cross-platform checks disable CGO.
An OpenPGP import or a package-loading error fails the job. Add any new release
targets or build tags to this check before relying on the exception for them.

To revalidate, run the guard and `govulncheck -test -show verbose ./...` from
the root module. Review the package-level results, not only the exit code:
an affected package must remain absent even if no vulnerable symbol is called.
If OpenPGP becomes necessary, remove the exception and use a maintained
implementation as described in the
[Go advisory](https://pkg.go.dev/vuln/GO-2026-5932).

## Suggesting changes

If you have suggestions on how this process could be improved please submit an
issue or pull request.
