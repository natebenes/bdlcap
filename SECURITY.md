# Security

`bdlcap` is an unsupported experiment for testing interoperability with proposal
135-2024df. Only the latest release is looked at, with no promise of a fix or a
response time. Do not rely on it to protect a production system.

## Reporting a vulnerability

Please report vulnerabilities in this tool privately through
[GitHub security advisories](https://github.com/natebenes/bdlcap/security/advisories/new)
rather than in a public issue.

Concerns about the protocol in Annex YY itself belong in the proposal's public
review, since they affect every implementation.

## Handling credentials and captures

The README describes the risks to be aware of: the password is visible in the
process list during a capture, `--insecure` can send it to an impostor, and
capture files hold traffic in the clear.
