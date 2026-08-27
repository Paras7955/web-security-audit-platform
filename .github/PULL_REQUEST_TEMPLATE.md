## Summary

Describe the defensive problem, the bounded change, and the user-visible result.

## Security boundaries

Explain any effect on scanner authority, allowlisting/SSRF, TLS, authentication,
workspace isolation, redaction, persistence, reports, AI, container networks, or
repository execution. Write `No trust-boundary change` only after reviewing
each area.

## Verification

List the exact checks you ran and any checks that remain for CI or a maintainer.

## Contributor checklist

- [ ] The change is intended only for owned or explicitly authorized targets.
- [ ] Tests cover relevant denial, isolation, redaction, and failure paths.
- [ ] Documentation and upgrade notes match the implemented behavior.
- [ ] No credentials, personal/production data, raw traffic, scanner output,
      generated artifacts, or unlicensed copied material are included.
- [ ] Dependency or image additions identify their license and provenance.
- [ ] The change does not add arbitrary public scanning, insecure TLS,
      repository code execution, or another unsupported trust-boundary bypass.

ScopeHarbor is maintained as a portfolio project. Submissions are reviewed and
accepted at the maintainer's discretion; no response or merge timeline is
guaranteed.

