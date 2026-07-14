# Contributing to ScopeHarbor

Thank you for your interest in ScopeHarbor.

This repository is currently **source-visible, not open source**. No license is
granted; all reuse rights are reserved. Until a license and contribution terms
are selected, external pull requests are not accepted and contributions cannot
be assumed to confer reuse rights.

General non-sensitive feedback may be shared through repository channels when
they are enabled. Report security defects privately using the process in
[`SECURITY.md`](SECURITY.md); never include real secrets, target data, or exploit
details in a public issue.

## Maintainer development workflow

Maintainers must follow [`AGENTS.md`](AGENTS.md), especially its phase branch,
commit, review, safety, and user-action rules. Changes should be cohesive,
verified first with targeted tests and then broader clean-database checks, and
must preserve the deny-by-default scope.

Before proposing an internal change:

- explain intended behavior and security boundaries;
- add denial-path, workspace-isolation, and redaction tests where relevant;
- keep product APIs under `/api/v1` and use safe public projections;
- update architecture, threat-model, API, operator, and upgrade docs when their
  contracts change;
- run Ruff, Pyright, backend branch coverage, frontend lint/build, migrations,
  dependency audits, and relevant container smoke tests;
- never commit `.env`, auth-profile keys, ZAP keys, tokens, provider keys,
  scanner output, reports containing target data, or local database artifacts.

## Scanner changes

New or broadened scanner behavior requires explicit scope approval. A scanner
adapter must be allowlist/root confined, bounded, cancellable, non-executing for
repository content, deterministic about failure/warning behavior, independently
sanitized, and covered by adversarial fixtures. Public/cloud scanning,
authenticated browser workflows, repository code execution, and online
dependency resolution are outside current scope.

## Licensing status

Do not add third-party code or assets whose terms have not been reviewed. The
repository owner must choose and add a license before accepting outside code or
describing ScopeHarbor as open source.
