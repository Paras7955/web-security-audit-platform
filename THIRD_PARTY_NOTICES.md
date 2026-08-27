# Third-Party Notices

ScopeHarbor source code is licensed under the [MIT License](LICENSE). This
document identifies the principal third-party software that ScopeHarbor
installs, builds, or asks Docker to run. Those components remain subject to
their own copyright notices and license terms.

This inventory is intended to make the project's dependency provenance easy to
review. It is not legal advice and it does not replace the license files shipped
with each package or container image.

## Bundled scanning tools

The ScopeHarbor worker image builds the following binaries from pinned upstream
source revisions and copies them into the final image.

| Component | ScopeHarbor pin | License | Upstream source and license |
| --- | --- | --- | --- |
| Gitleaks | 8.30.1 (`83d9cd6`) | MIT | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) |
| OSV-Scanner | 2.5.0 (`a55e6f8`) | Apache-2.0 | [google/osv-scanner](https://github.com/google/osv-scanner) |

ScopeHarbor uses the open-source Gitleaks scanner executable, not the separately
licensed `gitleaks-action` GitHub Action.

## Compose services and CI tooling

These digest-pinned images are pulled or built as part of the documented setup
or CI process. They are not relicensed by ScopeHarbor.

| Component | ScopeHarbor pin | Primary project license | Upstream source and license |
| --- | --- | --- | --- |
| PostgreSQL | 16.14 on Alpine 3.24 | PostgreSQL License | [PostgreSQL license](https://www.postgresql.org/about/licence/) |
| Zed Attack Proxy (ZAP) | 2.17.0 stable image | Apache-2.0 | [ZAP legal notice](https://github.com/zaproxy/zaproxy/blob/main/LEGALNOTICE.md) |
| OWASP Juice Shop | 20.1.1 | MIT | [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) |
| Trivy | 0.70.0 | Apache-2.0 | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) |

ZAP, Juice Shop, PostgreSQL, Trivy, and their images contain additional
third-party packages with their own notices. Refer to each upstream image and
the generated ScopeHarbor image SBOMs for that complete package inventory.

## Application base images

ScopeHarbor builds from digest-pinned Docker Official Images for
[Python](https://hub.docker.com/_/python),
[Node.js](https://hub.docker.com/_/node), and
[Go](https://hub.docker.com/_/golang). The language runtimes, Debian or Alpine
base system, and installed operating-system packages retain their respective
licenses. The resulting image inventory is recorded in the generated SBOMs.

## Direct backend dependencies

The authoritative versions are in `backend/requirements.in` and the
hash-locked requirement files. License expressions below come from the package
metadata for the versions locked by ScopeHarbor 1.1.0.

| Package | License expression |
| --- | --- |
| Alembic | MIT |
| cryptography | Apache-2.0 OR BSD-3-Clause |
| FastAPI | MIT |
| greenlet | MIT AND PSF-2.0 |
| HTTPX | BSD-3-Clause |
| PyJWT | MIT |
| Psycopg | LGPL-3.0-only |
| pydantic-settings | MIT |
| PyYAML | MIT |
| SQLAlchemy | MIT |
| Uvicorn | BSD-3-Clause |

## Direct frontend dependencies

The authoritative versions are in `frontend/package.json` and
`frontend/package-lock.json`.

| Package | License |
| --- | --- |
| Next.js | MIT |
| React and React DOM | MIT |
| three.js | MIT |

Development-only Python and npm dependencies also retain their own licenses and
are captured by the lockfiles and dependency inventories.

## Product assets

ScopeHarbor's repository images, social-preview artwork, and synthetic-data
screenshots were created for this project and are covered by ScopeHarbor's MIT
License. The interface uses system font stacks and project-authored SVG marks;
no third-party font files, icon packs, stock images, or production data are
redistributed in the repository.

## Transitive inventory

The lockfiles are the source of truth for installed transitive application
packages. CI also generates CycloneDX JSON SBOMs for the API, worker, relay, and
frontend images and uploads them as short-retention workflow artifacts. An SBOM
is a package inventory, not a legal compatibility determination; consult the
license text included with the relevant package before redistributing a
modified image or dependency.
