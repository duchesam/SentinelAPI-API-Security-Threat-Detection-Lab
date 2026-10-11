# SentinelAPI — API Threat Detection & Cloud Security Lab

Built by Ermias Seyoum. An educational, reproducible security engineering project with real local enforcement and a read-only hosted evidence viewer.

## Quick start (Python 3.12+)

```bash
bash scripts/run_lab.sh
```

Open http://127.0.0.1:8000/docs. In another terminal:

```bash
.venv/bin/python scripts/init_lab.py --tokens
```

Use Alice's short-lived token to read `pay-a-001`. Reading `pay-b-001` returns 404. Three denied requests create an ACCESS-001 incident. Use the analyst token for `/incidents` and `/events`. Admin tokens are explicitly authorized for global incident review. The generated private key is local lab material in `.state/`, excluded from source and downloads.

```bash
PYTHONPATH=backend .venv/bin/pytest backend/tests -q
node --test tests/web.test.mjs
PYTHONPATH=backend .venv/bin/python scripts/export_replay.py
```

## Docker profile (supplied; not executed in the build environment)

```bash
docker compose up --build
# Generate tokens inside the same container whose public key verifies them:
docker compose exec api python scripts/init_lab.py --tokens
```

API: http://127.0.0.1:8000/docs. Nginx gateway: http://127.0.0.1:8081. PostgreSQL and Redis have no host ports. API uses PostgreSQL and Redis in this profile. Local Python uses SQLite and an in-process limiter. The Compose credentials are synthetic lab-only defaults. Keep this profile on localhost; it has no production TLS or deployment hardening claim.

## Optional Keycloak profile (supplied; not integration-tested)

`docker compose --profile oidc up --build` adds a local realm at http://127.0.0.1:8082. The imported realm provides alice, bob, and analyst users with a synthetic password found in `infra/sentinel-realm.json`. Direct grants are enabled only to simplify this isolated lab; production clients should use an appropriate modern OAuth flow.

For a locally running Python API, set `JWT_ISSUER=http://localhost:8082/realms/sentinel` and `JWKS_URL=http://localhost:8082/realms/sentinel/protocol/openid-connect/certs`. Audience is `sentinel-api`. The issuer must match the actual token issuer exactly. When using Docker, the JWKS URL can be the container-reachable `http://keycloak:8080/realms/sentinel/protocol/openid-connect/certs`; keep issuer validation aligned with the issuer used to obtain the token. There is no dynamic, user-supplied JWKS URL.

## Repository map

- `backend/sentinel/app.py`: verified tokens, scope checks, limiter, audit storage, detection, incident APIs.
- `backend/tests/`: security regression tests.
- `backend/sentinel/posture.py`: exported configuration evaluation and graph traversal.
- `dist/`: buildless responsive evidence dashboard.
- `scripts/export_replay.py`: actual local request/response recording.
- `docs/`: threat model, coverage, reports, case study, and portfolio material.
- `infra/`: gateway, optional identity realm, and private GCS Terraform example.
- `apigee/`: optional JWT / SpikeArrest policy examples.
- `.github/workflows/security.yml`: regression, static, dependency, secret, and container jobs.

## Verification and limitations

Read `docs/project-guide.md` for the complete control matrix and limitations. Recorded metrics are small local samples, not enterprise performance measurements. The hosted page is a static viewer and does not operate a live SOC. Container services, Keycloak, Apigee, Terraform, and CI execution require separate environment validation. mTLS, Kubernetes, live telemetry, and an LLM-backed assistant are future work. The evidence brief is deterministic and uses only referenced event fields.

No Google, Meta, FBI, or other company endorsement is claimed. No external scanning, real payment data, or automatic remediation is provided.

## View the dashboard locally

```bash
python3 scripts/package_source.py
python3 -m http.server 8080 --directory dist
```

Open http://127.0.0.1:8080. The dashboard shows recorded local evidence and never sends security scenarios to a live service.
