# cicd-dashboard

The information system owner's view of their applications on [cicd-ref-arch](https://forge.goblincorps.com/ffwf/cicd-ref-arch): what is deployed where, how each commit is doing on its road to prod, and (coming) what evidence covers which security controls.

The plans this follows are in akb (project `kubecon2026shenanigans`, task `cicd-compliance-dashboard`):
- #450, #453 and #456: purpose and data model;
- #451 and #455: OSCAL continuous assessment;
- #452 and #454: tenant self-service.

It is the owner's side. The CSPD app, which runs assessments, is its counterparty. Everything is visible here to the application's developers and sysadmins; what goes to IT Security is a release the owner chooses (planned).

## Step 1 (this version): read-only

| Page | Shows |
|---|---|
| `/` | Tenants and their applications, with what dev and prod run |
| `/a/<app>` | Environments (URLs, commit, security gate), branches with their road to prod, recent commits on the dev branch |
| `/a/<app>/c/<sha>` | One commit's road to prod: Committed › Tests › Build › Security › Deployed › Assessed › Review › Promotion PR › Approved › Scheduled › In prod. Findings that would block prod, and who requested and approved a promotion, with the two-person rule in plain words. |
| `/api/...` | The same data as JSON, for agents (`/api/docs`) |

**Glyphs:**

| Glyph | Meaning |
|---|---|
| ✓ | done |
| ⚠ | warning |
| ✗ | failed or blocking |
| ◌ | in progress |
| ○ | not reached |
| ⊘ | skipped |

A finding that is only a warning in dev is shown ahead of time on the prod-side stages.

**Where the data comes from:** pages update themselves over server-sent events when the forge or the state repo changes. The dashboard reads the state repo's archive and Forgejo's API, anonymously for public repos, or with `FORGEJO_TOKEN` (read-only) for private ones. It stores nothing.

## Run it locally

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/uvicorn dashboard.app:app --reload --port 8765
```

| Variable | Default |
|---|---|
| `FORGE_URL` | `https://forge.goblincorps.com` |
| `STATE_REPO` | `ffwf/cicd-ref-arch` |
| `STATE_BRANCH` | `master` |
| `CLUSTER` | `c-local` |
| `FORGEJO_TOKEN` | none |

## Next

- **Step 2:** sign in (Keycloak, or Forgejo as the OAuth provider) and act as the user: request and approve promotions, remove or pause branch environments, and the tenant's 16-branch limit.
- **Step 3:** OSCAL self-assessment per commit.
- **Step 4:** imported findings become failing tests.
- **Step 5:** advisories trigger selective re-scans.
- **Step 6:** release packages for IT Security.

MIT licensed.
