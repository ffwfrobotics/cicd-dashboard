# cicd-dashboard

The information system owner's view of their applications on [cicd-ref-arch](https://forge.goblincorps.com/ffwf/cicd-ref-arch): what is deployed where, how each commit is doing on its way to prod, and what evidence covers which security controls.

The plans this follows are in akb (project `kubecon2026shenanigans`, task `cicd-compliance-dashboard`):
- #450, #453 and #456: purpose and data model;
- #451 and #455: OSCAL continuous assessment;
- #452 and #454: tenant self-service.

It is the owner's side. The CSPD app, which runs assessments, is its counterparty. Everything is visible here to the application's developers and sysadmins; what goes to IT Security is a release the owner chooses (planned).

## Step 1 (this version): read-only

| Page | Shows |
|---|---|
| `/` | Tenants and their applications, with what dev and prod run |
| `/a/<app>` | Environments (URLs, commit, security gate), branches with their pipeline, recent commits on the dev branch |
| `/a/<app>/c/<sha>` | One commit's pipeline: Committed › Tests › Build › Security › Deployed › Assessed › Findings › Promotion › Approved › Scheduled › Prod. Findings that would block prod, and who requested and approved a promotion. |
| `/api/...` | The same data as JSON, for agents (`/api/docs`) |

Each stage has one of six states, with the same icon and colour everywhere: done, warning, failed, running, pending, skipped. A finding that is only a warning in dev shows as a badge on the first prod-side stage it would block.

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

## Appearance and branding

| What | How |
|---|---|
| Colours, fonts, corner radius, logo | One file: [`dashboard/static/theme.css`](dashboard/static/theme.css). Each colour is `light-dark(<light>, <dark>)`. To use your own without rebuilding the image, mount a file and set `DASHBOARD_THEME` to its path. |
| Product name | `DASHBOARD_BRAND` (default `cicd-dashboard`) |
| Logo | `--brand-logo` (any CSS image; a `data:` URL keeps it in the one file) and `--brand-logo-width` in the theme |
| Light or dark | Follows the browser; the header button switches between auto, light and dark and remembers it |
| Icons | `dashboard/static/icons.svg`, drawn in the theme's status colours |

Layout is in `dashboard/static/app.css`, which only uses the theme's variables. The design rules for pages and copy are in [docs/design.md](docs/design.md).

### Branding it for your organisation

1. Copy `dashboard/static/theme.css` and change the values. Keep every variable: the layout uses them all.
   ```css
   :root {
     --brand-logo: url("data:image/svg+xml;base64,...");
     --brand-logo-width: 6rem;
     --accent: light-dark(#7a1f5c, #e58cc5);
     --font: "Inter", system-ui, sans-serif;
   }
   ```
2. Either replace the file in your fork, or keep the image as it is and mount yours:
   ```yaml
   # deploy/: a ConfigMap holding your theme.css, mounted read-only
   env:
   - {name: DASHBOARD_BRAND, value: "Acme Delivery"}
   - {name: DASHBOARD_THEME, value: /etc/dashboard/theme.css}
   volumeMounts:
   - {name: theme, mountPath: /etc/dashboard, readOnly: true}
   volumes:
   - {name: theme, configMap: {name: dashboard-theme}}
   ```
3. Check both modes with the header's theme button. Status colours (`--ok`, `--warn`, `--fail`) need to stay readable on `--bg` and `--surface` in each.

The theme is served at `/theme.css` and cached for five minutes.

## Step 2: sign in and act as yourself

**Sign-in.** Sign-in is through the forge's OAuth2 app: authorization code with PKCE S256. The forge itself signs people in through Keycloak (FFwF SSO). Every action is a Forgejo API call with your own token, so the forge records it as you.

**Configuration.** The client comes from Secret `dashboard-oauth`, which exists only in `dashboard-dev` and `dashboard` (prod) and is created by hand, never through git. It holds `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`, `OAUTH_ISSUER` and `SESSION_KEY`. It is mounted as files under `/var/run/secrets/dashboard-oauth` (not environment variables); a local run reads the same names from the environment. The registered redirect URIs are `https://dashboard[-dev].c-local.k.ffwf.net/auth/callback`, so use the https URL. Branch environments have no Secret and stay read-only.

| Action | Who | How |
|---|---|---|
| Request a promotion | write on the app repo | Dispatches the app's own pipeline (`action: request-promotion`). You are recorded as the requester. |
| Pause, resume, remove a branch environment | write on the app repo | Dispatches the app's own pipeline (`action: pause` and so on). The state repo commit names you. |
| Approve, or approve by merging, a promotion | anyone but its requester and the PR's author | A review or merge on the state repo's PR, as you. The dashboard won't offer it to the requester, and says why. |

**Tenant limit.** At most 16 branch environments per tenant are in CI/CD at a time; set in cicd-ref-arch `tenants/_limits.yaml`. A branch over the limit, or a paused one, isn't tested, built or deployed, and the dashboard says why.

**Sessions** live in memory: after the dashboard scales to zero, the next page signs you in again with one redirect and no password.

## Steps 3 to 6: the owner's evidence for IT Security

These read the owner's compliance repo, [`ffwf/cicd-compliance`](https://forge.goblincorps.com/ffwf/cicd-compliance) (`COMPLIANCE_REPO`). It may be private, so it is read **as the signed-in person**: whoever can't see it on the forge doesn't see IT Security's findings here either. Every change is a commit or pull request by that person. The platform side is cicd-ref-arch [docs/oscal.md](https://forge.goblincorps.com/ffwf/cicd-ref-arch/src/branch/master/docs/oscal.md).

| Page | Step | Shows and does |
|---|---|---|
| `/a/<app>/controls` | 3 | Each environment's OSCAL self-assessment, per NIST SP 800-53A objective: satisfied or not, automated or manual, which layer said so, and the evidence on hover. Links to the OSCAL assessment results, SSP and SBOM (`/api/apps/<app>/envs/<env>/<doc>`). The commit page's **Assessed** stage summarises it. |
| `/a/<app>/findings` | 4 | IT Security's findings as tests per environment. **Import** a Tenable CSV (`examples/it-security-scan-demo.csv`); each row gets a check (package, missing header, or manual). **Accept risk** (reason and expiry: a claim for the assessor) or **close**. The commit page's **Findings** stage summarises them. |
| `/advisories` | 5 | Announce a vulnerability (package and affected range), or pick one from OSV, which is asked about the live SBOMs' packages. It shows which live environments the advisory hits; only those are re-scanned. |
| `/a/<app>/releases` | 6 | Prepare a package of chosen environments' records, unaltered with sha256s, as a pull request. **Release** by merging it, as a second person with merge rights (or a named approver: `apps/<app>/app.yaml` `release:`). |

Changes to the compliance repo make the platform re-assess what they affect within minutes, without a rebuild.

