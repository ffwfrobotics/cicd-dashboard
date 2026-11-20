# cicd-dashboard

FastAPI + Jinja + htmx, no build step. The owner's dashboard for apps on cicd-ref-arch; it stores nothing and reads the forge and the state repo.

- **Before changing a page, a label or a message:** read `docs/design.md` and follow it. Short keywords, explanation on hover, one status vocabulary, no intro paragraphs.
- **Colours and fonts** go in `dashboard/static/theme.css` only. Never put a literal colour in `app.css` or a template.
- **Icons** come from `dashboard/static/icons.svg` through the `icon()` macro. No emoji or text glyphs.
- **Tests** (`python3 -m unittest discover -s tests`) assert states and fields, never wording.
- **Branches:** `main` deploys to dev (`dashboard-dev.c-local.k.ffwf.net`). Prod is a promotion a second person approves.
- **Run locally:** see README, "Run it locally". Branding and theming: README, "Appearance and branding".
