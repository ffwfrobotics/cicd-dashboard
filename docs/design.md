# Design language

How the dashboard looks and reads. Follow it when adding or changing a page.

## Principle: show, don't tell

A page shows the data. It doesn't explain itself, justify the design, or restate its own tab label.
- **No intro paragraphs.** If a page needs a paragraph to be understood, change the layout.
- **Explanation goes on hover** (`title`), on the thing it explains: a pill, a column header, a button.
- **Rules are states, not sentences.** "You prepared this package; someone else has to release it" is a `Pending` pill with the hover text "Awaiting a second approver".
- **Don't state what position already shows.** The first incomplete stage needs no "ready to request".
- **Explanation never sits among inputs.** A form is labelled fields, then the action.

## Vocabulary

One word per object, used everywhere, never qualified by who it comes from or goes to.

| Object | Word | Not |
|---|---|---|
| A commit's stages | Pipeline | Road to prod |
| IT Security's findings | Findings | IT Security's findings |
| Release packages | Releases | Releases to IT Security |
| The app's first tab | Overview | |
| 800-53A objectives | Controls (tab), Objectives (table) | |
| Announced vulnerabilities | Advisories | |

- **Headings and tabs:** one or two words. Every app tab keeps the app's name as its `h1`; the tab says where you are.
- **Buttons:** one verb (`Approve`, `Release`, `Prepare`, `Import`). The consequence goes on hover.
- **Stage details:** a keyword or a number (`38/40`, `2 fixed`, `pending`, `live`). The sentence goes in the stage's `tip`.
- **Messages after an action:** what happened, in a few words (`Imported 2 new, 0 known. Re-assessing.`).
- **Empty states:** `None.` or one short line.

## Status

Six states, each with one icon and one colour, everywhere. Use the `icon()` macro; never a text glyph or emoji.

| State | Colour | Used for |
|---|---|---|
| `ok` | `--ok` | done, satisfied, passed, fixed |
| `warn` | `--warn` | warning, pending a person, needs attention |
| `fail` | `--fail` | failed, open, blocks prod |
| `run` | `--warn`, spinning | in progress |
| `todo` | `--muted` | not reached, uncovered |
| `skip` | `--muted` | skipped, risk accepted |

`na` (a dash) is for not applicable. Status is never colour alone: each state has its own shape.

## Components

| Component | Use | Markup |
|---|---|---|
| Pill | a state or a kind, one or two words | `.pill` with `s-<state>` or `.plain` |
| Count badge | a category and its number | `.pill.count` with the number in `<b>` |
| Blocker badge | what would block prod, on the first prod-side stage only | `blockers()` macro |
| Meter | a commit's pipeline in a table row | `meter()` macro |
| Card | one environment or application | `.card` in `.cards` |
| Key/value | a record's fields | `dl.kv` |
| Form | labelled fields, then the action | `form.panel.fields`, each input inside a `<label>` |
| Row action with input | opens its own small form | `details.pop` |
| Legend | icons with their words, once, under the table | `legend()` macro |
| Time | `Nov 20 05:36`, full UTC time on hover | `{{ value | ts }}` |

Highlight only what needs action. In a row of counts, the one that needs attention gets a status colour; the rest stay `.plain`.

## Where things go

- **Header:** brand, top-level navigation, then connection state, theme and the signed-in user together on the right.
- **Footer:** version and commit.
- **Colours, fonts, logo:** only in `static/theme.css`. `static/app.css` and templates use the theme's variables, never a literal colour.

## Code

- **A stage** (`destiny.py`) has `state`, a short `detail`, a longer `tip`, and structured `blockers`. Templates decide how they look.
- **No logic reads display text.** If a rule needs a fact, it gets a field. Tests assert states and fields, never wording.
