# `unifit-menu` Directus extension

UNI FIT students photograph or download their KYK dormitory's monthly menu and send it from the
app. This extension reads the files with Claude, hands the student a draft table to correct, and
lets an editor publish the confirmed table into `zest_province_menus`.

A **bundle** with two entries:

| Entry | Type | What it does |
| --- | --- | --- |
| `unifit-menu` | endpoint | Mounted at `/unifit-menu`. Creates submissions, runs the extraction, takes the student's confirmation |
| `unifit-menu-review` | hook | Publishes a submission when an editor sets it to `approved`, and undoes it on `rolled_back` |

## Flow

```
app uploads files (directus_files)
  -> POST /unifit-menu/submissions {file_ids}      row: extracting | limit_reached
       background: Claude reads the files          row: extracted | extract_failed
  -> app polls GET /unifit-menu/submissions/:id, shows the draft, student corrects it
  -> POST /unifit-menu/submissions/:id/confirm     row: pending
editor in Directus sets status = approved          hook: published | publish_failed
editor sets status = rolled_back (optional)        hook: rolled_back
```

## Endpoints

All three need a signed-in user; the id comes from `req.accountability`, never from the body.

| Method | Path | Body | Returns |
| --- | --- | --- | --- |
| POST | `/unifit-menu/submissions` | `{ file_ids: string[] }` (1-5, the caller's own uploads) | `201 { id, status, daily_limit, used_today }` |
| GET | `/unifit-menu/submissions/:id` | - | `{ id, status, province_id, dorm, period_start, period_end, days, confidence, problems }` |
| POST | `/unifit-menu/submissions/:id/confirm` | `{ province_id, dorm, days, notes? }` | `{ id, status: "pending" }` |

`days` is `[{ date: "YYYY-MM-DD", breakfast: string[], dinner: string[] }]`. Errors use Directus's
shape, `errors[0].extensions.code`: `INVALID_FILES`, `INVALID_PROVINCE`, `INVALID_DORM`,
`INVALID_DAYS`, `INVALID_NOTES`, `NOT_FOUND`, `ALREADY_SUBMITTED`.

## Rules worth knowing

- **Files must be the caller's own** (`directus_files.uploaded_by`). Otherwise any signed-in user
  could make the server send someone else's upload to a third party by naming its id.
- **Daily limit**: `UNIFIT_MENU_DAILY_LIMIT` (default 5) extractions per user per Istanbul day.
  Failed extractions do not count; in-flight ones do, so parallel uploads cannot all slip under it.
  Over the limit the row is created as `limit_reached` and the student fills the table by hand.
- **Never auto-published.** The model's output is stored in `extracted` for reference; what gets
  published is `days`, after the student confirmed it and an editor approved it.
- **A late extraction never overwrites a confirmation**: results are written only while the row is
  still `extracting`.
- **Publishing applies to the whole province.** `zest_province_menus` has no dorm column.
- **Duplicates**: an existing (province, date, meal) row is kept unless the editor sets
  `publish_mode = replace` before approving. `publish_log` records every created, replaced and
  skipped row, which is what makes `rolled_back` exact.
- **Calories**: menus do not print a calorie range, so published rows get a default per meal -
  `UNIFIT_MENU_CALORIES_BREAKFAST` / `UNIFIT_MENU_CALORIES_DINNER` as `"min,max"`, defaulting to
  `500,700` and `700,900`.

## Extraction

`claude-opus-5-5` at effort `medium`, streamed, with structured output (`output_config.format`)
and the server-side refusal fallback (`fallbacks: "default"`). PDFs go in as document blocks;
images are fetched as a resized JPEG rendition from Directus (which also converts HEIC when the
server's libvips can decode it); `.xlsx` and `.docx` are unzipped and sent as text, because
the full parsers would not fit in the instance's 1 MiB extension ConfigMap. `extract_meta` keeps
the model, token usage, skipped files and timing for every run.

## Environment

| Variable | Required | Notes |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | yes | Already set on the `general` instance for `suvia` |
| `UNIFIT_MENU_DAILY_LIMIT` | no | Default `5` |
| `UNIFIT_MENU_CALORIES_BREAKFAST` | no | Default `500,700` |
| `UNIFIT_MENU_CALORIES_DINNER` | no | Default `700,900` |

## Schema

The collections are created by `scripts/setup-menu-submissions.ts` in the UNI FIT repository
(dry run by default). `zest_menu_submissions`: `id` (uuid), `status`, `user_created`,
`date_created`, `date_updated`, `province_id` (-> `provinces`), `dorm`, `period_start`,
`period_end`, `days` (json), `extracted` (json), `extract_meta` (json), `notes`, `publish_mode`,
`publish_log` (json), `review_note`, `files` (M2M -> `directus_files` through
`zest_menu_submissions_files`). The app role needs no permission on either collection.

## Development

```bash
npm install
npm test          # bun test
npm run typecheck
npm run build     # dist/api.js + dist/app.js
```
