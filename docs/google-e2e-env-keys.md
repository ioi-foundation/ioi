# Local Google E2E Env Keys

Use this file only for local/dev Google connector smoke tests and live integration runs:

- File name: `.env.google-e2e.local`
- Git status: ignored (`.gitignore`)
- Purpose: process env bootstrap for the Google connector runtime and live tests
- Production: for private installs, prefer the in-app local credential flow over repo-local `.env` files

## Current Env Keys

The Google connector currently reads these environment variables:

```bash
# Required for the native desktop OAuth flow.
GOOGLE_OAUTH_CLIENT_ID=

# Optional for desktop/native clients, but supported when your OAuth client uses one.
GOOGLE_OAUTH_CLIENT_SECRET=

# Optional non-interactive bootstrap for local live tests.
GOOGLE_OAUTH_REFRESH_TOKEN=

# Recommended for BigQuery live tests and default project resolution.
GOOGLE_CLOUD_PROJECT=

# Optional fallback alias if GOOGLE_CLOUD_PROJECT is not set.
GOOGLE_WORKSPACE_PROJECT_ID=

# Optional override for where native OAuth tokens are stored locally.
IOI_GOOGLE_AUTH_PATH=
```

## Notes

- Gmail, Calendar, Docs, Sheets, Drive, Tasks, Chat, and Events use the native Google OAuth flow.
- The connector stores refreshable local auth on disk, and `IOI_GOOGLE_AUTH_PATH` can override that location.
- BigQuery `location` is not read from env today; pass it in the action input when needed.

## Auth Flow

Autopilot now treats private Google access as a local-first setup flow:

1. `Credentials`
   Create a Desktop OAuth client in your own Google Cloud project, then paste the client ID into
   the Google connector and save it locally.
2. `Scope selection`
   Choose which Google capability bundles this local assistant should access before consent.
3. `Consent`
   Finish the native desktop OAuth flow in your browser.
4. `Connected dashboard`
   Autopilot discovers calendars, Gmail labels, task lists, and project defaults after auth.

That keeps the OAuth app identity, consent screen, and stored tokens under the user's control.

## How To Get `GOOGLE_OAUTH_CLIENT_ID`

For local Autopilot development, create an OAuth client in Google Cloud Console:

1. Open Google Cloud Console and select the project you want to use for this test account.
2. Configure the Google Auth branding / consent screen for the project if you have not done that yet.
3. Create an OAuth client credential.
4. Choose `Desktop app` as the application type.
5. Copy the generated Client ID.

Then place it in `.env.google-e2e.local`:

```bash
GOOGLE_OAUTH_CLIENT_ID=your-desktop-client-id.apps.googleusercontent.com
```

Notes:

- `GOOGLE_OAUTH_CLIENT_SECRET` is optional for the current native desktop flow.
- If your OAuth consent screen is in testing mode and the app is external, make sure the Google test account is added as a test user in Google Cloud Console.

## Recommended Local Workflow

Create the local env file at repo root:

```bash
cat > .env.google-e2e.local <<'EOF'
GOOGLE_OAUTH_CLIENT_ID=your-google-oauth-client-id.apps.googleusercontent.com
# Optional if your client requires one:
# GOOGLE_OAUTH_CLIENT_SECRET=your-client-secret
# Optional if you want non-interactive tests after first consent:
# GOOGLE_OAUTH_REFRESH_TOKEN=your-refresh-token
GOOGLE_CLOUD_PROJECT=your-gcp-project-id
EOF
```

Load it into the current shell before running live tests or the desktop app:

```bash
set -a
source ./.env.google-e2e.local
set +a
```

For local Autopilot desktop development, the native Google connector now also tries to read
`.env.google-e2e.local` automatically from the repo when the process env is missing these keys.
Direct `cargo test` runs should still source the file explicitly.

## Example Usage

Run a focused Rust live test or start the desktop app from the same shell session:

```bash
cargo test --manifest-path crates/services/Cargo.toml google_ -- --nocapture
```

```bash
cd apps/autopilot
npm run tauri dev
```

## Verification

You can verify the connector sees auth and project defaults by:

```bash
cat "${IOI_GOOGLE_AUTH_PATH:-$HOME/.config/ioi/google_workspace_oauth.json}" 2>/dev/null || true
echo "$GOOGLE_CLOUD_PROJECT"
```
