# Local Mail E2E Env Keys

Use this file only for local/dev bootstrap of wallet mail connector state:

- File name: `.env.mail-e2e.local`
- Git status: ignored (`.gitignore`)
- Purpose: CLI bootstrap source for `store_secret_record@v1` + `mail_connector_upsert@v1`
- Production: do not use `.env` bootstrap; inject/store secrets via wallet secret APIs and alias references only.

## CLI Bootstrap

Run from repo root:

```bash
cargo run -p ioi-cli --bin cli -- dev --rpc 127.0.0.1:9000 bootstrap-mail --env-file .env.mail-e2e.local
```

- This command stores aliases as vault secret records, then upserts the mail connector.
- Desktop Integrations UI should use manual connector details and execution flow; it does not read `.env.mail-e2e.local`.

## Required Keys

```bash
MAIL_E2E_ACCOUNT_EMAIL=
MAIL_E2E_IMAP_HOST=
MAIL_E2E_IMAP_PORT=
MAIL_E2E_SMTP_HOST=
MAIL_E2E_SMTP_PORT=
MAIL_E2E_IMAP_USERNAME=
MAIL_E2E_SMTP_USERNAME=
```

### Required Credential Keys By Auth Mode

`MAIL_E2E_AUTH_MODE` defaults to `password` if unset.

For `MAIL_E2E_AUTH_MODE=password` (default):

```bash
MAIL_E2E_IMAP_PASSWORD=
MAIL_E2E_SMTP_PASSWORD=
```

For `MAIL_E2E_AUTH_MODE=oauth2`:

```bash
MAIL_E2E_IMAP_BEARER_TOKEN=
MAIL_E2E_SMTP_BEARER_TOKEN=
```

## Optional Keys

```bash
# Auth mode: password | oauth2
# If unset, CLI infers oauth2 only when bearer-token keys exist and password keys are absent.
MAIL_E2E_AUTH_MODE=

# Defaults to "primary"
MAIL_E2E_MAILBOX=

# TLS mode values: plaintext | starttls | tls
# Defaults: IMAP=tls, SMTP=starttls
MAIL_E2E_IMAP_TLS_MODE=
MAIL_E2E_SMTP_TLS_MODE=

# Alias defaults
MAIL_E2E_IMAP_USERNAME_ALIAS=mail.imap.username
MAIL_E2E_SMTP_USERNAME_ALIAS=mail.smtp.username

# Password mode alias defaults
MAIL_E2E_IMAP_PASSWORD_ALIAS=mail.imap.password
MAIL_E2E_SMTP_PASSWORD_ALIAS=mail.smtp.password

# OAuth2 mode alias defaults
MAIL_E2E_IMAP_BEARER_TOKEN_ALIAS=mail.imap.bearer_token
MAIL_E2E_SMTP_BEARER_TOKEN_ALIAS=mail.smtp.bearer_token

# Secret ID defaults
MAIL_E2E_IMAP_USERNAME_SECRET_ID=mail-imap-username
MAIL_E2E_SMTP_USERNAME_SECRET_ID=mail-smtp-username

# Password mode secret ID defaults
MAIL_E2E_IMAP_PASSWORD_SECRET_ID=mail-imap-password
MAIL_E2E_SMTP_PASSWORD_SECRET_ID=mail-smtp-password

# OAuth2 mode secret ID defaults
MAIL_E2E_IMAP_BEARER_TOKEN_SECRET_ID=mail-imap-bearer-token
MAIL_E2E_SMTP_BEARER_TOKEN_SECRET_ID=mail-smtp-bearer-token
```

## Notes

- Quote values if they contain spaces, `#`, or special characters.
- Do not place raw secret values in connector metadata fields.
- Alias constraints are enforced in wallet service (lowercase, bounded length, safe charset).
- `password` mode is default for manual username/password setups.
- Some providers reject account passwords for IMAP/SMTP and require app passwords or OAuth2.
