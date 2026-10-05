# Otti Auth V1

Adds account/session foundations to the Otti realtime chat.

## Included
- Email development sign-in (local demo; does not verify email ownership)
- Google OAuth callback flow
- GitHub OAuth callback flow
- Server-side opaque sessions in HttpOnly cookies
- Logout/session expiry
- WebSocket identity derived from the session, not client-supplied user IDs
- Server-side protected conversation membership
- Existing realtime messaging and `〰 DIVE`

## Run
```bash
npm install
npm start
```
Open `http://localhost:3000` and sign in with an email for local testing.

## OAuth callbacks
Google: `/auth/google/callback`
GitHub: `/auth/github/callback`

Set `BASE_URL` and provider credentials in `.env` (never commit secrets).

## Production before public launch
Use a real transactional email provider, PostgreSQL-backed users/sessions/memberships, Redis for horizontal WebSocket fan-out, HTTPS/WSS, CSRF protection as applicable, OAuth redirect allowlisting, account recovery/session revocation, abuse controls, monitoring, backups, and authorization tests.

Session guidance follows OWASP: use server-side sessions with secure cookie attributes; do not store authentication/session tokens in localStorage.
