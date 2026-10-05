# Otti Live V2 Security

- Passwords are hashed with bcrypt (12 rounds).
- Authentication uses server-side sessions stored in PostgreSQL.
- Session cookies are HTTP-only, SameSite=Lax, Secure in production.
- OAuth uses state values stored in the server session.
- Google requests `openid email profile` only.
- GitHub requests `read:user user:email`.
- WebSocket connections require a short-lived, one-time token minted from an authenticated session.
- Room membership is checked server-side before loading history or joining realtime rooms.
- Never commit `.env` or OAuth client secrets.
- Set `APP_URL` to the exact public HTTPS origin in production.
