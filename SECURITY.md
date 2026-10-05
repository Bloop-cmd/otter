# Otti security baseline

Sessions are represented in the browser only by an opaque `__Host-otti_session` cookie. The session record remains server-side. Production sets Secure cookies over HTTPS, with HttpOnly and SameSite policy. WebSocket joins derive identity from that session and check conversation membership server-side.

The current implementation uses in-memory session/user/membership storage for development. It is not a production persistence layer yet.
