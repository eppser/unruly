# @eppser/unruly

Security scanner for browser-facing databases — Supabase, Firebase, Neon,
PocketBase. Point it at a URL and it proves what an anonymous caller can read,
with the rows as evidence.

```bash
npm install -g @eppser/unruly
unruly -u https://your-app.com
```

Exit codes: `0` clean and fully measured · `2` findings at high or above ·
`3` something could not be assessed.

This package downloads the prebuilt binary for your platform from the matching
GitHub release and verifies it against a checksum pinned at publish time. A
mismatch fails the install.

Full documentation: https://github.com/eppser/unruly
