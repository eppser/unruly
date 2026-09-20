# @eppser/unruly

Security scanner for backend-as-a-service databases — Supabase, Firebase,
Neon, PocketBase. Give it a URL: it finds the public key in your own bundle,
proves what that key reaches — with the rows — and names the surfaces it
could not judge.

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
