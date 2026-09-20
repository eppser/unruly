# 06 — the target cannot be scanned

## What this target is for

**The one property it measures that no other project does: "unreachable" must
be reported as UNMEASURED, and must never be reported as clean.**

Project 05 is an empty list because there is nothing there. This project is an
empty list because nothing was asked. The two are indistinguishable in a report
that only carries findings, and the difference is the whole value of the
report: one says "this project is safe", the other says "I never spoke to it".
A scanner that collapses a connection error into "no findings" hands an
operator a clean bill of health for a host it never reached.

There is no database here, no PostgREST, no relation. The entire measurement is
what the transport does.

## The three modes, as measured on the wire

| port | configuration | HTTP status | what the client saw |
|---|---|---|---|
| 54451 | nothing bound | **none** (`0`) | `URLError: [Errno 61] Connection refused` |
| 54452 | nginx `return 444;` | **none** (`0`) | `RemoteDisconnected: Remote end closed connection without response` |
| 54453 | nginx → dead upstream | **502** | `text/html`, `Server: nginx/1.31.3`, nginx's own 502 page |
| `*.invalid` | RFC 2606 reserved name | **none** (`0`) | `URLError: [Errno 8] nodename nor servname provided, or not known` |

Errno numbers are macOS; on glibc the refusal is errno 111 and the resolver
failure is `[Errno -2] Name or service not known`. The *text* "Connection
refused" and "Remote end closed connection without response" is portable, and
that is what the answer key asserts. The resolver string is not, so the DNS
check asserts only the status and the two negatives that separate it from the
other modes.

### 54451 — nothing listening

No service is declared for this port in `docker-compose.yml`. `connect()` gets
`ECONNREFUSED` and no bytes are ever exchanged. This is the honest failure:
almost any client surfaces it as an error.

### 54452 — accepts, then drops

nginx's non-standard `return 444;` closes the connection without sending a
status line. **The TCP handshake succeeds.** A direct socket test during
development confirmed it: `connect()` returns, `sendall()` of a full request
line succeeds, and `recv()` returns `b''`.

This is the mode that defeats a liveness gate. "Can I open a socket to this
host?" answers *yes*. Every subsequent probe then returns nothing, and whatever
the scanner does with an empty answer, it does thirty times in a row and
reports as a finished scan.

The answer key pins this down as a *negative*: 54452 must NOT produce
`Connection refused`. That is the only observable that separates "the handshake
completed and then nothing came back" from "there was no handshake".

### 54453 — answers, but not with a backend

nginx proxies to `127.0.0.1:9` inside its own container, where nothing is
bound, so every request fails to connect upstream and nginx synthesises a 502.
The host is fully reachable and completely uninformative: `text/html`, no JSON,
no PostgREST error code, no schema document. `GET /` and
`GET /rest/v1/users` return byte-identical pages, so the path carries no
information; `POST` returns the same. Nothing about the API behind this gateway
can be measured, and the 502 is emphatically **not** a 404 — reading it as
"relation absent" is the mode-3 version of calling an unreachable host clean.

## What a correct scanner must NOT report

- No relations, no "clean", no zero-findings verdict for any of the three
  ports. Every one of them is unmeasured.
- Not `PGRST205`, not "table does not exist", for anything on 54453. A 502 is
  the gateway talking about itself.

## The thing that surprised us

**The drop case does not arrive as a `URLError`.** `urllib` documents
`URLError` as the wrapper for transport failures, and modes 1 and 4 do arrive
that way. Mode 2 does not: `http.client.RemoteDisconnected` propagates out of
`urlopen` uncaught, and `lib/check.py` only catches it because it has a
trailing `except Exception` after the `URLError` clause:

```python
except urllib.error.URLError as e:
    return 0, {}, f"URLError: {e.reason}"
except Exception as e:          # socket timeouts, resets
    return 0, {}, f"{type(e).__name__}: {e}"
```

Take that last clause away and the client raises. So of the three modes, the
one deliberately built to look alive to a naive liveness check is also the one
most likely to crash a client whose error handling was written from the
`urllib` documentation. Both failure paths converge on the same port, which was
not the intent when the port was configured.

A second, smaller one, found while building mode 3: **nginx resolves upstream
hostnames at configuration-load time.** `proxy_pass http://nosuchhost:3000;`
does not model a dead backend —

```
nginx: [emerg] host not found in upstream "nosuchhost-unruly" in /etc/nginx/conf.d/default.conf:3
nginx: configuration file /etc/nginx/nginx.conf test failed
```

— the container refuses to start, and the port then presents as *mode 1*. The
obvious way to write this fixture silently collapses the two modes it exists to
separate. Hence the literal `127.0.0.1:9`, which nginx accepts at load and
fails to reach at request time.

## Running it

```sh
cd benchmark/corpus/06-unreachable && docker compose up -d --wait
../verify.sh --no-up 06-unreachable
```

Port 54451 is left undeclared rather than declared-and-stopped, so "nothing
listening" is a property of the compose file rather than of whichever command
was run last.
