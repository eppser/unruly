"""A deliberately small YAML reader for the corpus answer keys.

Why this exists rather than PyYAML: the machine this corpus was built on has no
`yaml` module and no `pip install` in the verification path, and a benchmark
whose honesty check cannot run without a network fetch is a benchmark whose
honesty check does not run.

The subset is:

  key: scalar            scalars are int, float, true/false, null, or string
  key:                   nested block mapping (2-space indent)
  key: [a, b, c]         inline flow sequence of scalars
  - scalar               block sequence of scalars
  - key: v               block sequence of mappings; further keys indent to
    key2: v              the same column as the first
  key: >                 folded block scalar
  key: |                 literal block scalar
  # comment              full-line, and trailing when preceded by a space and
                         not inside quotes

Anything outside that subset raises. That is the point: a parser that silently
skips what it does not understand turns a typo in an answer key into a check
that quietly stops running, which is the exact failure this corpus exists to
avoid. Loud and narrow beats permissive.
"""
from __future__ import annotations


class YamliteError(ValueError):
    pass


def _strip_comment(line: str) -> str:
    out = []
    quote = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == quote:
                quote = None
            out.append(ch)
        elif ch in "'\"":
            quote = ch
            out.append(ch)
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        else:
            out.append(ch)
        i += 1
    return "".join(out).rstrip()


def _scalar(raw: str):
    raw = raw.strip()
    if raw == "":
        return None
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
        return raw[1:-1]
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        if not inner:
            return []
        return [_scalar(p) for p in _split_flow(inner)]
    low = raw.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~"):
        return None
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    return raw


def _split_flow(inner: str) -> list[str]:
    parts, buf, quote = [], [], None
    for ch in inner:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch == ",":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return [p for p in (p.strip() for p in parts) if p != ""]


class _Reader:
    def __init__(self, text: str):
        self.lines: list[tuple[int, str, int]] = []  # indent, content, lineno
        for n, raw in enumerate(text.splitlines(), start=1):
            stripped = _strip_comment(raw)
            if stripped.strip() == "":
                continue
            if stripped.lstrip().startswith("---"):
                continue
            indent = len(stripped) - len(stripped.lstrip(" "))
            self.lines.append((indent, stripped.strip(), n))
        self.i = 0
        self.raw_lines = text.splitlines()

    def peek(self):
        return self.lines[self.i] if self.i < len(self.lines) else None

    def block_scalar(self, style: str, min_indent: int, after_lineno: int) -> str:
        """Block scalars are read from the RAW lines: their content is data, so
        comment stripping and indentation normalisation must not touch it."""
        out, indent = [], None
        n = after_lineno  # 1-based index of the `key: >` line
        while n < len(self.raw_lines):
            raw = self.raw_lines[n]
            if raw.strip() == "":
                out.append("")
                n += 1
                continue
            cur = len(raw) - len(raw.lstrip(" "))
            if cur <= min_indent:
                break
            if indent is None:
                indent = cur
            out.append(raw[indent:])
            n += 1
        # Drop the consumed lines from the token stream.
        while self.i < len(self.lines) and self.lines[self.i][2] <= n and self.lines[self.i][2] > after_lineno:
            self.i += 1
        while out and out[-1] == "":
            out.pop()
        if style == "|":
            return "\n".join(out) + "\n"
        folded, para = [], []
        for line in out:
            if line == "":
                folded.append(" ".join(para))
                para = []
            else:
                para.append(line.strip())
        if para:
            folded.append(" ".join(para))
        return "\n".join(folded) + "\n"

    def parse_block(self, indent: int):
        head = self.peek()
        if head is None:
            return None
        if head[1].startswith("- "):
            return self.parse_seq(indent)
        return self.parse_map(indent)

    def parse_seq(self, indent: int) -> list:
        items = []
        while True:
            cur = self.peek()
            if cur is None or cur[0] != indent or not cur[1].startswith("- "):
                break
            body = cur[1][2:].strip()
            lineno = cur[2]
            self.i += 1
            if ":" in body and not body.startswith("[") and _looks_like_key(body):
                key, _, rest = body.partition(":")
                item = {}
                self._assign(item, key.strip(), rest, indent + 2, lineno)
                nxt = self.peek()
                if nxt is not None and nxt[0] == indent + 2 and not nxt[1].startswith("- "):
                    item.update(self.parse_map(indent + 2))
                items.append(item)
            else:
                items.append(_scalar(body))
        return items

    def parse_map(self, indent: int) -> dict:
        out: dict = {}
        while True:
            cur = self.peek()
            if cur is None or cur[0] != indent:
                break
            if cur[1].startswith("- "):
                break
            if not _looks_like_key(cur[1]):
                raise YamliteError(f"line {cur[2]}: not a mapping entry: {cur[1]!r}")
            key, _, rest = cur[1].partition(":")
            lineno = cur[2]
            self.i += 1
            self._assign(out, key.strip(), rest, indent, lineno)
        return out

    def _assign(self, out: dict, key: str, rest: str, indent: int, lineno: int):
        rest = rest.strip()
        if rest in (">", "|", ">-", "|-"):
            out[key] = self.block_scalar(rest[0], indent, lineno)
            return
        if rest != "":
            out[key] = _scalar(rest)
            return
        nxt = self.peek()
        if nxt is None or nxt[0] <= indent:
            out[key] = None
            return
        if nxt[1].startswith("- "):
            out[key] = self.parse_seq(nxt[0])
        else:
            out[key] = self.parse_map(nxt[0])


def _looks_like_key(text: str) -> bool:
    quote = None
    for i, ch in enumerate(text):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == ":":
            return i + 1 == len(text) or text[i + 1] in " \t"
    return False


def load(text: str):
    r = _Reader(text)
    value = r.parse_block(0)
    if r.peek() is not None:
        raise YamliteError(f"line {r.peek()[2]}: unparsed trailing content {r.peek()[1]!r}")
    return value


def load_path(path: str):
    with open(path, "r", encoding="utf-8") as fh:
        return load(fh.read())
