"""Version comparison and npm range checks (enough for root-cause tracing).

Not a full semver implementation: pre-release tags are ordered below the
release and otherwise compared as text. Anything we cannot parse returns None
("unknown"), and callers report that instead of guessing.
"""

from __future__ import annotations

import re
from functools import total_ordering


@total_ordering
class V:
    __slots__ = ("raw", "nums", "pre")

    def __init__(self, raw: str):
        self.raw = raw
        s = raw.strip().lstrip("vV=")
        s = s.split("+", 1)[0]
        main, _, pre = s.partition("-")
        # PyPI style 1.0rc1 / 1.0.post1
        m = re.match(r"^([0-9][0-9.]*)(.*)$", main)
        if m and not pre and m.group(2):
            main, pre = m.group(1).rstrip("."), m.group(2).lstrip(".")
        self.nums = tuple(int(x) for x in re.findall(r"\d+", main)[:6]) or (0,)
        self.pre = pre

    def _key(self):
        nums = self.nums + (0,) * (6 - len(self.nums))
        post = self.pre.startswith("post")
        return (nums, 2 if post else (0 if self.pre else 1), self.pre)

    def __eq__(self, other):
        return self._key() == other._key()

    def __lt__(self, other):
        return self._key() < other._key()

    def __repr__(self):
        return f"V({self.raw})"


def vkey(v: str) -> V:
    return V(v)


# ------------------------------------------------------------------ npm ranges

_PART = r"(?:\d+|[xX*])"
_VER = rf"v?(?P<maj>{_PART})(?:\.(?P<min>{_PART}))?(?:\.(?P<pat>{_PART}))?(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?"


def _xparts(s: str):
    m = re.fullmatch(_VER, s.strip())
    if not m:
        return None
    vals = []
    for k in ("maj", "min", "pat"):
        g = m.group(k)
        vals.append(None if g is None or g in "xX*" else int(g))
    return vals, m.group("pre")


def _cmp_set(token: str):
    """One comparator token -> list of (op, V). Returns None if unparsable."""
    token = token.strip()
    if token in ("", "*", "x", "X", "latest"):
        return []
    m = re.fullmatch(r"(\^|~>?|>=|<=|>|<|=)?\s*(.+)", token)
    if not m:
        return None
    op, rest = m.group(1) or "", m.group(2)
    p = _xparts(rest)
    if not p:
        return None
    (maj, mn, pat), pre = p
    def ver(a, b, c, pr=None):
        return V(f"{a}.{b}.{c}" + (f"-{pr}" if pr else ""))
    if maj is None:
        return []
    if op == "^":
        lo = ver(maj, mn or 0, pat or 0, pre)
        if maj > 0 or mn is None:
            hi = ver(maj + 1, 0, 0, "0")
        elif mn > 0 or pat is None:
            hi = ver(0, mn + 1, 0, "0")
        else:
            hi = ver(0, 0, pat + 1, "0")
        return [(">=", lo), ("<", hi)]
    if op.startswith("~"):
        lo = ver(maj, mn or 0, pat or 0, pre)
        hi = ver(maj + 1, 0, 0, "0") if mn is None else ver(maj, mn + 1, 0, "0")
        return [(">=", lo), ("<", hi)]
    if op in ("", "="):
        if mn is None:
            return [(">=", ver(maj, 0, 0)), ("<", ver(maj + 1, 0, 0, "0"))]
        if pat is None:
            return [(">=", ver(maj, mn, 0)), ("<", ver(maj, mn + 1, 0, "0"))]
        return [("=", ver(maj, mn, pat, pre))]
    # >, >=, <, <= with partials
    if op in (">", "<="):
        if mn is None:
            base = ver(maj + 1, 0, 0, "0")
            return [(">=", base)] if op == ">" else [("<", base)]
        if pat is None:
            base = ver(maj, mn + 1, 0, "0")
            return [(">=", base)] if op == ">" else [("<", base)]
    return [(op, ver(maj, mn or 0, pat or 0, pre))]


def npm_satisfies(version: str, rng: str) -> bool | None:
    """Does `version` satisfy npm range `rng`? None when the range is not a semver range."""
    if rng is None:
        return None
    rng = rng.strip()
    if rng.startswith("npm:"):                      # alias: npm:pkg@^1.2
        rng = rng.rsplit("@", 1)[-1] if "@" in rng[4:] else "*"
    if re.match(r"^(git|github:|file:|link:|http|workspace:|[\w.-]+/[\w.-]+)", rng) and not re.match(r"^\d", rng):
        return None
    v = V(version)
    for alt in rng.split("||"):
        alt = alt.strip()
        if " - " in alt:
            a, b = alt.split(" - ", 1)
            pa, pb = _xparts(a), _xparts(b)
            if not pa or not pb:
                return None
            comps = (_cmp_set(f">={a.strip()}") or []) + (_cmp_set(f"<={b.strip()}") or [])
        else:
            tokens = re.findall(r"(?:\^|~>?|>=|<=|>|<|=)?\s*[^\s]+", alt) if alt else []
            comps = []
            for t in tokens:
                c = _cmp_set(t)
                if c is None:
                    return None
                comps += c
        ok = True
        for op, b in comps:
            if op == "=" and not v == b: ok = False
            elif op == ">=" and v < b: ok = False
            elif op == ">" and not b < v: ok = False
            elif op == "<" and not v < b: ok = False
            elif op == "<=" and b < v: ok = False
        if ok:
            return True
    return False


def cmp(a: str, b: str) -> int:
    """-1 / 0 / 1 comparison of two version strings (any ecosystem, best effort)."""
    va, vb = V(str(a)), V(str(b))
    return -1 if va < vb else (1 if vb < va else 0)


def satisfies(eco: str, version: str | None, spec: str | None) -> bool | None:
    """Does `version` satisfy the declared `spec`? None = unknown (no spec, or not checkable)."""
    if not version or spec is None or str(spec).strip() == "":
        return None
    spec = str(spec).strip()
    if eco == "npm":
        return npm_satisfies(version, spec)
    if eco == "pypi":
        # PEP 440 subset: ==, !=, >=, <=, >, <, ~= joined by commas
        ok = True
        for part in [p.strip() for p in spec.split(",") if p.strip()]:
            m = re.match(r"^(===|==|!=|~=|>=|<=|>|<)\s*([^\s;]+)$", part)
            if not m:
                return None
            op, ver = m.groups()
            if ver.endswith(".*"):
                if op not in ("==", "!="):
                    return None
                pre = ver[:-2]
                hit = str(version) == pre or str(version).startswith(pre + ".")
                ok &= hit if op == "==" else not hit
                continue
            c = cmp(version, ver)
            if op in ("==", "==="): ok &= c == 0
            elif op == "!=": ok &= c != 0
            elif op == ">=": ok &= c >= 0
            elif op == "<=": ok &= c <= 0
            elif op == ">": ok &= c > 0
            elif op == "<": ok &= c < 0
            elif op == "~=":
                nums = V(ver).nums
                upper = ".".join(str(n) for n in nums[:-2] + (nums[-2] + 1,)) if len(nums) >= 2 else None
                ok &= c >= 0 and (upper is None or cmp(version, upper) < 0)
        return ok
    if eco == "golang":
        return None   # Go uses minimal version selection: go.mod requires are minimums
    if eco == "maven":
        s = spec.strip()
        if s and s[0] in "[(":   # Maven range like [1.0,2.0)
            m = re.match(r"^([\[(])\s*([^,]*)\s*,\s*([^\])]*)\s*([\])])$", s)
            if not m:
                return None
            lo_inc, lo, hi, hi_inc = m.group(1) == "[", m.group(2), m.group(3), m.group(4) == "]"
            if lo and (cmp(version, lo) < 0 or (cmp(version, lo) == 0 and not lo_inc)):
                return False
            if hi and (cmp(version, hi) > 0 or (cmp(version, hi) == 0 and not hi_inc)):
                return False
            return True
        return None   # a plain Maven version is a soft requirement (nearest wins)
    return None
