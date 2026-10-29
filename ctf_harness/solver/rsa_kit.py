"""Pure-python RSA attack kit (stdlib only) powering L1 recipes.

Implements the classics seen in real competitions:

* small public exponent (e=3/5) short-message cube-root (Hastad-style),
* Wiener attack via continued fractions of e/n (small private exponent),
* Fermat factorisation (p and q close),
* common factor between two moduli,
* small prime factors (toy keys),
* DER/PEM parsing of ``PUBLIC KEY`` (SPKI) and ``RSA PUBLIC KEY`` (PKCS#1).
"""

from __future__ import annotations

import base64
import re
from math import gcd, isqrt

_SMALL_PRIMES_LIMIT = 100_000


# --------------------------------------------------------------------------- #
# integer roots
# --------------------------------------------------------------------------- #
def iroot(n: int, k: int) -> tuple[int, bool]:
    """Floor k-th root via Newton; returns (root, exact?)."""
    if n < 0:
        raise ValueError("negative")
    if n == 0:
        return 0, True
    if k == 1:
        return n, True
    x = 1 << ((n.bit_length() + k - 1) // k)
    while True:
        y = ((k - 1) * x + n // (x ** (k - 1))) // k
        if y >= x:
            break
        x = y
    return x, x ** k == n


def cube_root(n: int) -> int:
    return iroot(n, 3)[0]


# --------------------------------------------------------------------------- #
# factoring attacks
# --------------------------------------------------------------------------- #
def small_factor(n: int, limit: int = _SMALL_PRIMES_LIMIT) -> int | None:
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3
    candidate, step = 5, 2
    while candidate <= limit and candidate * candidate <= n:
        if n % candidate == 0:
            return candidate
        candidate += step
        step = 6 - step
    return None


def fermat_factor(n: int, max_iterations: int = 100_000) -> tuple[int, int] | None:
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iterations):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2 and a - b > 1 and a + b < n:
            return a - b, a + b
        a += 1
    return None


def common_factor(n1: int, n2: int) -> int | None:
    factor = gcd(n1, n2)
    return factor if 1 < factor < min(n1, n2) else None


def wiener(e: int, n: int) -> int | None:
    """Recover a small private exponent d from (e, n)."""
    def continued_fraction(a: int, b: int):
        while b:
            yield a // b
            a, b = b, a % b

    # convergent recurrences: h_{-2}=0, h_{-1}=1 ; k_{-2}=1, k_{-1}=0
    num_prev, num_cur = 0, 1
    den_prev, den_cur = 1, 0
    for a in continued_fraction(e, n):
        num_next = a * num_cur + num_prev
        den_next = a * den_cur + den_prev
        num_prev, num_cur = num_cur, num_next
        den_prev, den_cur = den_cur, den_next
        if num_cur == 0 or den_cur == 0:
            continue
        k, d = num_cur, den_cur
        if k == 0 or (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1          # p + q
        disc = s * s - 4 * n
        if disc < 0:
            continue
        r = isqrt(disc)
        if r * r == disc and (s + r) % 2 == 0:
            p = (s + r) // 2
            q = (s - r) // 2
            if p > 1 and q > 1 and p * q == n:
                return d
    return None


# --------------------------------------------------------------------------- #
# key material parsing
# --------------------------------------------------------------------------- #
def _der_read(buf: bytes, pos: int) -> tuple[int, bytes, int]:
    tag = buf[pos]
    pos += 1
    length = buf[pos]
    pos += 1
    if length & 0x80:
        nbytes = length & 0x7F
        length = int.from_bytes(buf[pos:pos + nbytes], "big")
        pos += nbytes
    return tag, buf[pos:pos + length], pos + length


def _der_ints(buf: bytes) -> list[int]:
    out: list[int] = []

    def walk(blob: bytes) -> None:
        pos = 0
        while pos < len(blob):
            tag, value, pos = _der_read(blob, pos)
            if tag == 0x02:                      # INTEGER
                out.append(int.from_bytes(value, "big"))
            elif tag in (0x30, 0x31):            # SEQUENCE / SET
                walk(value)
            elif tag == 0x03:                    # BIT STRING
                walk(value[1:] if value else value)

    try:
        walk(buf)
    except Exception:  # noqa: BLE001 - malformed DER must not crash recipes
        pass
    return out


def parse_pem(data: str) -> list[int]:
    match = re.search(
        r"-----BEGIN [A-Z ]*PUBLIC KEY[A-Z ]*-----(.*?)-----END [A-Z ]*PUBLIC KEY[A-Z ]*-----",
        data, re.DOTALL)
    if not match:
        return []
    body = re.sub(r"\s+", "", match.group(1))
    try:
        return _der_ints(base64.b64decode(body))
    except Exception:  # noqa: BLE001
        return []


def parse_rsa_material(text: str) -> dict[str, list[int]]:
    """Extract n/e/c(/d/p/q) from free text: labeled ints, bare big ints, PEM."""
    material: dict[str, list[int]] = {"n": [], "e": [], "c": [], "d": [], "p": [], "q": []}
    alias = {
        "n": "n", "modulus": "n", "mod": "n", "nn": "n",
        "e": "e", "exp": "e", "exponent": "e", "pub": "e", "ee": "e",
        "c": "c", "ct": "c", "ciphertext": "c", "enc": "c", "m_enc": "c", "cc": "c",
        "d": "d", "priv": "d", "p": "p", "q": "q",
    }
    for match in re.finditer(
            r"(?i)\b([a-z_][a-z_0-9]{0,15})\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)", text):
        name = match.group(1).lower()
        if name not in alias:
            continue
        value = match.group(2)
        number = int(value, 16) if value.lower().startswith("0x") else int(value)
        if number > 0:
            material[alias[name]].append(number)

    pem_ints = parse_pem(text)
    if pem_ints:
        material["n"].append(pem_ints[0])
        if len(pem_ints) > 1:
            material["e"].append(pem_ints[1])

    if not material["n"]:
        # unlabeled big ints: largest is n, tiny/familiar ones are e, rest are c
        bigs = sorted(
            {int(m) for m in re.findall(r"\b(\d{20,})\b", text)} |
            {int(m, 16) for m in re.findall(r"\b0x([0-9a-fA-F]{16,})\b", text)},
            reverse=True)
        if bigs:
            material["n"].append(bigs[0])
            for value in bigs[1:]:
                if value in (3, 5, 7, 17, 65537) and not material["e"]:
                    material["e"].append(value)
                else:
                    material["c"].append(value)
    if not material["e"]:
        material["e"].append(65537)
    return material


def _int_to_text(number: int) -> str:
    raw = number.to_bytes((number.bit_length() + 7) // 8 or 1, "big")
    return raw.decode("latin-1")


def _modinv(e: int, m: int) -> int | None:
    try:
        return pow(e, -1, m)
    except ValueError:
        return None


def attack(material: dict[str, list[int]]) -> list[tuple[str, str]]:
    """Run every applicable attack; returns [(technique, recovered_text)]."""
    results: list[tuple[str, str]] = []
    n = material.get("n") or [None]
    e = (material.get("e") or [65537])[0]
    cs = material.get("c") or []
    ds = material.get("d") or []
    factors = [(p, q) for p in material.get("p", []) for q in material.get("q", [])
               if p * q == (material.get("n") or [0])[0]]

    private_d: set[int] = set(ds)
    for n_value in n:
        if not n_value:
            continue
        # 1. known factors
        for p, q in factors:
            d = _modinv(e, (p - 1) * (q - 1))
            if d:
                private_d.add(d)
        # 2. small factors
        f = small_factor(n_value)
        if f:
            d = _modinv(e, (f - 1) * (n_value // f - 1))
            if d:
                private_d.add(d)
        # 3. Fermat
        pair = fermat_factor(n_value)
        if pair:
            p, q = pair
            d = _modinv(e, (p - 1) * (q - 1))
            if d:
                private_d.add(d)
        # 4. Wiener
        w = wiener(e, n_value)
        if w:
            private_d.add(w)
        # 5. common factor across all moduli
        for other in n:
            if other and other != n_value:
                shared = common_factor(n_value, other)
                if shared:
                    d = _modinv(e, (shared - 1) * (n_value // shared - 1))
                    if d:
                        private_d.add(d)

    seen: set[str] = set()
    for d in private_d:
        for n_value in n:
            if not n_value:
                continue
            for c in cs or [0]:
                if not c:
                    continue
                text = _int_to_text(pow(c, d, n_value))
                if text not in seen:
                    seen.add(text)
                    results.append(("known-private-key", text))
    # 6. small e short message (no padding, m^e < n)
    if e in (3, 5, 7) and n[0]:
        for c in cs:
            root, exact = iroot(c, e)
            if exact and root and root ** e == c:
                text = _int_to_text(root)
                if text not in seen:
                    seen.add(text)
                    results.append((f"small-e cube-root (e={e})", text))
    return results
