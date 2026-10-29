"""Crypto playbook: parameter table -> classic attack list -> scripting."""

from __future__ import annotations

import re

from .base import Playbook, _desc_has, _file_heads


class CryptoPlaybook(Playbook):
    id = "crypto"
    title = "Cryptography"

    def matches(self, challenge) -> float:
        if _has_ciphertext_markers(challenge):
            return 0.75
        if _desc_has(challenge, "rsa", "aes", "crypto", "cipher", "密码", "加密"):
            return 0.7
        for _path, head in _file_heads(challenge):
            if head.startswith(b"-----BEGIN"):
                return 0.8
        return 0.0

    def seed_hypotheses(self, challenge) -> list[str]:
        return [
            "Extract all parameters (n,e,c / key / mode+IV / hash) into notes, "
            "then match against the classic attack table.",
            "If RSA: small-e cube root, Wiener, Fermat, common factor; if AES: "
            "mode oracles (ECB pattern/padding oracle, CBC bit-flip).",
            "If classical: frequency analysis, known-plaintext on 'flag{' "
            "prefix, Vigenere IC analysis.",
        ]

    def system_prompt(self, challenge) -> str:
        return """## CRYPTO METHODOLOGY
1. EXTRACT: pull every integer (labeled or bare), key, mode, IV, hint, and the
   ciphertext into notes. Watch for hex/decimal/base64 variants.
2. RSA attack table (try in order; pure python is enough):
   - e in (3,5,17) and short message, no padding: integer k-th root of c.
   - two ciphertexts same n, coprime e: common-modulus ( extended euclid).
   - small d: Wiener (continued fractions of e/n) - harness recipe already ran.
   - p,q close: Fermat factorization (isqrt walk).
   - multiple n values: pairwise gcd.
   - e shares phi factors, related messages: Franklin-Reiter (write the
     polynomial gcd in python) / Coppersmith small-root if sage exists.
   - given d or p,q: just decrypt: m = pow(c, d, n).
   - unpadded e=65537 with chosen-prefix structure: check message space size.
3. AES/Symmetric:
   - ECB: block repetition patterns -> cut-and-paste attacks; identical blocks
     leak equality.
   - CBC: bit-flip admin flags by xor-ing into the PREVIOUS ciphertext block;
     fixed IV = prefix oracle; padding-oracle script template: for each byte
     try 0x01..0xff, watch the server error differential.
   - Known plaintext + xor: assume the flag starts with 'flag{' and derive
     the repeating key.
4. HASH: identify by length (32 md5 / 40 sha1 / 64 sha256 / 128 sha512);
   length-extension on md5/sha1 (write hlextend-style forging in python if
   the app appends data); hash collisions with structure.
5. CLASSICAL: Caesar/ROT (auto), Vigenere (IC + chi-square - recipe ran),
   substitution (frequency + pattern words), book/rail/columnar ciphers, Morse.
6. Always write the solver in run_python and iterate: crypto is scripted
   mathematics, not guesswork. Keep n/e/c as python ints.
Note: the harness already ran automatic decoders (base64/hex/xor/caesar/zip)
and RSA classics (small-e/Wiener/Fermat) before you started."""


def _has_ciphertext_markers(challenge) -> bool:
    markers = re.compile(
        r"([0-9a-fA-F]{32,}|\b(n|e|c|p|q|d)\s*[:=]\s*(0x)?\d{8,}|"
        r"BEGIN (RSA )?(PUBLIC|PRIVATE) KEY)")
    for path in list(challenge.iter_files())[:15]:
        try:
            head = path.read_bytes()[:100_000].decode("latin-1")
        except OSError:
            continue
        if markers.search(head):
            return True
    return bool(markers.search(challenge.description or ""))
