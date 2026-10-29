"""Crypto recipes: RSA attack kit, Vigenere solver, basic hash cracking."""

from __future__ import annotations

import hashlib
import re

from ..heuristics import Finding
from ..rsa_kit import attack as rsa_attack
from ..rsa_kit import parse_rsa_material
from .base import Recipe

_ENGLISH_FREQ = (0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
                 0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
                 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
                 0.00978, 0.02360, 0.00150, 0.01974, 0.00074)

_COMMON_WORDS = ("password", "123456", "12345678", "qwerty", "abc123", "letmein",
                 "admin", "root", "flag", "ctf", "secret", "p@ssw0rd", "iloveyou",
                 "monkey", "dragon", "111111", "000000", "test", "guest", "user",
                 "welcome", "master", "login", "pass", "hello", "free", "whatever",
                 "baseball", "football", "starwars", "shadow", "superman", "batman",
                 "trustno1", "sunshine", "princess", "freedom", "changeme")


def _read_texts(challenge, limit_files: int = 25, limit_bytes: int = 200_000) -> str:
    chunks: list[str] = []
    for path in list(challenge.iter_files())[:limit_files]:
        try:
            data = path.read_bytes()[:limit_bytes]
        except OSError:
            continue
        chunks.append(data.decode("latin-1"))
    return "\n".join(chunks)


class RsaAttacksRecipe(Recipe):
    id = "crypto.rsa_attacks"
    title = "Run the pure-python RSA attack kit (small-e/Wiener/Fermat/common-factor)"
    categories = ("crypto",)

    def match(self, challenge) -> bool:
        return True  # cheap text sniff happens in run()

    def run(self, rc) -> list:
        text = _read_texts(rc.challenge) + "\n" + (rc.challenge.description or "")
        material = parse_rsa_material(text)
        if not material.get("n"):
            return []
        results = rsa_attack(material)
        if not results:
            rc.note("RSA material found but no classic attack succeeded", tag="crypto")
            return []
        outputs = []
        for technique, recovered in results:
            rc.note(f"RSA attack hit: {technique} -> {recovered[:80]!r}", tag="crypto")
            outputs.append(recovered)
        return rc.scan(*outputs)


class VigenereSolverRecipe(Recipe):
    id = "crypto.vigenere"
    title = "Break Vigenere via index-of-coincidence + chi-square"
    categories = ("crypto", "misc")

    @staticmethod
    def _letters_only(text: str) -> str:
        return "".join(c.lower() for c in text if c.isascii() and c.isalpha())

    @staticmethod
    def _ic(text: str) -> float:
        n = len(text)
        if n < 2:
            return 0.0
        freq = [0] * 26
        for ch in text:
            freq[ord(ch) - 97] += 1
        return sum(f * (f - 1) for f in freq) / (n * (n - 1))

    @staticmethod
    def _chi2(text: str) -> float:
        n = max(1, len(text))
        freq = [0] * 26
        for ch in text:
            freq[ord(ch) - 97] += 1
        return sum((freq[i] / n - _ENGLISH_FREQ[i]) ** 2 / max(_ENGLISH_FREQ[i], 1e-6)
                   for i in range(26))

    def _solve(self, cipher: str, key_length: int) -> tuple[str, str]:
        columns = [cipher[i::key_length] for i in range(key_length)]
        key = ""
        for column in columns:
            best_shift, best_score = 0, float("inf")
            for shift in range(26):
                shifted = "".join(chr((ord(c) - 97 - shift) % 26 + 97) for c in column)
                score = self._chi2(shifted)
                if score < best_score:
                    best_shift, best_score = shift, score
            key += chr(best_shift + 97)
        plain = ""
        for i, ch in enumerate(cipher):
            shift = ord(key[i % key_length]) - 97
            plain += chr((ord(ch) - 97 - shift) % 26 + 97)
        return key, plain

    def match(self, challenge) -> bool:
        return True

    def run(self, rc) -> list:
        for path in list(rc.challenge.iter_files())[:10]:
            try:
                raw = path.read_bytes()[:200_000].decode("latin-1")
            except OSError:
                continue
            cipher = self._letters_only(raw)
            if len(cipher) < 80:
                continue
            scores = {}
            for key_length in range(2, 17):
                column_ics = [self._ic(cipher[i::key_length]) for i in range(key_length)]
                scores[key_length] = sum(column_ics) / key_length
            for key_length, score in sorted(scores.items(), key=lambda kv: -kv[1])[:2]:
                if score < 0.052:
                    continue
                key, plain = self._solve(cipher, key_length)
                rc.note(f"vigenere candidate key_length={key_length} key={key!r}",
                        tag="crypto")
                found = rc.scan(plain)
                if found:
                    return found
        return []


class HashCrackRecipe(Recipe):
    id = "crypto.hash_crack"
    title = "Try a common-word list against md5/sha1/sha256/sha512 digests"
    categories = ("crypto", "misc", "web")

    _ALGOS = ("md5", "sha1", "sha256", "sha512")

    def match(self, challenge) -> bool:
        return True

    def run(self, rc) -> list:
        text = _read_texts(rc.challenge, limit_files=10, limit_bytes=100_000)
        hashes: list[str] = []
        for match in re.finditer(
                r"\b([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})\b",
                text):
            value = match.group(1).lower()
            if value not in hashes:
                hashes.append(value)
        if not hashes:
            return []
        for digest in hashes[:20]:
            for word in _COMMON_WORDS:
                for wrapper in (word, f"flag{{{word}}}", f"ctf{{{word}}}"):
                    for algo in self._ALGOS:
                        if hashlib.new(algo, wrapper.encode()).hexdigest() == digest:
                            rc.note(f"hash {digest[:16]}... = {algo}({wrapper!r})",
                                    tag="crypto")
                            return rc.scan(wrapper)
        rc.note(f"{len(hashes)} hash(es) found, common wordlist missed", tag="crypto")
        return []


def crypto_recipes() -> list[Recipe]:
    return [
        RsaAttacksRecipe(RsaAttacksRecipe.id, RsaAttacksRecipe.title,
                         ("crypto",), "RSA small-e/Wiener/Fermat"),
        VigenereSolverRecipe(VigenereSolverRecipe.id, VigenereSolverRecipe.title,
                             ("crypto", "misc"), "IC + chi-square vigenere"),
        HashCrackRecipe(HashCrackRecipe.id, HashCrackRecipe.title,
                        ("crypto", "misc", "web"), "common word hash cracking"),
    ]
