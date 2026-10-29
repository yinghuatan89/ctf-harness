"""Unit tests: solver layer (flag extract, L0 heuristics, RSA kit, categories,
recipes incl. PNG-LSB steg and declarative user recipes)."""

from __future__ import annotations

import base64
import gzip
import random
import tempfile
import unittest
import zipfile
from pathlib import Path

from ctf_harness.categories import select
from ctf_harness.core.blackboard import Blackboard
from ctf_harness.core.challenge import Challenge, DEFAULT_FLAG_RE
from ctf_harness.core.session import SessionLog
from ctf_harness.safety import Guard
from ctf_harness.solver.flagextract import extract_candidates, extract_generic
from ctf_harness.solver.heuristics import fast_scan
from ctf_harness.solver.rsa_kit import (cube_root, fermat_factor, iroot,
                                        parse_rsa_material, small_factor,
                                        wiener)
from ctf_harness.solver.declarative import load_declarative_recipes
from ctf_harness.solver.recipes import all_recipes
from ctf_harness.solver.recipes.base import RecipeContext
from ctf_harness.tools import ToolContext, build_registry


def _is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(30):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        n = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(n):
            return n


class TestFlagExtract(unittest.TestCase):
    def test_extract(self):
        text = 'junk "flag{abc_123}" tail FLAG{UPPER_case} not-this{nope}'
        found = extract_candidates(text, DEFAULT_FLAG_RE)
        self.assertIn("flag{abc_123}", found)
        self.assertIn("FLAG{UPPER_case}", found)
        self.assertNotIn("not-this{nope}", found)

    def test_generic(self):
        found = extract_generic('loot{H4rd_c0ded_tr3asure}')
        self.assertIn("loot{H4rd_c0ded_tr3asure}", found)
        # json-ish braces must not produce candidates
        self.assertEqual(extract_generic('{"tool": "x"}'), [])


class TestHeuristics(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ctfh-l0-"))

    def _scan(self, name="x") -> list:
        return fast_scan(self.tmp, DEFAULT_FLAG_RE, budget_s=20)

    def test_nested_base64(self):
        once = base64.b64encode(b"flag{nested_b64_deep}").decode()
        twice = base64.b64encode(once.encode()).decode()
        (self.tmp / "f.txt").write_text(twice)
        flags = [f.flag for f in self._scan()]
        self.assertIn("flag{nested_b64_deep}", flags)

    def test_hex(self):
        (self.tmp / "h.txt").write_text(b"flag{hexy_wins}".hex())
        self.assertIn("flag{hexy_wins}", [f.flag for f in self._scan()])

    def test_gzip(self):
        (self.tmp / "g.bin").write_bytes(gzip.compress(b"prefix flag{gz_flag}"))
        self.assertIn("flag{gz_flag}", [f.flag for f in self._scan()])

    def test_zip_with_password(self):
        import io
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            zf.setpassword(b"ctf")
            zf.writestr(zipfile.ZipInfo("inner.txt"), "flag{zipped_pw}")
        (self.tmp / "z.zip").write_bytes(buffer.getvalue())
        self.assertIn("flag{zipped_pw}", [f.flag for f in self._scan()])

    def test_single_byte_xor(self):
        raw = b"flag{xor_hit_again}\n"
        (self.tmp / "x.bin").write_bytes(bytes(b ^ 0x37 for b in raw))
        self.assertIn("flag{xor_hit_again}", [f.flag for f in self._scan()])

    def test_binary_strings(self):
        payload = b"\x00\x01" + b"flag{embedded_string}" + b"\xff\x00" * 8
        (self.tmp / "b.bin").write_bytes(payload)
        self.assertIn("flag{embedded_string}", [f.flag for f in self._scan()])

    def test_no_false_positive(self):
        (self.tmp / "plain.txt").write_text("just a normal text file, no flags")
        self.assertEqual(self._scan(), [])


class TestRsaKit(unittest.TestCase):
    def test_iroot_exact_and_floor(self):
        self.assertEqual(iroot(27, 3), (3, True))
        self.assertEqual(iroot(28, 3), (3, False))
        self.assertEqual(cube_root(1000), 10)

    def test_small_factor(self):
        n = 100003 * 99991
        self.assertEqual(small_factor(n), 99991)

    def test_fermat_close_primes(self):
        def next_prime(start: int) -> int:
            n = start if start % 2 else start + 1
            while not _is_prime(n):
                n += 2
            return n

        p = next_prime(10 ** 9)
        q = next_prime(p + 2)
        pair = fermat_factor(p * q)
        self.assertIsNotNone(pair)
        self.assertEqual(set(pair), {p, q})

    def test_wiener_small_d(self):
        from math import gcd
        random.seed(7)
        for _attempt in range(60):
            p, q = _gen_prime(256), _gen_prime(256)
            n, phi = p * q, (p - 1) * (q - 1)
            d = 40007  # deliberately small private exponent
            if gcd(d, phi) != 1:
                continue
            e = pow(d, -1, phi)
            break
        else:
            self.fail("could not build a wiener-vulnerable key")
        self.assertEqual(wiener(e, n), d)

    def test_parse_material_labeled(self):
        text = "n = 12345678901234567890123456789\ne = 3\nc = 998877665544332211"
        material = parse_rsa_material(text)
        self.assertEqual(material["e"], [3])
        self.assertEqual(len(material["n"]), 1)
        self.assertEqual(len(material["c"]), 1)

    def test_parse_material_pem(self):
        # hand-build a minimal SPKI-like DER: SEQ { SEQ{}, BITSTRING { SEQ { n, e } } }
        def der_int(value: int) -> bytes:
            raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
            if raw[0] & 0x80:
                raw = b"\x00" + raw
            return b"\x02" + bytes([len(raw)]) + raw

        def der_seq(body: bytes) -> bytes:
            return b"\x30" + bytes([len(body)]) + body

        inner = der_seq(der_int(987654321987654321) + der_int(65537))
        bit = b"\x03" + bytes([len(inner) + 1]) + b"\x00" + inner
        spki = der_seq(der_seq(b"") + bit)
        import base64 as b64
        pem = ("-----BEGIN PUBLIC KEY-----\n"
               + b64.b64encode(spki).decode() + "\n-----END PUBLIC KEY-----\n")
        material = parse_rsa_material(pem)
        self.assertEqual(material["n"][0], 987654321987654321)
        self.assertIn(65537, material["e"])


class TestCategories(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ctfh-cat-"))

    def _file(self, name: str, data: bytes):
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_explicit_category(self):
        self.assertEqual(select(Challenge(name="x", category="web")).id, "web")
        self.assertEqual(select(Challenge(name="x", category="re")).id, "reverse")
        self.assertEqual(select(Challenge(name="x", category="取证")).id, "forensics")

    def test_autodetect_web(self):
        challenge = Challenge(name="x", url="http://ctf.example.com/")
        self.assertEqual(select(challenge).id, "web")

    def test_autodetect_pwn_vs_reverse(self):
        self._file("chall_pwn", b"\x7fELF" + b"\x00" * 64)
        pwnish = Challenge(name="x", path=self.tmp, remote="1.2.3.4:1337")
        self.assertEqual(select(pwnish).id, "pwn")
        self._file("chall_rev", b"\x7fELF" + b"\x00" * 64)
        revish = Challenge(name="x", path=self.tmp)
        self.assertEqual(select(revish).id, "reverse")

    def test_autodetect_forensics_and_misc(self):
        self._file("trace.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 32)
        challenge = Challenge(name="x", path=self.tmp)
        self.assertEqual(select(challenge).id, "forensics")
        self.assertEqual(select(Challenge(name="x")).id, "misc")


class TestRecipes(unittest.TestCase):
    def _recipe_context(self, challenge):
        tmp = Path(tempfile.mkdtemp(prefix="ctfh-rc-"))
        registry = build_registry()
        guard = Guard(tmp, scope_hosts=challenge.scope_hosts())
        ctx = ToolContext(
            workspace=tmp, guard=guard, challenge=challenge,
            session=SessionLog(tmp / ".ctfh" / "session.jsonl"),
            blackboard=Blackboard(),
            propose_flag=lambda flag: (True, "ok"),
            step_dir=tmp / ".ctfh" / "l1", lane="l1")
        return RecipeContext(challenge=challenge, guard=guard, registry=registry,
                             tool_ctx=ctx, flag_re=challenge.flag_format)

    def test_recipe_ids_unique_and_builtins_present(self):
        recipes = all_recipes()
        ids = [r.id for r in recipes]
        self.assertEqual(len(ids), len(set(ids)))
        for expected in ("web.sqli_bypass", "web.ssti_probe", "web.jwt_probe",
                         "crypto.rsa_attacks", "crypto.vigenere",
                         "crypto.hash_crack", "misc.steg_probe",
                         "misc.zero_width", "misc.brainfuck", "misc.git_mining",
                         "misc.known_plaintext_xor", "forensics.pcap_scan",
                         "forensics.file_carve", "forensics.memory_hints",
                         "pwn.elf_recon", "pwn.fmt_probe", "pwn.upx_unpack",
                         "web.low_hanging", "web.cmd_injection_probe"):
            self.assertIn(expected, ids)

    def test_steg_lsb_png(self):
        import struct
        import zlib

        flag = b"flag{lsb_steg_visible}"
        bits = "".join(f"{byte:08b}" for byte in flag)
        width, height, channels = 24, 4, 3
        raw = bytearray()
        index = 0
        for _y in range(height):
            raw.append(0)  # filter type 0
            for _x in range(width):
                for channel in range(channels):
                    bit = int(bits[index]) if index < len(bits) else 0
                    raw.append(0x80 | bit)
                    index += 1
        def chunk(ctype: bytes, body: bytes) -> bytes:
            return (struct.pack(">I", len(body)) + ctype + body
                    + struct.pack(">I", zlib.crc32(ctype + body) & 0xFFFFFFFF))
        ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
        png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
               + chunk(b"IDAT", zlib.compress(bytes(raw))) + chunk(b"IEND", b""))
        tmp = Path(tempfile.mkdtemp(prefix="ctfh-steg-"))
        (tmp / "cover.png").write_bytes(png)
        challenge = Challenge(name="steg", path=tmp, category="misc")
        recipes = {r.id: r for r in all_recipes()}
        findings = recipes["misc.steg_probe"].run(self._recipe_context(challenge))
        self.assertTrue(any(f.flag == flag.decode() for f in findings),
                        msg=str(findings))

    def test_declarative_recipe_load_and_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            recipes_dir = Path(tmp)
            (recipes_dir / "probe.json").write_text(
                '{\"id\": \"user.probe\", \"title\": \"probe hidden route\",'
                ' \"category\": \"web\", \"requires\": {\"url\": true},'
                ' \"steps\": [{\"tool\": \"http\", \"args\":'
                ' {\"method\": \"GET\", \"url\": \"{{url}}/hidden_flag\"}}]}',
                encoding="utf-8")
            recipes, errors = load_declarative_recipes([recipes_dir])
            self.assertEqual(errors, [])
            self.assertEqual(len(recipes), 1)
            self.assertEqual(recipes[0].id, "user.probe")
            self.assertTrue(recipes[0].match(
                Challenge(name="x", url="http://127.0.0.1:1/")))
            self.assertFalse(recipes[0].match(Challenge(name="x")))

    def test_brainfuck_recipe(self):
        tmp = Path(tempfile.mkdtemp(prefix="ctfh-bf-"))
        # a valid BF program that prints the flag: for each char,
        # '+'*ord(c) then '.' then '-'*ord(c) resets the cell
        flag = "flag{bf_esolang_done}"
        program = "".join("+" * ord(c) + "." + "-" * ord(c) for c in flag)
        (tmp / "prog.bf").write_text(program, encoding="ascii")
        challenge = Challenge(name="bf", path=tmp, category="misc")
        recipes = {r.id: r for r in all_recipes()}
        self.assertTrue(recipes["misc.brainfuck"].match(challenge))
        findings = recipes["misc.brainfuck"].run(self._recipe_context(challenge))
        self.assertTrue(any(f.flag == flag for f in findings), msg=str(findings))


if __name__ == "__main__":
    unittest.main()
