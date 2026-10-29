"""Forensics playbook: identify artifact -> right extractor -> correlate."""

from __future__ import annotations

from .base import Playbook, _desc_has, _has_ext


class ForensicsPlaybook(Playbook):
    id = "forensics"
    title = "Forensics"

    def matches(self, challenge) -> float:
        if _has_ext(challenge, (".pcap", ".pcapng", ".raw", ".E01", ".dd",
                                ".img", ".vmdk", ".mem", ".dmp", ".ad1", ".aff")):
            return 0.9
        if _desc_has(challenge, "pcap", "traffic", "memory dump", "disk",
                     "流量", "内存", "取证", "镜像", "wireshark", "volatility"):
            return 0.85
        return 0.0

    def seed_hypotheses(self, challenge) -> list[str]:
        return [
            "Identify the artifact type precisely, then apply the canonical "
            "extraction chain for that type (see methodology).",
            "In captures: reconstruct the interesting conversation (HTTP file "
            "transfers, credentials, exfil) and export the objects.",
            "In memory dumps: process list + cmdline + injected code regions; "
            "in disk images: deleted-file carving and registry artifacts.",
        ]

    def system_prompt(self, challenge) -> str:
        return """## FORENSICS METHODOLOGY
1. IDENTIFY: file signature first (notes already have the sniff); pcap vs
   memory dump vs disk image vs document vs archive - each has its own chain.
2. NETWORK CAPTURES (pcap/pcapng):
   - protocol hierarchy and conversations (tshark if installed, else parse
     or string-scan; the harness recipe already scanned flags/creds/URIs);
   - follow TCP/HTTP streams of interest, export transferred objects,
     reassemble fragmented transfers;
   - check for DNS/ICMP exfil, FTP/SMTP/SMB credentials, Kerberos hashes.
3. MEMORY DUMPS: if volatility3 exists use pslist/cmdline/filescan/
   dumpfiles/procdump + malfind; else python-string mining targeted at
   flag/password/credential/window titles and injected regions.
4. DISK IMAGES / deleted files: carve by magic (recipe already carved
   common formats); check NTFS artifacts, browser history SQLite files,
   recycle bin ($I/$R files), MFT/USN if tooling exists.
5. DOCUMENTS: zip-based formats (docx/xlsx) -> unzip and inspect XML +
   vbaProject.bin (macros); PDF -> object/stream extraction, JS payloads.
6. METADATA: exiftool when available; GPS/author/hidden fields.
7. CORRELATE: forensic challenges usually chain 2-3 steps (decode ->
   extract -> decode again). Keep every intermediate artifact in the
   workspace and note what each one revealed - the flag is typically at
   the end of the chain, and your notes are the writeup."""
