# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Aukora
# Independent Python reference for EvidencePack v1 canonical bytes, packDigest, catalogueId, and fence
# nonce (contract decision 17). Not imported by the package; a cross-runtime conformance oracle. D2:
# reproduces the CATALOGUE_ID and the MAXIMAL body packDigest as well, so both KATs are checked in a
# second language rather than only echoed by the library that produced them.
import hashlib, json, struct

PACK_DOMAIN = b'aukora-fu-evidence-pack-v1'
FENCE_DOMAIN = 'aukora-fu-evidence-fence-v1'

def canonical(value) -> str:
    # JCS-aligned for the accepted closed domain (safe-int numbers, JSON string escaping, sorted keys).
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

def pack_digest(body) -> str:
    c = canonical(body).encode('utf-8')
    pre = PACK_DOMAIN + b'\x00' + struct.pack('>Q', len(c)) + c
    return hashlib.sha256(pre).hexdigest()

def fence_nonce(pack_digest_hex: str, contents) -> str:
    for counter in range(100000):
        nonce = hashlib.sha256(f'{FENCE_DOMAIN}|{pack_digest_hex}|{counter}'.encode('utf-8')).hexdigest()
        toks = [f'<<AUKORA-DATA:{nonce}>>', f'<<AUKORA-END:{nonce}>>']
        if all(all(t not in c for t in toks) for c in contents):
            return nonce
    raise RuntimeError('E_FENCE_NONCE')

# Faithful replica of src/evidence/catalogue.ts SECRET_CATALOGUE (schema v2). catalogueId is the sha256
# of its canonical bytes, so this dict must match the TS table entry-for-entry (order is irrelevant —
# canonical() sorts keys). Confusable keys use explicit code points to remove any glyph-copy ambiguity.
SECRET_CATALOGUE = {
    'schema': 'aukora-fu-secret-catalogue-v2',
    'patterns': [
        {'id': 'openrouter-key', 'pattern': 'sk-or-[A-Za-z0-9_\\-]{16,}', 'flags': 'g'},
        {'id': 'openai-key', 'pattern': 'sk-[A-Za-z0-9]{20,}', 'flags': 'g'},
        {'id': 'aws-access-key-id', 'pattern': 'AKIA[0-9A-Z]{16}', 'flags': 'g'},
        {'id': 'pem-private-key', 'pattern': '-----BEGIN [A-Z ]*PRIVATE KEY-----', 'flags': 'g'},
        {'id': 'jwt', 'pattern': 'eyJ[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{10,}\\.[A-Za-z0-9_\\-]{6,}', 'flags': 'g'},
        {'id': 'env-secret-assign', 'pattern': '(?:API|SECRET|TOKEN|PASSWORD|PRIVATE)[A-Z0-9_]*\\s*=\\s*\\S{8,}', 'flags': 'gi'},
    ],
    'confusables': {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
        'ѕ': 's', 'і': 'i', 'ј': 'j', 'һ': 'h', 'ԁ': 'd', 'ԛ': 'q',
        'ɡ': 'g', 'ο': 'o', 'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Κ': 'K',
        'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Χ': 'X',
    },
    'zeroWidth': ['​', '‌', '‍', '⁠', '﻿'],
}

def catalogue_id() -> str:
    return hashlib.sha256(canonical(SECRET_CATALOGUE).encode('utf-8')).hexdigest()

CATALOGUE_ID = catalogue_id()

if __name__ == '__main__':
    min_body = {
        "schema": "aukora-fu-evidence-pack-v1", "advisoryOnly": True, "grantsAuthority": False,
        "repoId": "aumara-xyz/aukora-fu", "headCommit": "a"*40, "headTree": "b"*40,
        "baseCommit": None, "baseTree": None, "files": [], "omissions": [], "testRuns": [],
        "rootAllowlist": [], "limitsProfileId": "default-v1",
        "builderToolVersions": {"node": "v22.23.0"},
        "catalogueId": CATALOGUE_ID,
    }
    SHA_HELLO = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    SHA_ZEROS3 = '709e80c88487a2411e1ee4dfb9f22a861492d20c4765150c0c794abd70f8147c'
    SHA_EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'  # sha256("")
    max_body = {
        "schema": "aukora-fu-evidence-pack-v1", "advisoryOnly": True, "grantsAuthority": False,
        "repoId": "aumara-xyz/aukora-fu", "headCommit": "a"*40, "headTree": "b"*40,
        "baseCommit": None, "baseTree": None,
        "files": [
            {"path": "a.ts", "kind": "text", "originalSizeBytes": 5, "includedByteStart": 0,
             "includedByteEnd": 5, "truncated": False, "fullSha256": SHA_HELLO,
             "includedSha256": SHA_HELLO, "encoding": "utf8", "content": "hello"},
            {"path": "b.png", "kind": "binary", "originalSizeBytes": 3, "includedByteStart": 0,
             "includedByteEnd": 3, "truncated": False, "fullSha256": SHA_ZEROS3,
             "includedSha256": SHA_ZEROS3, "encoding": "base64", "content": "AAAA"},
        ],
        "omissions": [
            {"path": "secret.env", "reason": "secret-file", "originalSizeBytes": None, "sha256": None},
        ],
        "testRuns": [
            {"command": ["npm", "run", "verify"], "cwdRelative": ".", "exitCode": 0,
             "stdoutSha256": SHA_EMPTY, "stderrSha256": SHA_EMPTY, "stdoutBytes": 0, "stderrBytes": 0,
             "stdoutExcerpt": "", "stderrExcerpt": "", "durationMs": None, "toolVersions": {}},
        ],
        "rootAllowlist": ["a.ts", "b.png", "secret.env"], "limitsProfileId": "default-v1",
        "builderToolVersions": {"node": "v22.23.0"}, "catalogueId": CATALOGUE_ID,
    }
    print("CATALOGUE_ID=" + CATALOGUE_ID)
    print("MIN_CANON=" + canonical(min_body))
    print("MIN_DIGEST=" + pack_digest(min_body))
    print("MAX_DIGEST=" + pack_digest(max_body))
    print("FENCE=" + fence_nonce("00"*32, ["hello", "world"]))
