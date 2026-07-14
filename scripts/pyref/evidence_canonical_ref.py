# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Aukora
# Independent Python reference for EvidencePack v1 canonical bytes, packDigest, and fence nonce
# (contract decision 17). Not imported by the package; a cross-runtime conformance oracle.
import hashlib, json, struct

PACK_DOMAIN = b'aukora-fu-evidence-pack-v1'
FENCE_DOMAIN = 'aukora-fu-evidence-fence-v1'

def canonical(value) -> str:
    # JCS-aligned for the accepted closed domain (ASCII keys, safe-int numbers, JSON string escaping).
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

if __name__ == '__main__':
    min_body = {
        "schema": "aukora-fu-evidence-pack-v1", "advisoryOnly": True, "grantsAuthority": False,
        "repoId": "aumara-xyz/aukora-fu", "headCommit": "a"*40, "headTree": "b"*40,
        "baseCommit": None, "baseTree": None, "files": [], "omissions": [], "testRuns": [],
        "rootAllowlist": [], "limitsProfileId": "default-v1",
        "builderToolVersions": {"node": "v22.23.0"},
        "catalogueId": "04b0ae213e8dacb99665015bbc761e9cddef68391902ef0026af13dda82a94cb",
    }
    print("MIN_CANON=" + canonical(min_body))
    print("MIN_DIGEST=" + pack_digest(min_body))
    print("FENCE=" + fence_nonce("00"*32, ["hello", "world"]))
