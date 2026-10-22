#!/usr/bin/env python3
"""floor check: how exposed is a Solana program's upgrade key?

    python3 tools/floor_check.py <program-id> [--rpc URL] [--json]

Reports, for any upgradeable (loader-v3) program:
- who can upgrade it: nobody (immutable), a single plain key (on the ed25519
  curve), or a program-controlled address (a PDA: a multisig, a DAO, Floor);
- when it last changed;
- whether its current binary is sBPF v3, i.e. still deployable after
  SIMD-0500 (planned for Agave 4.4) disables deploying v0/v1/v2. A program that is not v3
  can't be patched, stopped-and-restored, or redeployed with its current
  toolchain once SIMD-0500 is active;
- the size of its programdata account.

Standard library only. Reads only account headers (RPC `dataSlice`), never a
whole program. Uses the parsers in reference/bulkhead_ref.py, which the
differential runner checks against the Rust core.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "reference"))
import bulkhead_ref as ref  # noqa: E402

LOADER_V3 = "BPFLoaderUpgradeab1e11111111111111111111111"
SLOT_SECONDS = 0.4

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        if c not in B58:
            raise ValueError(f"not a base58 string: {s!r}")
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + raw


def program_id(s: str) -> str:
    """A program id as given, once it decodes to exactly 32 bytes. A mistyped
    id used to go to the RPC as it was (or crash on a character outside the
    alphabet); the answer was then the node's, not this tool's (finding 145)."""
    try:
        raw = b58decode(s)
    except ValueError as e:
        raise SystemExit(f"floor_check: {e}")
    if len(raw) != 32:
        raise SystemExit(f"floor_check: {s!r} decodes to {len(raw)} bytes, not the 32 of an address")
    return s


def rpc_url(url: str) -> str:
    """An http(s) URL. urllib would also open file: and other schemes."""
    scheme = urllib.parse.urlsplit(url).scheme
    if scheme not in ("http", "https"):
        raise SystemExit(f"floor_check: --rpc must be an http(s) URL, not {url!r}")
    return url


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out


# --- ed25519: is a 32-byte address a point on the curve? -------------------
P = 2**255 - 19
D = (-121665 * pow(121666, P - 2, P)) % P


def on_curve(key: bytes) -> bool:
    """RFC 8032 point decoding: True iff `key` decodes to a curve point, i.e. a
    keypair could exist for it. PDAs are, by construction, off the curve."""
    # As Solana's is_on_curve (curve25519-dalek): a y of p or more is taken mod p,
    # not refused (p + 1 is the identity point, on the curve).
    y = (int.from_bytes(key, "little") & ((1 << 255) - 1)) % P
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x = (u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P)) % P
    if (v * x * x - u) % P == 0:
        return True
    return (v * x * x + u) % P == 0  # x * sqrt(-1) is the root


# --- RPC --------------------------------------------------------------------
def rpc(url: str, method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, body, {"content-type": "application/json", "user-agent": "floor-check"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            out = json.loads(r.read())
    except (urllib.error.URLError, OSError, ValueError) as e:
        # A transport or decoding failure is reported as such, never as a
        # verdict about the program (finding 145).
        raise SystemExit(f"floor_check: {method} failed against {urllib.parse.urlsplit(url).netloc}: {e}")
    if not isinstance(out, dict) or "result" not in out and "error" not in out:
        raise SystemExit(f"floor_check: {method}: the endpoint did not answer JSON-RPC")
    if "error" in out:
        raise RuntimeError(f"{method}: {out['error']}")
    return out["result"]


def account(url: str, address: str, length: int | None = None):
    cfg = {"encoding": "base64"}
    if length is not None:
        cfg["dataSlice"] = {"offset": 0, "length": length}
    v = rpc(url, "getAccountInfo", [address, cfg])["value"]
    if v is None:
        return None
    v["bytes"] = base64.b64decode(v["data"][0])
    return v


def check(program_id: str, url: str) -> dict:
    prog = account(url, program_id)
    if prog is None:
        return {"program": program_id, "error": "account not found"}
    if prog["owner"] != LOADER_V3:
        return {"program": program_id, "error": f"not an upgradeable (loader-v3) program; owner {prog['owner']}"}
    pd_key = ref.program_programdata(prog["bytes"])
    if pd_key is None:
        return {"program": program_id, "error": "malformed program account"}
    programdata = b58encode(pd_key)
    pd = account(url, programdata, ref.PROGRAMDATA_DATA_OFFSET + 64)
    if pd is None:
        # `solana program close` removes the programdata; the program account stays.
        return {"program": program_id, "programdata": programdata, "error": "program closed: its programdata account no longer exists"}
    header = ref.programdata_header(pd["bytes"])
    if header is None:
        return {"program": program_id, "programdata": programdata, "error": "malformed programdata account"}
    size = pd.get("space")
    if size is None:  # older RPCs: fetch the full account once
        size = len(account(url, programdata)["bytes"])
    elf = ref.elf_info(pd["bytes"][ref.PROGRAMDATA_DATA_OFFSET:])
    slot = rpc(url, "getSlot", [])
    last_slot, auth = header
    if auth[0] == "none":
        who, authority = "immutable", None
    else:
        authority = b58encode(auth[1])
        who = "single plain key (on-curve)" if on_curve(auth[1]) else "program-controlled address (PDA: multisig, DAO or Floor)"
    return {
        "program": program_id,
        "programdata": programdata,
        "upgrade_authority": authority,
        "authority_kind": who,
        "last_deployed_slot": last_slot,
        "days_since_last_deploy": round((slot - last_slot) * SLOT_SECONDS / 86_400, 1),
        "sbpf": {"e_machine": elf and elf[0], "e_flags": elf and elf[1]},
        "deployable_after_simd0500": ref.deployable_after_simd0500(elf),
        "programdata_bytes": size,
    }


def report(r: dict) -> str:
    if "error" in r:
        return f"{r['program']}: {r['error']}"
    if r["upgrade_authority"] is None:
        v3 = "not applicable (immutable: nothing can be deployed to it)"
    elif r["deployable_after_simd0500"]:
        v3 = "yes (sBPF v3)"
    else:
        v3 = "NO: after SIMD-0500 only an sBPF v3 build can be deployed; ship and test one first"
    lines = [
        f"program            {r['program']}",
        f"upgrade authority  {r['upgrade_authority'] or '(none)'}",
        f"  kind             {r['authority_kind']}",
        f"last deployed      slot {r['last_deployed_slot']} (~{r['days_since_last_deploy']} days ago)",
        f"binary             e_machine {r['sbpf']['e_machine']}, e_flags {r['sbpf']['e_flags']}",
        f"SIMD-0500 ready    {v3}",
        f"size               {r['programdata_bytes']:,} bytes of programdata",
    ]
    if r["upgrade_authority"] and "plain key" in r["authority_kind"]:
        lines.append("note               one key can replace this program's code at any time, instantly")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("program", nargs="?", help="program id (base58)")
    ap.add_argument("--rpc", default=os.environ.get("SOLANA_RPC", "https://api.mainnet-beta.solana.com"))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true", help="check the curve test on known keys")
    a = ap.parse_args()
    if a.self_test:
        # 268 addresses (PDA candidates and y ≥ p edges) with Solana's own verdict (solana-address
        # `is_on_curve`, curve25519-dalek), generated by
        # programs/tests/tests/curve_vectors.rs. Every one must agree.
        with open(os.path.join(HERE, "testdata", "curve25519_vectors.json")) as f:
            vectors = json.load(f)
        bad = [h for h, want in vectors if on_curve(bytes.fromhex(h)) != want]
        on = sum(1 for _, w in vectors if w)
        if bad:
            print(f"self-test FAILED on {len(bad)} of {len(vectors)} vectors: {bad[:3]}")
            return 1
        print(f"self-test OK: {len(vectors)} vectors ({on} on-curve, {len(vectors) - on} off-curve) agree with curve25519-dalek")
        return 0
    if not a.program:
        ap.error("program id required")
    r = check(program_id(a.program), rpc_url(a.rpc))
    print(json.dumps(r, indent=2) if a.json else report(r))
    return 0 if "error" not in r else 1


if __name__ == "__main__":
    sys.exit(main())
