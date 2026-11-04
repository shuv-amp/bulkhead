#!/usr/bin/env python3
"""floor check: how exposed is a Solana program's upgrade key?

    python3 tools/floor_check.py <program-id> [--rpc URL] [--allow-private-rpc] [--json]

An --rpc whose host resolves to a loopback, private (RFC 1918), link-local,
unique-local or otherwise non-public address is refused unless
--allow-private-rpc is given (a local validator, a node on your own network).

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
import ipaddress
import json
import os
import socket
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


def private_reason(address: str) -> str | None:
    """Why an IP address is not a public one (loopback, RFC 1918, link-local,
    unique-local, CGNAT, unspecified, multicast, reserved), or None. An IPv4
    address carried inside IPv6 (mapped, compatible, 6to4) is judged as IPv4."""
    ip = ipaddress.ip_address(address.split("%", 1)[0])  # drop an IPv6 zone
    if ip.version == 6:
        inner = ip.ipv4_mapped or ip.sixtofour
        if inner is None and int(ip) >> 32 == 0 and int(ip) > 1:  # ::a.b.c.d
            inner = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if inner is not None:
            return private_reason(str(inner))
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_multicast:
        return "multicast"
    if ip.version == 6 and ip in ipaddress.ip_network("fc00::/7"):
        return "unique-local"
    if ip.is_private:
        return "private"
    if not ip.is_global:  # 100.64.0.0/10 (CGNAT) and other special ranges
        return "not globally routable"
    return None


def resolve(host: str, port: int) -> list[str]:
    return sorted({ai[4][0] for ai in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)})


def rpc_url(url: str, allow_private: bool = False, resolver=resolve) -> str:
    """An http(s) URL whose host resolves only to public addresses. urllib
    would also open file: and other schemes, and would POST to a loopback or
    private address as readily as to a public RPC (F-02): every address the
    host resolves to is checked, unless `allow_private`."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise SystemExit(f"floor_check: --rpc must be an http(s) URL, not {url!r}")
    try:
        host, port = parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as e:
        raise SystemExit(f"floor_check: --rpc {url!r}: {e}")
    if not host:
        raise SystemExit(f"floor_check: --rpc {url!r} names no host")
    if allow_private:
        return url
    try:
        addresses = [str(ipaddress.ip_address(host))]  # an address literal: nothing to resolve
    except ValueError:
        try:
            addresses = resolver(host, port)
        except (OSError, UnicodeError) as e:
            raise SystemExit(f"floor_check: cannot resolve {host}: {e}")
    if not addresses:
        raise SystemExit(f"floor_check: {host} resolves to no address")
    bad = [(a, why) for a in addresses if (why := private_reason(a))]
    if bad:
        listed = ", ".join(f"{a} ({why})" for a, why in bad)
        raise SystemExit(
            f"floor_check: refusing --rpc {host}: it resolves to {listed}, not a public address. "
            "Pass --allow-private-rpc to query a node on this machine or network."
        )
    return url


class NoRedirects(urllib.request.HTTPRedirectHandler):
    """JSON-RPC needs no redirects, and following one would let a public URL
    send this tool to a private address the check above refused (F-02)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, f"redirect to {newurl} refused", headers, fp)


OPENER = urllib.request.build_opener(NoRedirects)


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
        with OPENER.open(req, timeout=30) as r:
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


# Addresses and the verdict `private_reason` must give: None for public ones.
RPC_ADDRESS_CASES = [
    ("127.0.0.1", "loopback"), ("127.255.0.9", "loopback"), ("::1", "loopback"),
    ("10.0.0.1", "private"), ("172.16.0.1", "private"), ("172.31.255.255", "private"),
    ("192.168.1.10", "private"), ("0.0.0.0", "unspecified"), ("::", "unspecified"),
    ("169.254.169.254", "link-local"), ("fe80::1", "link-local"), ("fe80::1%en0", "link-local"),
    ("fd00::1", "unique-local"), ("fc00::abcd", "unique-local"),
    ("100.64.0.1", "not globally routable"), ("224.0.0.1", "multicast"),
    ("::ffff:127.0.0.1", "loopback"), ("::ffff:10.1.2.3", "private"), ("::ffff:169.254.1.1", "link-local"),
    ("2002:c0a8:0101::1", "private"), ("::192.168.0.1", "private"),
    ("172.15.255.255", None), ("172.32.0.1", None), ("8.8.8.8", None), ("1.1.1.1", None),
    ("100.128.0.1", None), ("2606:4700:4700::1111", None), ("::ffff:8.8.8.8", None),
]


def rpc_self_test() -> list:
    """The --rpc address check, with a stub resolver: no network. Returns the
    cases that failed."""
    failed = [(a, private_reason(a), want) for a, want in RPC_ADDRESS_CASES if private_reason(a) != want]

    def stub(table):
        def resolver(host, port):
            if host not in table:
                raise socket.gaierror(f"unknown host {host}")
            return table[host]
        return resolver

    names = stub({
        "rpc.example": ["203.0.114.7", "2606:4700::6810:84e5"],  # every address public
        "split.example": ["203.0.114.7", "10.0.0.5"],  # one private address is enough to refuse
        "localhost": ["127.0.0.1", "::1"],
        "metadata.example": ["169.254.169.254"],
        "empty.example": [],
    })

    def verdict(url, allow=False):
        try:
            return rpc_url(url, allow, names) == url
        except SystemExit as e:
            return str(e)

    url_cases = [
        ("https://rpc.example/", False, True),
        ("http://rpc.example:8899", False, True),
        ("https://split.example", False, "10.0.0.5 (private)"),
        ("http://localhost:8899", False, "127.0.0.1 (loopback), ::1 (loopback)"),
        ("http://127.0.0.1:8899", False, "127.0.0.1 (loopback)"),
        ("http://[::1]:8899", False, "::1 (loopback)"),
        ("http://metadata.example/latest", False, "169.254.169.254 (link-local)"),
        ("http://localhost:8899", True, True),  # --allow-private-rpc
        ("http://10.0.0.1:8899", True, True),
        ("https://nowhere.example", False, "cannot resolve nowhere.example"),
        ("https://empty.example", False, "resolves to no address"),
        ("file:///etc/passwd", False, "must be an http(s) URL"),
        ("file:///etc/passwd", True, "must be an http(s) URL"),
        ("http://:8899", False, "names no host"),
    ]
    for url, allow, want in url_cases:
        got = verdict(url, allow)
        if not (got is True if want is True else isinstance(got, str) and want in got):
            failed.append((url, allow, got, want))
    # An address literal is judged as it is, never looked up.
    def never(host, port):
        raise AssertionError(f"{host} was looked up")

    for url, want in [("http://127.0.0.1:8899", "loopback"), ("http://[fd00::1]/", "unique-local")]:
        try:
            rpc_url(url, False, never)
            failed.append((url, "accepted"))
        except SystemExit as e:
            if want not in str(e):
                failed.append((url, str(e)))
        except AssertionError as e:
            failed.append((url, str(e)))
    # A redirect is refused, never followed (to a private address or anywhere).
    try:
        NoRedirects().redirect_request(urllib.request.Request("https://rpc.example/"), None, 302, "Found", {}, "http://127.0.0.1:8899/")
        failed.append(("redirect", "followed"))
    except urllib.error.HTTPError as e:
        if "refused" not in str(e):
            failed.append(("redirect", str(e)))
    if not failed:
        print(f"self-test OK: --rpc address check: {len(RPC_ADDRESS_CASES)} addresses, {len(url_cases) + 3} URLs, redirects refused")
    return failed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("program", nargs="?", help="program id (base58)")
    ap.add_argument("--rpc", default=os.environ.get("SOLANA_RPC", "https://api.mainnet-beta.solana.com"),
                    help="JSON-RPC endpoint (default: $SOLANA_RPC or mainnet-beta's public RPC); "
                    "one resolving to a loopback, private, link-local or unique-local address is refused")
    ap.add_argument("--allow-private-rpc", action="store_true",
                    help="query an --rpc on this machine or a private network (a local validator, a node on your LAN)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true", help="check the curve test on known keys and the --rpc address check")
    a = ap.parse_args()
    if a.self_test:
        failed = rpc_self_test()
        if failed:
            print(f"self-test FAILED: --rpc address check: {failed}")
            return 1
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
    r = check(program_id(a.program), rpc_url(a.rpc, a.allow_private_rpc))
    print(json.dumps(r, indent=2) if a.json else report(r))
    return 0 if "error" not in r else 1


if __name__ == "__main__":
    sys.exit(main())
