#!/usr/bin/env python3
"""
verify.py -- check Recompound's anchored track record without trusting Recompound.

Standard library only. Mirrors SPEC v1 (rcanchor-v1): canonical JSON is UTF-8,
keys sorted, separators "," and ":", numbers carried as strings; a leaf hash is
SHA-256 of those bytes; the tree sorts leaf hashes, hashes pairs left||right,
pairs an odd trailing node with itself.

  verify.py manifest roots.csv manifests/D.json manifests/D.proof.json
      The public manifest is inside the day root listed in roots.csv.
  verify.py chain roots.csv
      Every day's prev_root is the previous day's root (nothing inserted or removed).
  verify.py day leaves/D.jsonl manifests/D.json [roots.csv]
      With the private leaves (verifier under NDA): recompute the day root.
  verify.py backfill BACKFILL/days.csv BACKFILL/backfill_root.txt [roots.csv]
      Recompute the backfill root over the listed day roots.
  verify.py ots proofs/D.root.ots <root hex>
      The .ots proof commits to sha256(root bytes); prints the Bitcoin block it
      is attested in. Full check: `ots verify proofs/D.root.ots` with proofs/D.root
      next to it (pip install opentimestamps-client), or opentimestamps.org.
  verify.py dcrtime proofs/D.dcrtime.json <root hex> [--online]
      The saved dcrtime answer names the root and a Decred transaction;
      --online re-asks time.decred.org.

Exit status 0 = everything checked out, 1 = a check failed.
"""

import csv
import hashlib
import json
import sys
import urllib.request

OTS_MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
OTS_BITCOIN_TAG = bytes.fromhex("0588960d73d71901")
OTS_PENDING_TAG = bytes.fromhex("83dfe30d2ef90c8e")
DCRTIME_URL = "https://time.decred.org:49152/v2/verify/batch"
DCRTIME_ID = "recompound-track-record"


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def leaf_hash(obj):
    return hashlib.sha256(canon(obj)).digest()


def merkle_root(hashes):
    nodes = sorted(hashes)
    if not nodes:
        return hashlib.sha256(b"").digest()
    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])
        nodes = [hashlib.sha256(nodes[i] + nodes[i + 1]).digest() for i in range(0, len(nodes), 2)]
    return nodes[0]


def verify_proof(leaf, path, root_hex):
    h = leaf
    for sib_hex, side in path:
        sib = bytes.fromhex(sib_hex)
        h = hashlib.sha256((sib + h) if side == "L" else (h + sib)).digest()
    return h.hex() == root_hex


def read_roots(path):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def root_for(roots, date):
    for r in roots:
        if r["date"] == date:
            return r
    return None


class Check:
    def __init__(self):
        self.failed = False

    def ok(self, cond, msg):
        print(("OK   " if cond else "FAIL ") + msg)
        if not cond:
            self.failed = True
        return cond


def cmd_manifest(argv):
    c = Check()
    roots = read_roots(argv[0])
    manifest = json.load(open(argv[1], encoding="utf-8"))
    proof = json.load(open(argv[2], encoding="utf-8"))
    date = manifest["date"]
    leaf = leaf_hash(manifest)
    c.ok(leaf.hex() == proof["leaf"], f"manifest hash {leaf.hex()[:16]}… is the proof's leaf")
    c.ok(verify_proof(leaf, proof["path"], proof["root"]), "inclusion path leads to the proof's root")
    row = root_for(roots, date)
    if c.ok(row is not None, f"{date} is in roots.csv"):
        c.ok(row["day_root"] == proof["root"], "proof root equals roots.csv day_root")
        c.ok((row["prev_root"] or None) == manifest["prev_root"], "manifest prev_root equals roots.csv prev_root")
        c.ok(row["n_leaves"] == manifest["n_leaves"] and row["n_accounts"] == manifest["n_accounts"], "leaf and account counts agree")
        if manifest.get("backfilled_on"):
            print(f"note {date} is backfilled: fixed on {manifest['backfilled_on']}, proven by {row['ots_file']}")
    return c


def cmd_chain(argv):
    c = Check()
    roots = read_roots(argv[0])
    prev = None
    for r in roots:
        if prev is None:
            c.ok(r["prev_root"] == "", f"{r['date']} is the first day (no prev_root)")
        else:
            c.ok(r["prev_root"] == prev["day_root"] and r["date"] > prev["date"], f"{r['date']} links to {prev['date']}")
        prev = r
    print(f"{len(roots)} days checked")
    return c


def cmd_day(argv):
    c = Check()
    manifest = json.load(open(argv[1], encoding="utf-8"))
    hashes = []
    with open(argv[0], encoding="utf-8") as f:
        for line in f:
            if line.strip():
                leaf = json.loads(line)
                if leaf["date"] != manifest["date"]:
                    c.ok(False, f"leaf dated {leaf['date']} in the {manifest['date']} file")
                hashes.append(leaf_hash(leaf))
    n_accounts = sum(1 for _ in open(argv[0], encoding="utf-8") if '"type":"account"' in _)
    hashes.append(leaf_hash(manifest))
    root = merkle_root(hashes).hex()
    c.ok(str(len(hashes)) == manifest["n_leaves"], f"{len(hashes)} leaves incl. manifest = n_leaves")
    c.ok(str(n_accounts) == manifest["n_accounts"], f"{n_accounts} account leaves = n_accounts")
    print(f"recomputed day root {root}")
    if len(argv) > 2:
        row = root_for(read_roots(argv[2]), manifest["date"])
        c.ok(row is not None and row["day_root"] == root, "recomputed root equals roots.csv day_root")
    return c


def cmd_backfill(argv):
    c = Check()
    days = read_roots(argv[0])
    expected = open(argv[1], encoding="utf-8").read().strip()
    root = merkle_root([bytes.fromhex(d["day_root"]) for d in days]).hex()
    c.ok(root == expected, f"backfill root over {len(days)} day roots equals backfill_root.txt")
    if len(argv) > 2:
        roots = read_roots(argv[2])
        for d in days:
            row = root_for(roots, d["date"])
            if not c.ok(row is not None and row["day_root"] == d["day_root"], f"{d['date']} day_root matches roots.csv"):
                break
    return c


def _read_varuint(data, pos):
    value, shift = 0, 0
    while True:
        b = data[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, pos
        shift += 7


def cmd_ots(argv):
    c = Check()
    data = open(argv[0], "rb").read()
    root_hex = argv[1]
    c.ok(data.startswith(OTS_MAGIC), "file is an OpenTimestamps proof")
    pos = len(OTS_MAGIC)
    _, pos = _read_varuint(data, pos)
    c.ok(data[pos] == 0x08, "file hash op is SHA-256")
    digest = data[pos + 1 : pos + 33]
    expected = hashlib.sha256(bytes.fromhex(root_hex)).digest()
    c.ok(digest == expected, f"proof digest = sha256(root bytes) = {expected.hex()[:16]}…")
    heights = []
    i = data.find(OTS_BITCOIN_TAG)
    while i != -1:
        _, p = _read_varuint(data, i + 8)  # payload length
        h, _ = _read_varuint(data, p)
        heights.append(h)
        i = data.find(OTS_BITCOIN_TAG, i + 8)
    if heights:
        print(f"attested in Bitcoin block(s) {sorted(set(heights))} -- confirm the block's merkle root with `ots verify` or any block explorer")
    else:
        pending = data.count(OTS_PENDING_TAG)
        print(f"not yet attested in a Bitcoin block ({pending} calendar attestation(s) pending); `ots upgrade` later")
    return c


def cmd_dcrtime(argv):
    c = Check()
    saved = json.load(open(argv[0], encoding="utf-8"))
    root_hex = argv[1]
    entry = next((d for d in saved.get("digests", []) if d.get("digest") == root_hex), None)
    if c.ok(entry is not None, "saved dcrtime answer names this root"):
        chain = entry.get("chaininformation") or {}
        anchored = bool(chain.get("chaintimestamp")) and chain.get("transaction", "0" * 64) != "0" * 64
        print(("anchored" if anchored else "pending") + f": Decred tx {chain.get('transaction')} at unix {chain.get('chaintimestamp')}")
    if "--online" in argv:
        body = json.dumps({"id": saved.get("id", DCRTIME_ID), "digests": [root_hex], "timestamps": []}).encode()
        req = urllib.request.Request(DCRTIME_URL, data=body, headers={"Content-Type": "application/json"}, method="POST")
        live = json.loads(urllib.request.urlopen(req, timeout=20).read())
        entry = next((d for d in live.get("digests", []) if d.get("digest") == root_hex), None)
        c.ok(entry is not None and entry.get("result") in (1, 2), "time.decred.org knows this root")
        if entry:
            print("live: " + json.dumps(entry.get("chaininformation"), sort_keys=True))
    return c


COMMANDS = {"manifest": cmd_manifest, "chain": cmd_chain, "day": cmd_day, "backfill": cmd_backfill, "ots": cmd_ots, "dcrtime": cmd_dcrtime}


def main(argv):
    if len(argv) < 2 or argv[0] not in COMMANDS:
        print(__doc__)
        return 2
    return 1 if COMMANDS[argv[0]](argv[1:]).failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
