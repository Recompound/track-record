# Recompound track record — anchored daily

This repository holds the public half of Recompound's anchored track record:
one Merkle root per calendar day over every client account's end-of-day
portfolio value, stamped on the Bitcoin and Decred blockchains, so that no
past day can be rewritten after the fact — by Recompound or anyone else.

Nothing here identifies a client. The per-account records (the "leaves")
stay with Recompound; what is published is their Merkle root, a manifest of
aggregates per day, the proof that the manifest is inside the root, and the
chain attestations.

## What this proves, and what it does not

Anchoring proves that a record **existed by a date and has not changed since**.
It does **not** prove that the record was true or complete. Those are separate
layers: a written composite policy that fixes the selection rules before the
numbers, reconciliation against broker and KSEI records, and an outside
verifier. Until those exist, read these files as "this is what Recompound's
system recorded, fixed in time", not as audited performance.

## Important disclosures

Recompound is a platform operated by PT Solusi Brilian Digital Nusantara
("PT SBDN"). PT SBDN is not a licensed investment adviser. Its scope of
activity is limited to operational support for investment advisory activity,
and it is in the process of applying to Otoritas Jasa Keuangan (OJK) for
registration as a Penasihat Investasi.

Investment recommendations are issued by Budi Ryan, an investment adviser
individually licensed and supervised by OJK (Kep-1/PM.021/PI/2025, February
2025). Every Recompound client is a client of Budi Ryan in that capacity.

- **The series starts in February 2025**, the month of that individual
  licence. Some accounts on the platform are older; their earlier history is
  not published and is not part of this record.
- **The history from February 2025 to the go-live date was anchored in one
  batch** (`BACKFILL/`). Every manifest in that range carries
  `backfilled_on`: the date on which this version of the past was fixed. It
  proves nothing about those days before that date.
- Recompound does not hold client funds and does not place orders. Every
  account stays at the client's own broker, in the client's own name. Each
  account's `index_val` is its own unit-price series (100 at the account's
  start; deposits and withdrawals enter at that day's index), so it is
  time-weighted per account, not a composite return.
- Past performance does not guarantee future results. Individual client
  returns differ according to when each client acts on a recommendation
  within the execution window.
- Nothing here is an offer or solicitation to buy or sell any security.
  Investing carries risk, including the loss of principal.

## Files

| path | what |
|---|---|
| `roots.csv` | one line per day: `date,day_root,n_leaves,n_accounts,prev_root,generated_at,ots_file,dcrtime_file` |
| `manifests/YYYY-MM-DD.json` | the day's public aggregates and the link to the previous day's root; itself a leaf in the tree |
| `manifests/YYYY-MM-DD.proof.json` | Merkle inclusion proof of that manifest in the day root |
| `proofs/YYYY-MM-DD.root` | the 32 raw bytes of the day root |
| `proofs/YYYY-MM-DD.root.ots` | OpenTimestamps proof (Bitcoin); upgraded in place once the block exists |
| `proofs/YYYY-MM-DD.dcrtime.json` | dcrtime answer (Decred): the anchoring transaction and chain timestamp |
| `BACKFILL/` | the batch-anchored history: `days.csv`, the backfill root and its two proofs |
| `tools/verify.py` | the checker below; Python 3, standard library only |

Each manifest's `agg` covers **active** accounts that day (`agg_scope` says
exactly which); `n_accounts` counts every account with a record that day,
including suspended and churned ones, which stay in the private leaves so the
record carries no survivorship bias. `n_corrections` counts append-only
correction leaves: a published day is never edited; a late dividend or a
broker mismatch is recorded as a new leaf on the day it is discovered.

## Check it yourself

```bash
python3 tools/verify.py chain roots.csv
python3 tools/verify.py manifest roots.csv manifests/2026-11-03.json manifests/2026-11-03.proof.json
python3 tools/verify.py ots proofs/2026-11-03.root.ots <day_root from roots.csv>
python3 tools/verify.py dcrtime proofs/2026-11-03.dcrtime.json <day_root> --online
python3 tools/verify.py backfill BACKFILL/days.csv BACKFILL/backfill_root.txt roots.csv
```

Full Bitcoin verification: `pip install opentimestamps-client`, then
`ots verify proofs/2026-11-03.root.ots` with `proofs/2026-11-03.root` beside it
(needs a Bitcoin node), or drop the `.ots` file on https://opentimestamps.org.
For Decred, `--online` re-asks https://time.decred.org for the same digest.

The hashing rules (canonical JSON, SHA-256 leaves, sorted-pair Merkle tree,
all numbers carried as strings) are short enough to reimplement in any
language; `tools/verify.py` is the reference in about 200 lines. A verifier
given the private leaves under NDA recomputes every day root with
`verify.py day`.

## Contact

Questions about the method or requests for verifier access: support@recompound.id.
