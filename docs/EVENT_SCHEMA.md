<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# Event schema

Wardyn emits JSON in three places. This page is the contract for all of them.

| surface | what it holds | who reads it |
| --- | --- | --- |
| `--format json` on stdout | **every** observed event, allow rows included | a log shipper, a SIEM, `jq` |
| the audit log (`--audit`) | only `warn` and `block` — the security record | an operator, after the fact |
| the denial receipt (`--denials`) | only what the kernel really denied, this run | the watched agent itself |

The stream and the audit log share **one record builder**, so the fields they
have in common cannot drift apart; a test asserts a log line is byte-identical
to what that builder produces. The stream then adds two fields (`enforceable`,
`excepted`) that only mean something for a row which might be an allow. The
receipt is deliberately different — it is written for an LLM, not a parser, and
carries a prose `note`.

## Compatibility

`schema_version` is on **every record**, not on a header. An audit log is
appended to across runs and read with `grep`, `tail -f` and `jq -c`, so a
consumer routinely holds one line with no idea what came before it. A header
would be correct exactly once per file and useless to everyone downstream of a
pipe.

The current version is **1**. It is bumped only for a change a consumer could
not absorb:

| change | bumps? |
| --- | --- |
| a new field appears | **no** — ignore fields you do not know |
| a new `event` or `action` value appears | **no** — treat unknown values as opaque |
| a field is removed, renamed, or its meaning changes | **yes** |
| a field's type changes | **yes** |

Write consumers accordingly: match on the fields you need, ignore the rest, and
check `schema_version` only to refuse a *future* major you were not written for.

## The record

```json
{
  "schema_version": 1,
  "ts": "2026-09-08T13:41:21.072Z",
  "pid": 2140,
  "comm": "cat",
  "event": "open",
  "action": "block",
  "enforced": true,
  "source": "observed",
  "detail": "/home/kadir/wardyn-demo/.env",
  "rule": "**/.env",
  "matched_key": "name=.env",
  "enforceable": true,
  "excepted": false
}
```

| field | type | meaning |
| --- | --- | --- |
| `schema_version` | int | see above |
| `ts` | RFC 3339, ms, UTC | when wardyn processed the event, which can lag the syscall by a few ms |
| `pid` | int | the tgid, **in the initial pid namespace** — inside a container this is not the pid the agent sees |
| `comm` | string | the kernel's 15-char process name, not a path |
| `event` | string | `exec`, `open`, `connect`, `delete`, `create`, or `notice` |
| `action` | string | `allow`, `warn`, `block` — the policy's verdict |
| `enforced` | bool | whether the kernel **actually denied it**. See below |
| `source` | string | `kernel` or `observed`. See below |
| `detail` | string | the path or `address:port` |
| `rule` | string | the policy line that fired, or `kernel:<key>` |
| `matched_key` | string or null | the kernel key the decision was made on |
| `enforceable` | bool | stream only — whether a block here *could* be enforced |
| `excepted` | bool | stream only — an operator exception is covering this |

The audit log carries every field except the last two, which only make sense for
a row that might be an allow.

### `action` is not `enforced`

`action` is what the policy says; `enforced` is what the kernel did. They differ
in three real cases, and conflating them is the mistake this schema is shaped to
prevent:

- a `warn` is never enforced — it is a flag;
- a `block` on a rule that reduces to no kernel key is reported with
  `enforced: false` (the feed shows it as `block~`), because wardyn will not
  claim a denial it did not make;
- under observe mode (no `--enforce`) nothing is enforced at all.

**Count denials with `enforced == true`, never with `action == "block"`.**

### `source` says who is speaking

- `kernel` — the enforcement hook reported its own decision, naming the key it
  matched. This is proof.
- `observed` — userspace saw a syscall and applied the policy mirror to it. This
  is a prediction, and it is right almost always: it is derived from the path the
  syscall passed, which for a relative path, a symlink, or a dirfd-relative open
  describes something other than the object the kernel resolved.

A `kernel` row is never a duplicate of an `observed` one; wardyn suppresses the
confirmation when a prediction already covered it.

### `matched_key` is what to aggregate by

`rule` is policy *text* and several rules can share a kernel key. `matched_key`
is the key that actually fired — the unit an approve-once exception operates at,
and the same string `--dry-run` prints. Group by it, not by `rule`.

It is `null` for a `warn`, which denies nothing and so matches no key. That is a
meaningful null: the record is a flag, not a decision.

Shapes you will see: `name=.env`, `name=.aws/credentials` (a two-segment key),
`dir=.ssh`, `ino=dev 8:48 ino 494378` (an identity rule), `ip=1.1.1.1`,
`ip=1.1.1.1:25` (a port rule), `delete:dir-ino=…` (a lifecycle denial, wrapping
the key it narrows).

## The stream header

One record, first, before any event:

```json
{"schema_version": 1, "wardyn": "event-stream", "ts": "…", "enforcing": true}
```

`wardyn` is there so a mixed log can be filtered. Everything else it says is
repeated per event, so a consumer that starts reading mid-pipe is not required
to have seen it.

## `notice` rows

Stream only. Wardyn talking about itself — an LSM hook that failed to attach, an
exception the operator granted, a warning about the policy. They carry `event`,
`ts`, `schema_version` and `detail`, and nothing else.

They are marked rather than dropped because a consumer reconstructing *what the
tool was capable of* at a given moment needs them. One that only wants agent
behaviour can filter them out on the `event` field.

## Worked examples

```bash
# every denial the kernel actually made
wardyn --enforce --format json run -- npm install \
  | jq -c 'select(.enforced == true)'

# which keys fire most — the input to tightening a policy
wardyn --enforce --format json run -- npm install \
  | jq -r 'select(.enforced) | .matched_key' | sort | uniq -c | sort -rn

# blocks the kernel could NOT enforce: rules that look active and are not
wardyn --enforce --format json run -- npm install \
  | jq -c 'select(.action == "block" and .enforceable == false)'

# egress only, as a destination list
wardyn --format json run -- npm install \
  | jq -r 'select(.event == "connect") | .detail' | sort -u
```

## What the stream does not do

- **It is not lossless under load.** The kernel ring buffer is finite; a burst
  that overruns it drops events, and wardyn counts the drops and reports them at
  exit rather than pretending the run was clean. A dropped event is absent from
  the stream *and* the audit log.
- **It has no delivery guarantee.** Output goes to stdout. If the reader is
  slower than the agent, the pipe fills and wardyn blocks on the write; if the
  reader goes away, output ends. There is no buffering-to-disk, no retry.
- **It is not a metrics endpoint.** Counters are derivable from the stream, but
  wardyn exposes none itself. See the roadmap in
  [`COMPARISON.md`](./COMPARISON.md).
