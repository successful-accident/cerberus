# cerberus: instructions for Claude sessions

cerberus is a Go CLI that keeps a library of Linux ISOs current, either in a Proxmox VE storage or in a folder on any Linux file server. `PLAN.md` holds the design, the safety rules, the build phases and the dated status line.

## Start of every session

1. Read `PLAN.md`'s status line and the phase it names. Run `git status`, and summarize anything uncommitted before you change it.
2. Tell the owner, in a few lines, which phase is next and what it needs from them.

## Rules

- **Public repo.** Never commit anything specific to the owner's machines: host names, addresses, storage or pool layouts, schedules, ntfy topics, tokens, or the owner's name. Examples use generic values (`pve`, `local`, `/srv/isos`).
- **Safety rules.** The "Rules (shall)" in `PLAN.md` are requirements. A change that weakens one needs the owner's OK, and a test that proves the rule still holds.
- **Contract.** Exported names and signatures in `internal/*` are the contract between packages, and their doc comments are the spec. Change one only together with every caller, and update the doc comment in the same commit.
- **Before every commit:** `gofmt -l .` prints nothing, and `go vet ./...` and `go test ./...` pass.
- **Catalog.**
  - Every entry passes `go run ./cmd/cerberus catalog check <id>`.
  - Every pinned fingerprint cites its official source in the entry's `notes`.
  - An entry that can't be checked reliably is dropped, not shipped flaky.
- **Releases.** Release assets keep the names the README's install command uses: `cerberus-linux-amd64`, `cerberus-linux-arm64`, `SHA256SUMS`.
- **Style.** American English. Docs are direct and lead with the answer.

## Environment notes (cloud sandbox)

- github.com and api.github.com are blocked except for repos attached to the session. Catalog entries hosted on GitHub (Talos, netboot.xyz, Rescuezilla, ShredOS) can't be checked from the sandbox, so the weekly CI job checks them.
- The sandbox proxy refuses repo-settings writes (description, topics, social preview). The owner sets those.
- gnu.org sometimes resets connections. Retry with `curl --retry`.

## Lessons

- 2026-11-21: `pvesm path` builds a path without mounting anything, and PVE's ISO delete doesn't check VM references. Both are confirmed in the pve-storage source, and both are why cerberus checks storage state and VM configs itself.

## File map

| Path | What |
|---|---|
| `PLAN.md` | design, rules, build phases, status |
| `README.md`, `assets/` | the front page and its SVGs (dark and light pairs) |
| `embed.go` | embeds `catalog/` into the binary |
| `catalog/*.yaml`, `catalog/keys/*.asc` | the distro catalog and the signing keys it pins |
| `cmd/cerberus/` | the CLI |
| `internal/catalog` | entry schema, loading, lint, template rendering |
| `internal/resolve` | runs an entry's steps to find the newest release |
| `internal/verify` | checksums and OpenPGP signatures |
| `internal/download` | HTTPS-only client, resumable downloads, free space |
| `internal/library` | files on disk, state, journal, prune, relocate, lock |
| `internal/host` | host detection, Proxmox storages, schedule |
| `internal/notify` | ntfy alerts |
| `LICENSE` | GPL-3.0 |
