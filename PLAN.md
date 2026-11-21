# cerberus build plan

**Status (2026-11-21):** phases 0 and 1 are done.
- **Phase 1** (`32d8a7a`..`8abb0a4`): every lane passes under the race detector.
- **Phase 2:** the engine and config are done (`0a56fa6`), and the CLI is being written.
- **Integration review changes:**
  - A failed signature stops the candidate fallback (`resolve.ErrSignature`).
  - `download.Head` and `Size` treat a non-2xx status as an error.
  - A null jq value counts as an absent variable.
  - `Reconcile` never deletes a `.part` file that state doesn't name. This replaces the earlier "deletes unknown parts" wording, to honor rule 5.
- **Still with the owner:**
  - the About box and the social preview, which the sandbox proxy blocks;
  - deleting the stale `wip/phase-1-2` branch, which the proxy won't delete.

Update this line whenever a phase starts or ends.

## What cerberus is

cerberus keeps a library of Linux ISOs current:
- a curated catalog sorted by use case, with a picker to choose which distros to maintain;
- scheduled checks that download each new release and verify it before keeping it;
- an optional per-distro count of old versions to keep;
- a CLI that opens on a status list: version, last check, status, size, and the totals.

It finds out what kind of host it's on:
- **Proxmox VE:** new ISOs go into a PVE storage's ISO folder, so they show up in the VM wizard.
- **Anywhere else:** it asks for a folder, suggesting one under each Samba or NFS share it finds. The folder can be changed later, and the files are moved or copied, whichever fits.

## Decisions

- **Language and platform:** Go 1.26 (the floor set by golang.org/x/sys), shipped as one static binary for linux amd64 and arm64.
- **Pinned dependencies:**
  - cobra v1.10.2
  - huh v1.0.0 (accessible mode with `WithInput` and `WithOutput`, so forms can be tested from scripts)
  - lipgloss v1.1.0 (`table`)
  - gojq v0.12.20
  - ProtonMail/go-crypto v1.5.2 (`clearsign.Decode`, `CheckDetachedSignature`)
  - go.yaml.in/yaml/v3 v3.0.6
  - golang.org/x/sys
- **License:** GPL-3.0. All the dependency licenses are compatible.
- **Release assets:** `cerberus-linux-amd64`, `cerberus-linux-arm64` and `SHA256SUMS`, which the README's install command relies on.
- **v1 scope:**
  - catalog, sync, status screen, retention, Proxmox registration, host detection, and changing the ISO location;
  - signature verification;
  - `latest/` aliases, in directory mode only;
  - ntfy alerts;
  - a weekly CI catalog check.
- **Out of v1:** the darwin build, a generic webhook, and special handling for TrueNAS, Unraid, Synology and OMV, which are treated as plain Linux.
- **Proxmox registration:** write the ISO into the storage's ISO folder. Facts confirmed in pve-storage:
  - The listing is `<$path/*>`: flat, it follows symlinks, it counts only `.iso` and `.img`, and it ignores dotfiles and `.part` files.
  - `pvesm path` resolves files that don't exist yet and honors `content-dirs`, but never mounts anything.
  - PVE's delete never checks whether a VM uses the ISO.
- **Changing location:** use rename on the same filesystem. Otherwise go one file at a time: copy, verify against the stored sha256, rename, delete the source. An interrupted move resumes. There's no rsync dependency.
- **Repo About box:** the sandbox proxy refuses repo-settings writes, so the owner sets the description and topics.

## Behavior

**First run** (no config yet):
1. Detect the host.
2. Choose where ISOs go.
   - On PVE: pick a storage that's enabled, active and takes ISOs. `local` is the default, with a warning under 50 GB free.
   - Elsewhere: ask for the ISO folder, offering the suggestions, and create it on confirm.
3. Pick distros from a multi-select grouped by use case.
4. Set the default number of versions to keep (1).
5. Offer the schedule, then the ntfy topic file, then a first sync.

**Status screen** (when a config exists):
- A header with the host, mode, location and next run.
- One row per distro: name, version on disk, last check, status, size and versions kept.
- A footer with three numbers: space cerberus manages, other files in the folder, and free space with the reserve.

On a TTY, a menu follows: Sync now, Check only, Choose distros, Settings, Quit. When piped, or with `--plain`, it prints and exits. Every interactive step also has flags.

| Command | Does |
|---|---|
| `cerberus [status]` | status screen, plus the menu on a TTY |
| `init` | first-run setup; `--dir`, `--storage`, `--select`, `--keep`, `--schedule`, `--yes` |
| `select`, `add`, `remove [--delete-files]` | choose distros |
| `keep <id> <n>`, `pin <id> [prefix]` | per-distro retention and version pin |
| `sync [--dry-run] [ids]`, `check` | update now, or report only |
| `catalog [--category]`, `catalog check [ids]` | browse; resolve entries live, exit 1 on any failure |
| `location set <dir>` or `--storage <id>`, `[--files move\|copy\|leave] [--take-over]` | change where ISOs live |
| `schedule install [--at HH:MM]`, `remove`, `status` | timer |
| `settings` | location, keep, pins, ntfy, aliases, schedule |

**Sync, per distro:**
1. **Resolve** the latest version, honoring the pin and any excludes. If a later step fails, the resolver falls back to the next candidate.
2. **Compare** it with the newest kept version that matches the pin.
   - Same: done.
   - Lower: report "upstream regressed" and stop.
   - Higher: continue.
3. **Preflight.** In Proxmox mode, PVE must still report the storage as enabled and active. Free space must cover the ISO plus the reserve (10% of the filesystem, at least 10 GB).
4. **Download** to `<file>.part`, resuming with Range and If-Range. Record the partial in state before the first byte. A resume always starts again from the catalog URL, so expiring mirror tokens don't matter.
5. **Verify** the hash, plus the ISO signature if the entry declares one.
6. **Journal and rename.**
   1. Record a `pending` entry in state.
   2. Rename the file into place, but never over a file cerberus didn't write:
      - an identical existing file is adopted and never deleted;
      - a different one fails the update.
   3. Clear the `pending` entry.
7. **Alias:** update the `latest/` symlink (directory mode).
8. **Prune** versions beyond the keep count, by when they were added. Files a VM references, and adopted files, are never deleted.
9. **Save** state.

**Reconcile:** every command that takes the lock first reconciles. It finishes or rolls back a `pending` placement, and deletes partials of distros that are no longer selected. It never touches a file that state doesn't name, so another program's `.part` files are safe.

Running out of disk space stops the whole run. Resolving runs 8 at a time, and downloads run one at a time.

**Layouts:**
- **Directory mode:** `<dir>/<id>/<upstream name>`, plus `<dir>/latest/<id>.iso` symlinks.
- **Proxmox mode:** flat in the storage's ISO folder, with no aliases. They'd show up as duplicates in the VM wizard.
- **File names:** every name must contain its version. An entry whose upstream name lacks it sets a `filename` template.

**Host detection** takes a root path, so tests use a fake tree.

| Signal | Host | Default location | Scheduler |
|---|---|---|---|
| `/etc/pve` folder plus `pvesh` | Proxmox VE (`pveversion`) | Proxmox mode | systemd timer |
| shares in `/etc/samba/smb.conf` or `/etc/exports` | file server | directory mode, offering `<share path>/isos` for each share | systemd timer |
| anything else | Linux (`/etc/os-release`) | `/srv/isos` | systemd; without it, `/etc/cron.d`; else printed steps |

**Proxmox details:**
- **Finding storages:** `pvesh get /nodes/<node>/storage --content iso --enabled 1 --output-format json`, requiring `active: 1`. This runs again before every write, because an unmounted NFS storage would otherwise send ISOs to the boot disk.
- **ISO folder:** `dirname $(pvesm path <storage>:iso/cerberus-probe.iso)`.
- **In-use guard:** scan `/etc/pve/nodes/*/qemu-server/*.conf` for `<storage>:iso/<file>`, snapshot sections included. Prune skips those files and shows "kept: in use by VM 105". Changing storage copies those files instead of moving them.
- **Requirements:** Proxmox mode requires root. A permission error on NFS names root_squash as the likely cause.

**Schedule:**
- Service: oneshot `cerberus sync --quiet`, with `Nice=10` and `IOSchedulingClass=idle`.
- Timer: `OnCalendar=*-*-* 04:30`, `RandomizedDelaySec=1h`, `Persistent=true`.
- `--at` changes the time.

**ntfy:**
- A POST goes to `<server>/<topic>`. The topic is read at send time from a mode-0600 file (default `/etc/cerberus/ntfy-topic`), with a warning if the file is readable by others.
- A message goes out only when a sync updates or fails something.

**Files:**
- **Config:** `/etc/cerberus/config.yaml` as root, else `$XDG_CONFIG_HOME/cerberus/`.
- **State and lock:** `/var/lib/cerberus/` as root, else `$XDG_STATE_HOME/cerberus/`. State is written atomically.
- **Owner marker:** `.cerberus-owner` in the library root holds the host's machine-id. A second host refuses to manage the same library unless given `--take-over`.
- **Catalog:** embedded, with overrides in `/etc/cerberus/catalog.d/*.yaml`.

## Rules (shall)

1. Shall fetch only over HTTPS, including every redirect.
2. Shall verify every ISO against a sha256 or sha512 from the distro's own published source before the file appears in the library. A mismatch deletes the download and keeps the previous version.
3. Where an entry declares a signature, shall verify it against the entry's pinned fingerprints. Any signature block from an allowed key passes, and a failure counts as a failed update. Shall match clearsigned documents only inside the signed text.
4. Shall accept a resolved name only if it's a plain base name matching `^[A-Za-z0-9][A-Za-z0-9._+~-]*\.iso$`.
5. Shall never overwrite or delete a file it didn't write, never delete a file a PVE VM config references, and never prune before the new version verifies.
6. Shall write to a Proxmox storage only while PVE reports it enabled and active.
7. Shall keep the free-space reserve, and shall stop the run when the disk fills.
8. Shall never replace a kept version with a lower upstream version.
9. Shall keep the ntfy topic out of config, logs and the repo.
10. Shall run one sync at a time (flock), with one host per library (owner marker).

## Architecture

The exported types and signatures in each package are the contract between build lanes. Its doc comments are the spec.

| Package | Owns |
|---|---|
| `cmd/cerberus` | cobra commands, huh forms (accessible mode in tests), lipgloss status table |
| `internal/catalog` | the schema, embedded `catalog/*.yaml` and `catalog/keys/*.asc`, overrides, lint, `Render` and `ValidFilename` |
| `internal/resolve` | the step engine, version ordering, pins, excludes, candidate fallback |
| `internal/verify` | checksum parsing (GNU, BSD, bare, clearsigned) and OpenPGP checks against a fingerprint allowlist |
| `internal/download` | HTTPS-only client, Range and If-Range resume into `.part`, free-space reserve |
| `internal/library` | state with the `pending` journal, layouts, aliases, adoption, prune, relocate, lock, owner marker |
| `internal/host` | detection, PVE storages and VM references, scheduler install, remove and status |
| `internal/notify` | ntfy |
| `internal/engine` | sync orchestration, reconcile, the per-run report (phase 2) |
| `internal/config` | config file and paths (phase 2) |

## Catalog format

Ubuntu Server LTS resolves to 26.04.1 against the live feed:

```yaml
- id: ubuntu-server-lts
  name: Ubuntu Server LTS
  category: server
  arch: {amd64: amd64}
  steps:
    - fetch: https://releases.ubuntu.com/
      match: 'href="(?P<version>\d[02468]\.04(?:\.\d+)?)/"'
    - fetch: https://releases.ubuntu.com/{version}/SHA256SUMS
      match: '(?m)^(?P<sha256>[0-9a-f]{64}) \*(?P<file>ubuntu-(?P<version>[\d.]+)-live-server-{arch}\.iso)$'
  url: https://releases.ubuntu.com/{version}/{file}
  signature: {type: detached-checksums, url: 'https://releases.ubuntu.com/{version}/SHA256SUMS.gpg'}
  keys: [ubuntu-cdimage]
  fingerprints: [<confirmed in phase 3>]
```

Each step fetches a URL and extracts candidates with either `match:` (a regex) or `jq:` (for JSON and YAML feeds, with variables as `$name`). Every named capture becomes a variable for later steps.

Step options:
- **`from:`** chooses what the step reads: `body` (the default), `final-url`, `header:<Name>`, or `last-modified`.
- **`exclude:`** drops candidates such as nightlies and betas.
- **`clearsigned: true`** marks a step whose document is clearsigned.

Entry fields:
- **`checksum:`** fetches a sidecar file.
- **`signature:`** is `detached-checksums` or `detached-iso`.
- **`filename:`** is a template that must contain `{version}`.

With a pin, every step that captures `version` drops candidates that don't match. If a later step fails, the resolver retries with the next candidate, up to 3.

## Build phases (each ends at its check)

0. **Bootstrap, README and repo setup.**
   - Module, `LICENSE`, `PLAN.md`, `CLAUDE.md`, and the contract skeleton.
   - The README and its SVG assets.
   - A social-preview PNG.

   *Check:*
   - `go build ./...`, `go vet ./...` and the verify tests pass.
   - Every SVG renders correctly in Chromium in both themes.
   - The pushed repo shows the README.
   - GitHub detects the license as GPL-3.0.

1. **Packages, in four parallel lanes:** resolve and catalog; verify and download; library; host and notify. Each lane owns its package folder, adds unit tests, and leaves `go.mod` and every other package alone.

   *Check:* each `go test ./internal/<pkg>/...` passes, and the diffs keep to the contract.

2. **Engine, config, CLI and end-to-end tests.** The tests use a fake HTTPS mirror, plus a fake PVE tree with fake `pvesh` and `pvesm`.

   *Check:* `go test ./...` passes and covers:
   - a first download, and a re-sync that downloads nothing;
   - keep=1 pruning and keep=2 retaining;
   - a bad checksum, rejected with the old version kept;
   - resume, including an If-Range mismatch that restarts the download;
   - a bad signature, an unsigned line appended to a clearsigned file, and a checksum file with two signature blocks;
   - the flat Proxmox layout, with a VM-referenced ISO surviving prune;
   - an inactive storage, which makes the sync refuse with nothing written;
   - a hand-uploaded file with the same name: adopted when identical, a failed update when different;
   - a crash between the rename and saving state, reconciled on the next run;
   - free space below the reserve;
   - an upstream regression, with no download;
   - candidate fallback;
   - relocating by rename, by forced copy, interrupted then resumed, and in copy and leave modes;
   - a file name containing `../`, rejected;
   - a second sync blocked by the lock, and another host refused by the owner marker;
   - a non-root run using XDG paths, and Proxmox mode as non-root refused clearly;
   - one ntfy summary arriving at a fake server.

3. **Catalog:** about 6 agents, one per use-case group, write the entries. An independent agent confirms every pinned fingerprint against the distro's official HTTPS page. Leads:
   - NixOS: the channel comes from the nix-releases S3 listing.
   - CachyOS: `mirror.cachyos.org/ISO/desktop/<YYMMDD>/`.
   - SystemRescue: checksums and `.asc` from system-rescue.org.
   - TrueNAS: excludes for nightlies and betas.
   - Proxmox: `SHA256SUMS.asc` carries two signatures.
   - Bazzite: a version from `last-modified`.

   *Check:*
   - `cerberus catalog check` resolves every non-GitHub entry live.
   - Every fingerprint cites its source.
   - Entries that can't be made reliable are dropped and listed.

4. **Real run and packaging.**

   *Check:*
   - Alpine virt and Debian netinst download and verify for real in directory mode, including Debian's signature.
   - The status screen is correct, and a second sync downloads nothing.
   - `location set` moves both ISOs.
   - The units pass `systemd-analyze verify`.
   - These workflows exist, each with `concurrency: cancel-in-progress`:
     - CI: test, gofmt and vet;
     - the weekly `catalog check`;
     - a release on tag that publishes the three release assets.

5. **Docs re-check.**
   - Redraw the README's status mock from real output.
   - Regenerate the catalog table from `cerberus catalog`.
   - Drop the pre-release note at v0.1.

   *Check:* every command shown exists in `--help`, and every link and path resolves.

6. **Independent review:** separate reviewers cover data safety, security, and Proxmox and host integration with CLI UX and README accuracy. Their fixes get applied.

   *Check:* every finding is fixed or answered here, and `go test ./...` passes.
