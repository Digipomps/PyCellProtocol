# Upstream Sync

PyCellProtocol tracks Swift parity against the upstream `Digipomps/CellProtocol`
and `Digipomps/CellScaffold` repositories.

The `.github/workflows/upstream-sync.yml` workflow runs in three cases:

- `repository_dispatch` from `CellProtocol` or `CellScaffold`
- manual `workflow_dispatch`
- hourly schedule as a backstop

The workflow checks out the upstream repositories, installs PyCellProtocol, runs
the Python test suite, runs the Swift bridge parity smoke against the checked out
`CellProtocol`, and records the tested upstream commit heads in
`upstream-lock.json`.

## Required Secrets

`CellProtocol` is public, so the default `GITHUB_TOKEN` can read it.

`CellScaffold` is private. Configure `CELLPROTOCOL_SYNC_TOKEN` in
`Digipomps/PyCellProtocol` with read access to `Digipomps/CellScaffold` and write
access to `Digipomps/PyCellProtocol` if CellScaffold parity should run in CI.
The same token is also used for private Digipomps SwiftPM dependencies required
by the Swift bridge smoke. Without it, the workflow still runs Python parity and
updates public upstream state, but skips CellScaffold and Swift smoke steps.

To get immediate upstream push triggers, configure `PYCELLPROTOCOL_DISPATCH_TOKEN`
in both upstream repositories. The token must be able to call
`repos/Digipomps/PyCellProtocol/dispatches`.

Without the dispatch token, the hourly schedule still catches upstream changes.
