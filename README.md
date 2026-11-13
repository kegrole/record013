# lockcheck

`lockcheck` verifies integrity hashes declared in npm, pip and Go lock files using only the Python standard library. Each lock entry is checked against a real fixture file or module directory under `fixtures/packages/`.

## Usage

```bash
python -m lockcheck.cli --lock demo/locks --out out/report.json
```

`--lock` accepts a file or directory and can be repeated. When it is a directory, the tool scans supported `.json`, `.lock` and `.sum` files. The report is written to `--out`, and stdout gets one summary line containing total, ok, mismatch, missing and multi-version counts.

The optional `--fixtures` option overrides the default package root, `fixtures/packages`.

## Supported Lock Formats

### npm `package-lock.json`

- `lockfileVersion` 3 uses the `packages` layout and keys such as `node_modules/<name>`.
- `lockfileVersion` 2 uses the recursive `dependencies` layout.
- Package names are read from a node's `name` field when present; otherwise they are derived from the `node_modules/` path.
- `integrity` values use the form `<algorithm>-<standard-base64>`, for example `sha512-<base64>`.
- Multiple space-separated integrity values are candidates. Each candidate is checked and any matching candidate makes the entry `ok`; `computed_hash` uses the matching algorithm.
- Supported npm algorithms are `sha256`, `sha512` and `md5`; npm hashes always use base64.

### pip `requirements.lock`

Requirements use one entry per line:

```text
package==version --hash=sha256:<hex>
```

- `--hash` values use the form `<algorithm>:<hex>`.
- Multiple `--hash` tokens are supported; any valid candidate makes the entry `ok`.
- Supported algorithms are `sha256`, `sha512` and `md5`; pip hashes use hex encoding.
- Blank lines and lines beginning with `#` are ignored.

### Go `go.sum`

Go entries use the standard two-record shape:

```text
module@version version h1:<base64>
module@version/go.mod version h1:<base64>
```

The two lines are merged into one report entry. The first hash covers every file in the module directory; the second hash covers only `go.mod`. They are expected to differ and are not treated as two versions.

## Hash Encodings

| Ecosystem | Declared form | Encoding |
| --- | --- | --- |
| npm | `sha256-...`, `sha512-...`, `md5-...` | standard base64 with padding |
| pip | `--hash=sha256:...`, `--hash=sha512:...`, `--hash=md5:...` | lowercase hex |
| Go | `h1:...` | standard base64 with padding |

The implementation can compute `sha256`, `sha512` and `md5`, and can encode either raw digest as hex or standard base64.

## Go Dirhash Rules

A Go module hash is computed in two stages:

1. Hash each module file with SHA-256 and write one line as:

   ```text
   <sha256hex>  <module>@<version>/<file-path>
   ```

2. Sort those lines by file path, concatenate them in that order, hash the complete string again with SHA-256, base64-encode the result, and prefix it with `h1:`.

For a `go.mod` record, the same algorithm is applied to a file list containing only `go.mod`.

The required fixture `example.com/m@v1.0.0` contains exactly:

- `example.com/m@v1.0.0/go.mod` with `module example.com/m\n`
- `example.com/m@v1.0.0/pkg.go` with `package m\n`

Its directory and go.mod hashes are respectively:

- `h1:CxMCafGH3he2YUx8mpZWYG7zDCQfm9DQ8mJgx+y/ThM=`
- `h1:yJwNngL0tCKlmRg8yireic46hRGohEbhwD/WSE0Ax3I=`

## Go Module Path Escaping

Go escapes every uppercase ASCII letter in a module path as `!` followed by the lowercase letter. For example, `Example.com/Mod` is written in `go.sum` as `!example.com/!mod`.

The parser restores the escaped name before grouping entries and resolving fixture paths. Thus `!example.com/!mod@v1.2.3` is compared against the fixture directory `fixtures/packages/go/Example.com/Mod@v1.2.3` and is reported under the unescaped name `Example.com/Mod`.

## Fixture Layout

- npm content: `fixtures/packages/npm/<safe-name>/<version>.tgz`, where `/` in scoped names becomes `__`.
- pip content: `fixtures/packages/pip/<name>/<version>.<suffix>`.
- Go content: `fixtures/packages/go/<module>@<version>/`, containing the module's files.

The npm and pip `shared-blob` fixtures contain identical bytes, so their differently encoded hashes decode to the same SHA digest.

## Report Fields And Statuses

Every record contains exactly these seven fields:

- `name`: package or module name.
- `version`: package version, or a sorted list of both versions for `multi_version`.
- `declared_hash`: hash value found in the lock file, or `null` when absent.
- `computed_hash`: hash recomputed from the fixture.
- `status`: one of `ok`, `mismatch`, `missing`, or `multi_version`.
- `file`: source lock file path.
- `line`: one-based line number for the entry.

Status meanings:

- `ok`: all declared hashes match the recomputed hashes.
- `mismatch`: a declared hash exists but does not match the fixture.
- `missing`: the lock entry has no required declared hash, or a required Go h1 slot is absent.
- `multi_version`: the same package or module has more than one version in one lock file. The record lists both versions and no separate ordinary records are emitted for that package.

## Tests

```bash
python -m unittest test_lockcheck -v
```

The tests cover the four demo lock files, the exact 12 injected issues, the required Go dirhash vectors, uppercase module-path escaping, multi-candidate npm integrity, SHA-256/MD5 coverage, report field completeness and regeneration into temporary lock files.
