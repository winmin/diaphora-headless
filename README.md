# diaphora-headless

Headless binary diffing CLI powered by [Diaphora](https://github.com/joxeankoret/diaphora) and Hex-Rays **IDALib**.

Export two binaries (e.g. before/after a security patch) to Diaphora SQLite databases without opening the IDA GUI, run Diaphora's matching engine, and get a concise summary of modified, added, and removed functions. Works standalone from the terminal and pairs well with [`ida-headless-mcp`](https://github.com/mrexodia/ida-pro-mcp) for follow-up reverse engineering.

## Requirements

- **IDA Pro 9.0+** with IDALib and Hex-Rays decompiler (IDA Free is not supported). Tested on IDA 9.3 and 9.5.
- **Python 3.11+**
- **Diaphora 3.x** source tree:
  ```bash
  git clone https://github.com/joxeankoret/diaphora.git ~/diaphora
  ```

## Installation

Using `uv` (recommended):

```bash
git clone https://github.com/winmin/diaphora-headless.git
cd diaphora-headless
uv tool install .
```

Or with `pipx`:

```bash
pipx install .
```

Or run directly from the repo without installing:

```bash
uv run diaphora-headless --help
```

## Configuration

`diaphora-headless` locates dependencies via environment variables, with sensible defaults:

| Variable | Purpose | Default search behavior |
|---|---|---|
| `DIAPHORA_DIR` | Path to the Diaphora source tree (containing `diaphora.py`) | Checks `DIAPHORA_DIR`, `./vendor/diaphora`, `../diaphora`, `~/Desktop/diaphora`, `~/diaphora`, `/opt/diaphora`, `/usr/local/share/diaphora` |
| `IDADIR` | Path to your IDA Pro installation | Uses `IDADIR` if set; otherwise `idapro` reads `~/.idapro/ida-config.json` (or `%APPDATA%\Hex-Rays\IDA Pro\ida-config.json` on Windows) |

### Optional: IDALib processor-name fallback patch

On some IDA/IDALib versions, `idaapi.get_idp_name()` may return `None` during Diaphora's `save_callgraph`. A small fallback patch for Diaphora 3.5.0 is included:

```bash
git -C ~/diaphora apply /path/to/diaphora-headless/patches/diaphora-3.5.0-idalib.patch
```

## Usage

### 1. One-step export, diff, and summary

```bash
diaphora-headless run before/ntdll.dll after/ntdll.dll -d ./diff_out
```

Outputs (when both binaries share the same filename, parent directory names are used to disambiguate):

```text
diff_out/
├── before_ntdll.dll.sqlite
├── after_ntdll.dll.sqlite
└── before_vs_after_ntdll.diaphora
```

Summary output:

```text
=== Diaphora Summary ===
BEFORE (main): /.../diff_out/before_ntdll.dll.sqlite
AFTER  (diff): /.../diff_out/after_ntdll.dll.sqlite
Best (equal):        4380
Partial (modified?): 8
Unreliable:          0
Only in BEFORE:      0
Only in AFTER (new): 5

--- Top changed functions (lowest similarity first, limit 25) ---
  0.890  PssNtCaptureSnapshot (0x1800cbe10) -> PssNtCaptureSnapshot (0x180119f20)  [Perfect match, same name]
  0.950  PsspDuplicateSnapshotLocalToRemote (0x1800ccc70) -> PsspDuplicateSnapshotLocalToRemote (0x18011a3e0)  [Perfect match, same name]
```

### 2. Step-by-step

```bash
# Export a single binary (includes Hex-Rays pseudocode by default; pass --no-decompiler to skip)
diaphora-headless export before/ntdll.dll before.sqlite

# Diff two exported databases
diaphora-headless diff before.sqlite after.sqlite -o result.diaphora

# Re-print the summary of an existing diff database
diaphora-headless summary result.diaphora --limit 30
```

### Useful flags

- `--force`: re-export even if the target `.sqlite` already exists (otherwise existing exports are reused).
- `--no-decompiler`: skip pseudocode export for much faster CFG/asm-only diffing.
- `--ida-args "-pmetapc"`: pass extra arguments to `idapro.open_database`.
- `--project-script my_script.py`: load a custom Diaphora project script during export.

## Integration with idalib-mcp

1. Run `diaphora-headless run old.dll new.dll -d out` to identify candidate patched functions and their addresses.
2. Open both binaries in `idalib-mcp` (`idalib_open`) and use `decompile`, `disasm`, `xrefs_to`, and `diff_before_after` on the candidate addresses.
3. You can also query `before_*.sqlite` and `after_*.sqlite` directly in Python to diff Hex-Rays pseudocode of partial matches.

## Notes

- Diaphora creates a `.diaphora` SQLite database whose `unmatched` table labels main-db unmatched functions as `secondary` and diff-db unmatched functions as `primary`. `diaphora-headless summary` already accounts for this inversion.
- Diaphora itself is licensed under AGPL-3.0 by Joxean Koret. This wrapper is MIT-licensed and does not vendor Diaphora's code.
