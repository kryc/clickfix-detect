# runbox-emulator

`runbox-emulator` orchestrates the language emulators and modeled applications
over one shared virtual host. Its native binary provides a persistent Windows
cmd or PowerShell prompt where external commands are synchronously dispatched
through Runbox.

```console
cargo run -p runbox-emulator
C:\Users\analysis> set SHARED=from-cmd
C:\Users\analysis> powershell -c "Write-Output $env:SHARED"
from-cmd
```

Select a persistent PowerShell parent shell to dispatch cmd in the opposite
direction:

```console
cargo run -p runbox-emulator -- --shell powershell
PS> $env:SHARED = 'from-powershell'
PS> cmd /c echo %SHARED%
from-powershell
```

PowerShell, cmd, Windows Script Host, Bash, macOS, Linux, downloader, archive,
launcher, and persistence effects remain hermetic. Nested processes share
virtual files, environment variables, registry state, network fixtures,
resource limits, and trace events.

Recognized PE, ELF, and Mach-O bytes are inspected when they are captured,
written, marked executable, passed to a modeled loader, or invoked as a
virtual executable. Reports are cached by SHA-256 and include bounded
structural metadata; attempted native execution remains explicitly blocked.
The shared host also records typed causal edges for downloads, decoding,
copies, extraction, executable marking, and modeled execution.

```console
cargo run -p runbox-emulator -- -c "powershell -c \"Write-Output safe\""
cargo run -p runbox-emulator -- --shell powershell -c "cmd /c echo safe"
cargo run -p runbox-emulator -- --file sample.cmd --arg one
cat commands.txt | cargo run -p runbox-emulator -- --interactive
```

Use `--trace`, repeatable `--env NAME=VALUE`, `--delayed-expansion`,
`--max-steps`, and `--max-depth` to configure the shell. Real networking
remains disabled unless `--allow-network` is supplied.
