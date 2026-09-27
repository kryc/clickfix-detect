# cmd-emulator

`cmd-emulator` is a hermetic Windows `cmd.exe` interpreter.
It expands environment variables, models common built-ins, updates a virtual
filesystem through `emulator-core`, and emits typed process intents instead of
starting programs.

```console
cargo run -p cmd-emulator -- -c "echo hello"
cargo run -p cmd-emulator -- --env NAME=tester "echo %NAME%"
cargo run -p cmd-emulator -- --file samples/cmd/04-batch-control.cmd --arg tester
printf "set X=42\necho %%X%%\n" | cargo run -p cmd-emulator
```

Running without input in a terminal opens a persistent
`C:\Users\analysis>` prompt. Use Up/Down for history, Ctrl-C to cancel input,
and Ctrl-D, `exit`, or `quit` to leave. `--interactive` forces this mode for
piped input. `--trace` prints typed events to stderr, `--delayed-expansion`
enables `!VAR!`, and repeatable `--env NAME=VALUE` options override the
deterministic Windows environment.

Supported built-ins include `echo`, `set`, `set /a`, `cd`, `pushd`, `popd`,
`md`, `rd`, `dir`, `type`, `copy`, `move`, `del`, `ren`, `rem`, `ver`, `cls`,
`path`, `exit`, `start`, `call`, and `shift`. Chaining with `&`, `&&`, and
`||`, stdout pipelines, grouped commands, and output/error redirection compose
over the virtual host.

Executables such as `find.exe`, `findstr.exe`, `more.com`, `sort.exe`,
`where.exe`, `xcopy.exe`, and `robocopy.exe` are intentionally not cmd
built-ins. They are issued through the synchronous `ProcessIntent`/
`ProcessResult` contract and modeled by `runbox-emulator`. When cmd is used
with a plain `VirtualHost`, these requests remain deferred process intents.
An unavailable deferred executable returns the Windows-style command-not-found
exit code `9009`; for example, `ls` is not a cmd built-in. Use `dir` or
`dir /b` to list virtual files.

The default `VirtualHost` includes common Windows 11 directories and modeled
system executables. Commands such as `dir C:\Windows\System32` therefore show
`cmd.exe`, `mshta.exe`, `rundll32.exe`, and the other modeled utilities.
Library callers can add or remove virtual files, directories, executables,
environment variables, registry values, and network fixtures before invoking
the emulator.

Batch execution pre-parses labels and supports bounded `goto`, `goto :eof`,
`call :label`, `exit /b`, and `shift`. `%0`-`%9`, `%*`, common `%~` path
modifiers, environment replacement/substrings, and CALL double expansion are
modeled. `--file` exposes the supplied path through `%0`; repeatable
`--arg VALUE` options provide `%1` and later arguments.

Each command source is tokenized once into a span-preserving parsed document.
Command chains, pipelines, groups, redirections, command names, arguments,
`if`, and all supported `for` modes are represented as typed AST nodes.
Logical batch lines retain their parsed documents across loops, `goto`, and
subroutine calls. Environment or delayed expansion that changes command text
creates one explicit generated document before execution.

The control-flow slice includes `if` error-level, existence, definition,
equality, and ordered comparisons with `not`, blocks, and `else`. `for`
supports simple sets, `/L`, `/R`, and basic `/F` parsing over strings, virtual
files, and backquoted command output. Program counters, call depth, steps, and
loop iterations use the configured analysis limits.

Library users construct `CmdEmulator` and call `emulate`, `emulate_batch`, or
`emulate_batch_with_args` with an `emulator_core::Host`. `CmdEmulator::parse`
and `CmdEmulator::parse_batch` provide parse-only summaries. All files remain
virtual and every external command becomes a `ProcessIntent`.
