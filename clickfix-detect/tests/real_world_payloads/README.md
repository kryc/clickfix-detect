# Published ClickFix payload corpus

These fixtures contain Base64-encoded command text published by
threat-research vendors. Tests decode each fixture in memory and pass it to
`clickfix-detect` without trimming, quote normalization, or adaptation to
emulator capabilities. Per-fixture SHA-256 values in
`../real_world_payloads.rs` cover the decoded bytes and make accidental changes
visible.

Publication-only safety notation such as `hxxp`, `hxxps`, `[:]`, and `[.]` is
refanged where the original host is known. This restores the command's observed
network semantics without changing its execution structure. Publisher
placeholders, truncation, malformed quoting, path traversal, unusual
capitalization, and generalized hosts remain untouched. Every Base64 fixture
has an adjacent heavily defanged comment in the test table for review.

The files are inert test data. Corpus tests use the default disabled network
policy: no native process, network connection, registry modification, or host
filesystem write occurs.

## Sources

| Publisher | Source | Fixtures |
| --- | --- | --- |
| Proofpoint | [From Clipboard to Compromise: A PowerShell Self-Pwn](https://www.proofpoint.com/us/blog/threat-insight/clipboard-compromise-powershell-self-pwn) | Three TA571 PowerShell clipboard commands |
| Unit 42 | [2024-08-28 Lumma Stealer IOC report](https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/2024-08-28-IOCs-for-Lumman-Stealer-from-fake-human-captcha-copy-paste-script.txt) | Three `mshta` commands |
| Unit 42 | [2026-08-05 pcalua/WebDAV variant](https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/2026-08-05-New-Clickfix-Variant.txt) | Templated `pcalua` chain and generalized `davclnt` command |
| Sekoia | [ClickFix Tactic: The Phantom Meet](https://www.sekoia.com/blog/clickfix-tactic-the-phantom-meet) | Fake Google Meet `mshta` command |
| Huntress | [ClickFix Gets Creative: Malware Buried in Images](https://www.huntress.com/blog/clickfix-malware-buried-in-images) | Hex-octet `mshta` command |
| Huntress | [ClickFix Removes Your Background but Leaves the Malware](https://www.huntress.com/blog/clickfix-castleloader-backgroundfix) | `%COMSPEC%`, caret-obfuscated `finger` chain |
| Huntress | [ClickFix, Matanbuchus 3.0, and AstarionRAT](https://www.huntress.com/blog/clickfix-matanbuchus-astarionrat-analysis) | Mixed-case remote `msiexec` command |
| Fortinet | [From ClickFix to Command: A Full PowerShell Attack Chain](https://www.fortinet.com/blog/threat-research/clickfix-to-command-a-full-powershell-attack-chain) | Initial IEX command and two published follow-on PowerShell lines |
| CyberProof | [Beyond PowerShell: Analyzing the Multi-Action ClickFix Variant](https://www.cyberproof.com/blog/beyond-powershell-analyzing-the-multi-action-clickfix-variant/) | Multiline `cmdkey` and remote `regsvr32` chain |
| eSentire | [Unpacking NetSupport RAT Loaders Delivered via ClickFix](https://www.esentire.com/blog/unpacking-netsupport-rat-loaders-delivered-via-clickfix) | Two PowerShell cradles, two remote MSI commands, one truncated encoded command |
| Rapid7 | [ClickFix Phishing Campaign Masquerading as a Claude Installer](https://www.rapid7.com/blog/post/ve-clickfix-phishing-campaign-fake-claude-installer/) | Published cmd wrapper with encoded-command placeholder |
| Zscaler | [COLDRIVER Updates Its Arsenal](https://www.zscaler.com/blogs/security-research/coldriver-updates-arsenal-baitswitch-and-simplefix) | Remote UNC `rundll32` command |
| Zscaler | [Technical Analysis of MLTBackdoor](https://www.zscaler.com/blogs/security-research/technical-analysis-mltbackdoor) | Templated headless `conhost` chain |
| The DFIR Report | [KongTuke FileFix Leads to New Interlock RAT Variant](https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/) | PowerShell/WebClient Interlock loader command |
| BlackCloak | [Social Engineering Meets Shell Script Malware](https://kb.blackcloak.io/en/articles/9433217) | macOS `/bin/bash -c "$(curl ...)"` launcher and download/xattr/chmod/execute stage |
| Recorded Future Insikt Group | [ClickFix Campaigns Targeting Windows and macOS](https://assets.recordedfuture.com/insikt-report-pdfs/2026/cta-2026-0325.pdf) | Odyssey Base64/nohup Bash command, decoded command, and MacSync Base64/zsh command |
| Netskope Threat Labs | [macOS ClickFix Lures Deploy AppleScript Stealer & Persistent RAT](https://www.netskope.com/blog/macos-clickfix-lures-deploy-applescript-stealer-persistent-rat) | AppleScript download pipe and Base64 temporary-script execution command |
| ADAMnetworks / Techie Mike | [ClickFix: The Fake CAPTCHA That Tricks You Into Hacking Yourself](https://www.techiemike.com/clickfix-fake-captcha/) | Redacted PasteSwitch export/curl/zsh command shape |
| Hunt.io | [APT36-Style ClickFix Attack Spoofs Indian Ministry to Target Windows & Linux](https://hunt.io/blog/apt36-clickfix-campaign-indian-ministry-of-defence) | Reconstructed Linux download/chmod/execute command from the publication's described URL, filename, and actions |
| Purpleshift | [Hack yourself: breaking down ClickFix](https://purpleshift.io/articles/2026-08-24-clickfix/) | Three explicitly representative Linux curl/wget/download-chmod shell patterns |

`Truncated` fixture metadata means the publication itself used a placeholder,
generalized host, omitted argument, or shortened encoded value. Tests do not
attempt to reconstruct missing content.

`Reconstructed` means the publication supplied the URL, filename, and ordered
actions but did not publish a copyable one-line command. The fixture is a
minimal shell reconstruction and is never presented as a byte-exact capture.

`Representative` means the source explicitly published the command as a common
Linux ClickFix pattern rather than attributing it to one named campaign.

## Coverage gaps exposed by the corpus

1. **Generalized indicators:** publisher placeholders such as
   `hxxps://[.]com/` and `<PAYLOAD_HOST>` cannot be refanged without inventing
   evidence. Add a canonical indicator type that retains both published and
   executable forms when both are known. Canonical forms must never trigger
   real network access.
2. **Windows proxy executables:** `pcalua.exe` and
   `davclnt.dll,DavSetCookie` are detected but not recursively modeled.
   Headless `conhost.exe` command proxying is modeled.
3. **UNC and WebDAV resources:** remote `rundll32` and `regsvr32` paths are
   statically noted but cannot retrieve fixture-backed SMB/WebDAV content.
   Extend network fixtures with `smb://` and `webdav://` schemes and keep the
   returned bytes virtual.
4. **PowerShell web object shapes:** the eSentire
   `New-Object Net.WebClient`/`DownloadFile` form still records unsupported
   operations. Unify PowerShell WebClient instance state with the existing
   HTTP object model.
5. **PowerShell chained member evaluation:** nested expressions such as
   `IEX ((Invoke-RestMethod ...).note.body)` are detected, but the full
   property chain is not evaluated. Extend member access over response maps
   before invocation.
6. **Publication typography:** smart quotes, en-dash parameters, placeholders,
   and CMS-damaged quoting are intentionally retained. Add a secondary,
   provenance-marked tolerant parse candidate rather than mutating the primary
   input.
7. **Incomplete public evidence:** some reports publish commands only as
   screenshots; others replace encoded bodies or hosts with placeholders.
   Those cannot support byte-exact fixtures until a textual primary source is
   available.
8. **Linux evidence scarcity:** Linux-targeting campaigns are publicly
   documented, but primary reports rarely publish verbatim clipboard command
   text. The Hunt.io fixture is therefore marked `Reconstructed`, and the
   Purpleshift fixtures are marked `Representative`.
9. **Secondary-stage retrieval:** first-stage curl/wget commands are modeled,
   but public reports often omit the returned shell, AppleScript, Mach-O, or
   ELF bytes. Add fixture-backed secondary-stage samples when publications
   provide hashes and recoverable content.
10. **macOS native formats and installers:** Mach-O execution, universal
    binaries, DMG mounting, PKG installation, `hdiutil`, `installer`,
    `codesign`, `security`, and `dscl` are not yet modeled.
11. **AppleScript and JXA depth:** `osascript` captures scripts, URLs, and
    recursively dispatches `do shell script`, but it does not interpret general
    AppleScript/JXA stealer logic, Keychain access, browser data collection, or
    LaunchAgent creation.
12. **Dynamic C2 command extraction:** Base64 decode/write/chmod/execute chains
    are correlated, but full `sed`/JSON extraction from server responses and
    arbitrary dynamic command provenance remain incomplete.
13. **Linux native execution:** chmod-marked shell scripts can recurse through
    Bash, but ELF inspection, shared-object loading, `LD_PRELOAD`, kernel/module
    operations, container escapes, and architecture-specific loaders are not
    modeled.

The corpus also exposed and now covers several fixed gaps: blocked or invalid
archive content no longer aborts analysis; Windows Run environment variables
are expanded; `finger.exe` emits a typed network intent; `START` can proxy cmd
internal commands; unquoted `FOR /F` options are tolerated after nested parsing;
and nested child syntax errors are reported without discarding the parent
analysis.

The macOS/Linux corpus additionally fixed and now covers POSIX `base64 -d/-D`,
shell execution from pipeline stdin, macOS `nohup`, `sh`/`zsh`/`osascript`
download-execution correlation, wget chains, extensionless chmod-marked
executables, and decode/write/execute behavior.

Detector expectations distinguish provenance from standalone behavior. Complete
remote-launch and download/execute commands must be `Malicious`; incomplete
encoded placeholders remain `Suspicious`; and two isolated Fortinet retrieval
lines remain `Benign` because, without their surrounding script, they only
retrieve data and do not execute it. The separate benign corpus guards this
boundary against broad keyword or network-only scoring.
