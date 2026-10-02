use crate::{BinaryCapability, BinaryImport};
use std::collections::BTreeSet;

pub(crate) fn infer(imports: &[BinaryImport], dependencies: &[String]) -> Vec<BinaryCapability> {
    let mut capabilities = BTreeSet::new();
    for value in imports
        .iter()
        .map(|import| import.symbol.as_str())
        .chain(dependencies.iter().map(String::as_str))
    {
        let value = value.to_ascii_lowercase();
        if contains_any(
            &value,
            &[
                "createprocess",
                "shellexecute",
                "winexec",
                "system",
                "execve",
                "posix_spawn",
                "fork",
            ],
        ) {
            capabilities.insert(BinaryCapability::ProcessExecution);
        }
        if contains_any(
            &value,
            &[
                "winhttp",
                "wininet",
                "urldownloadtofile",
                "internetopen",
                "socket",
                "connect",
                "send",
                "recv",
                "libcurl",
            ],
        ) {
            capabilities.insert(BinaryCapability::Network);
        }
        if contains_any(
            &value,
            &[
                "virtualallocex",
                "writeprocessmemory",
                "createremotethread",
                "ntmapviewofsection",
                "ptrace",
                "process_vm_writev",
            ],
        ) {
            capabilities.insert(BinaryCapability::MemoryInjection);
        }
        if contains_any(
            &value,
            &[
                "loadlibrary",
                "getprocaddress",
                "dlopen",
                "dlsym",
                "nsmodule",
            ],
        ) {
            capabilities.insert(BinaryCapability::DynamicLoading);
        }
        if contains_any(
            &value,
            &[
                "createservice",
                "regsetvalue",
                "schtasks",
                "launchservices",
                "systemd",
            ],
        ) {
            capabilities.insert(BinaryCapability::Persistence);
        }
        if contains_any(
            &value,
            &[
                "credread",
                "lsaretrieveprivatedata",
                "security.framework",
                "keychain",
                "libsecret",
            ],
        ) {
            capabilities.insert(BinaryCapability::CredentialAccess);
        }
    }
    capabilities.into_iter().collect()
}

fn contains_any(value: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pattern| value.contains(pattern))
}
