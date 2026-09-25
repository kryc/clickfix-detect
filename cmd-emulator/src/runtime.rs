use emulator_core::Host;
use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub(crate) struct Runtime {
    pub current_directory: String,
    pub directory_stack: Vec<String>,
    pub directories: BTreeSet<String>,
    pub error_level: i32,
    pub delayed_expansion: bool,
    pub echo_enabled: bool,
    pub random_state: u32,
}

impl Default for Runtime {
    fn default() -> Self {
        let directories = [
            r"C:\",
            r"C:\Users",
            r"C:\Users\analysis",
            r"C:\Users\analysis\AppData",
            r"C:\Users\analysis\AppData\Local",
            r"C:\Users\analysis\AppData\Local\Temp",
            r"C:\Windows",
            r"C:\Windows\System32",
        ]
        .into_iter()
        .map(emulator_core::normalize_windows_path)
        .collect();
        Self {
            current_directory: r"C:\Users\analysis".into(),
            directory_stack: Vec::new(),
            directories,
            error_level: 0,
            delayed_expansion: false,
            echo_enabled: true,
            random_state: 0x434d_4421,
        }
    }
}

impl Runtime {
    pub(crate) fn variable(&mut self, name: &str, host: &dyn Host) -> String {
        if name.eq_ignore_ascii_case("CD") {
            self.current_directory.clone()
        } else if name.eq_ignore_ascii_case("ERRORLEVEL") {
            self.error_level.to_string()
        } else if name.eq_ignore_ascii_case("RANDOM") {
            self.random_state = self
                .random_state
                .wrapping_mul(1_103_515_245)
                .wrapping_add(12_345);
            ((self.random_state >> 16) & 0x7fff).to_string()
        } else if name.eq_ignore_ascii_case("DATE") {
            "Mon 01/01/2024".into()
        } else if name.eq_ignore_ascii_case("TIME") {
            "00:00:00.00".into()
        } else {
            host.environment(name).unwrap_or_default().into()
        }
    }

    pub fn resolve_path(&self, path: &str) -> String {
        let path = path.trim().replace('/', "\\");
        let absolute = if path.len() >= 2 && path.as_bytes()[1] == b':' {
            path
        } else if path.starts_with('\\') {
            format!("{}{}", &self.current_directory[..2], path)
        } else if path.is_empty() || path == "." {
            self.current_directory.clone()
        } else {
            format!(
                r"{}\{}",
                self.current_directory.trim_end_matches('\\'),
                path
            )
        };
        collapse_path(&absolute)
    }
}

fn collapse_path(path: &str) -> String {
    let drive = path.get(..2).unwrap_or("C:");
    let mut parts = Vec::new();
    for part in path.get(2..).unwrap_or_default().split('\\') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    if parts.is_empty() {
        format!("{drive}\\")
    } else {
        format!("{drive}\\{}", parts.join("\\"))
    }
}
