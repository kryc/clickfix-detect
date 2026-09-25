use crate::ProcessIntent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComClass {
    WScriptShell,
    ShellApplication,
    FileSystemObject,
    XmlHttp,
    WinHttpRequest,
    AdoDbStream,
    Unknown(String),
}

impl ComClass {
    #[must_use]
    pub fn canonical_progid(&self) -> &str {
        match self {
            Self::WScriptShell => "WScript.Shell",
            Self::ShellApplication => "Shell.Application",
            Self::FileSystemObject => "Scripting.FileSystemObject",
            Self::XmlHttp => "MSXML2.XMLHTTP",
            Self::WinHttpRequest => "WinHttp.WinHttpRequest.5.1",
            Self::AdoDbStream => "ADODB.Stream",
            Self::Unknown(program_id) => program_id,
        }
    }
}

#[must_use]
pub fn classify_com_progid(program_id: &str) -> ComClass {
    match program_id.trim().to_ascii_lowercase().as_str() {
        "wscript.shell" => ComClass::WScriptShell,
        "shell.application" => ComClass::ShellApplication,
        "scripting.filesystemobject" => ComClass::FileSystemObject,
        "msxml2.xmlhttp" | "msxml2.xmlhttp.3.0" | "msxml2.xmlhttp.6.0" | "microsoft.xmlhttp" => {
            ComClass::XmlHttp
        }
        "winhttp.winhttprequest" | "winhttp.winhttprequest.5.1" => ComClass::WinHttpRequest,
        "adodb.stream" => ComClass::AdoDbStream,
        _ => ComClass::Unknown(program_id.into()),
    }
}

#[must_use]
pub fn split_windows_command_line(input: &str) -> Vec<String> {
    let mut arguments = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut backslashes = 0_usize;
    for character in input.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                current.extend(std::iter::repeat_n('\\', backslashes / 2));
                if backslashes % 2 == 0 {
                    quoted = !quoted;
                } else {
                    current.push('"');
                }
                backslashes = 0;
            }
            character if character.is_whitespace() && !quoted => {
                current.extend(std::iter::repeat_n('\\', backslashes));
                backslashes = 0;
                if !current.is_empty() {
                    arguments.push(std::mem::take(&mut current));
                }
            }
            character => {
                current.extend(std::iter::repeat_n('\\', backslashes));
                backslashes = 0;
                current.push(character);
            }
        }
    }
    current.extend(std::iter::repeat_n('\\', backslashes));
    if !current.is_empty() {
        arguments.push(current);
    }
    arguments
}

#[must_use]
pub fn process_intent_from_command_line(
    command_line: &str,
    origin: &str,
    depth: usize,
    current_directory: &str,
) -> ProcessIntent {
    let parts = split_windows_command_line(command_line);
    ProcessIntent {
        program: parts.first().cloned().unwrap_or_default(),
        args: parts.into_iter().skip(1).collect(),
        command_line: command_line.into(),
        origin: origin.into(),
        depth,
        stdin: Vec::new(),
        current_directory: current_directory.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_common_com_aliases() {
        assert_eq!(classify_com_progid("Microsoft.XMLHTTP"), ComClass::XmlHttp);
        assert_eq!(
            classify_com_progid("WinHttp.WinHttpRequest.5.1"),
            ComClass::WinHttpRequest
        );
    }

    #[test]
    fn command_line_splitter_preserves_quoted_arguments() {
        assert_eq!(
            split_windows_command_line(r#"cmd.exe /c "echo safe value""#),
            ["cmd.exe", "/c", "echo safe value"]
        );
    }
}
