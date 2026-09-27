use crate::archives::extract_zip;
use crate::transforms::{
    aes_cbc_decrypt, aes_cbc_encrypt, decode_ascii, decode_base64_standard, decode_base64_url_safe,
    decode_utf16_be, decode_utf16_le, decode_utf32_be, decode_utf32_le, decode_utf8,
    encode_base64_standard, encode_base64_url_safe, encode_utf16_be, encode_utf16_le,
    encode_utf32_be, encode_utf32_le, encode_utf8, gzip_compress, gzip_decompress, hex_encode,
    md5_hash, rc4, repeating_key_xor, reverse_bytes, reverse_string, sha1_hash, sha256_hash,
    zlib_compress, zlib_decompress,
};
use crate::{PowerShellEmulator, PowerShellError, Value};
use emulator_core::{ArtifactKind, Engine, Host, NetworkIntent};
use regex::Regex;
use std::collections::BTreeMap;

pub(crate) enum DotNetDispatch {
    NotHandled,
    Handled(Value),
}

fn construct_object(
    type_name: &str,
    args: &[Value],
    host: &mut dyn Host,
    depth: usize,
) -> Option<Value> {
    let value = match type_name {
        "io.memorystream" => object(
            "MemoryStream",
            [
                (
                    "Data".into(),
                    args.first()
                        .cloned()
                        .unwrap_or_else(|| Value::Bytes(Vec::new())),
                ),
                ("Position".into(), Value::Number(0)),
            ],
        ),
        "io.streamreader" => object(
            "StreamReader",
            [("Data".into(), args.first().cloned().unwrap_or(Value::Null))],
        ),
        "io.filestream" => {
            let path = args.first().map_or_else(String::new, Value::as_string);
            let data = host
                .read_file(&path, Engine::PowerShell, depth)
                .unwrap_or_default();
            object(
                "FileStream",
                [
                    ("Path".into(), Value::String(path)),
                    ("Data".into(), Value::Bytes(data)),
                    ("Position".into(), Value::Number(0)),
                ],
            )
        }
        "io.binaryreader" => object(
            "BinaryReader",
            [(
                "Stream".into(),
                args.first().cloned().unwrap_or(Value::Null),
            )],
        ),
        "io.binarywriter" => object(
            "BinaryWriter",
            [(
                "Stream".into(),
                args.first().cloned().unwrap_or(Value::Null),
            )],
        ),
        "net.webclient" => object(
            "WebClient",
            [
                ("Headers".into(), Value::Map(BTreeMap::new())),
                ("Credentials".into(), Value::Null),
                ("Proxy".into(), Value::Null),
                ("Encoding".into(), Value::Object("Encoding:utf-8".into())),
            ],
        ),
        "net.http.httpclient" => object(
            "HttpClient",
            [
                ("DefaultRequestHeaders".into(), Value::Map(BTreeMap::new())),
                ("Timeout".into(), Value::Number(100)),
            ],
        ),
        "random" => Value::Object("Random".into()),
        "text.utf8encoding" => Value::Object("Encoding:utf-8".into()),
        "text.unicodeencoding" => Value::Object("Encoding:unicode".into()),
        "collections.hashtable" => Value::Map(BTreeMap::new()),
        "uri" => args
            .first()
            .cloned()
            .unwrap_or_else(|| Value::String(String::new())),
        "io.compression.gzipstream"
        | "io.compression.deflatestream"
        | "io.compression.zlibstream" => object(
            "CompressionStream",
            [("Data".into(), args.first().cloned().unwrap_or(Value::Null))],
        ),
        _ => return None,
    };
    Some(value)
}

fn object(type_name: &str, properties: impl IntoIterator<Item = (String, Value)>) -> Value {
    Value::Map(
        std::iter::once(("__type".into(), Value::String(type_name.into())))
            .chain(properties)
            .collect(),
    )
}

impl PowerShellEmulator {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn eval_extended_static_call(
        type_name: &str,
        method: &str,
        args: &[Value],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<DotNetDispatch, PowerShellError> {
        let type_name = normalize_type(type_name);
        let method = method.to_ascii_lowercase();
        if method == "new" {
            return Ok(construct_object(&type_name, args, host, depth)
                .map_or(DotNetDispatch::NotHandled, DotNetDispatch::Handled));
        }
        let value = match (type_name.as_str(), method.as_str()) {
            ("convert", "tobase64string") => Value::String(encode_base64_standard(
                &args.first().map_or_else(Vec::new, Value::as_bytes),
                true,
            )),
            ("convert", "tobase64urlstring") => Value::String(encode_base64_url_safe(
                &args.first().map_or_else(Vec::new, Value::as_bytes),
                false,
            )),
            ("convert", "frombase64string") => {
                let input = args.first().map_or_else(String::new, Value::as_string);
                let bytes = decode_base64_standard(&input, true)
                    .or_else(|_| decode_base64_url_safe(&input, true))
                    .map_err(|error| {
                        PowerShellError::Evaluation(format!("invalid base64 input: {error}"))
                    })?;
                Self::record_decode("base64", &bytes, host, depth);
                Value::Bytes(bytes)
            }

            ("convert", "tohexstring") | ("bitconverter", "tostring") => {
                let bytes = args.first().map_or_else(Vec::new, Value::as_bytes);
                let hex = hex_encode(&bytes);
                if type_name == "bitconverter" {
                    Value::String(
                        hex.as_bytes()
                            .chunks_exact(2)
                            .map(|pair| String::from_utf8_lossy(pair).to_ascii_uppercase())
                            .collect::<Vec<_>>()
                            .join("-"),
                    )
                } else {
                    Value::String(hex.to_ascii_uppercase())
                }
            }
            ("convert", "toint32" | "toint64") => {
                let input = args.first().map_or_else(String::new, Value::as_string);
                let radix = args.get(1).and_then(Value::as_i64).unwrap_or(10);
                let radix = u32::try_from(radix).unwrap_or(10);
                Value::Number(i64::from_str_radix(input.trim(), radix).unwrap_or_default())
            }
            ("string", "join") => {
                let separator = args.first().map_or_else(String::new, Value::as_string);
                let values = args.get(1).cloned().unwrap_or(Value::Null);
                let values = match values {
                    Value::Array(values) => values,
                    value => vec![value],
                };
                Value::String(
                    values
                        .iter()
                        .map(Value::as_string)
                        .collect::<Vec<_>>()
                        .join(&separator),
                )
            }
            ("string", "concat") => Value::String(args.iter().map(Value::as_string).collect()),
            ("array", "reverse") => {
                let mut values = match args.first().cloned().unwrap_or(Value::Null) {
                    Value::Array(values) => values,
                    Value::Bytes(bytes) => bytes
                        .into_iter()
                        .map(|byte| Value::Number(i64::from(byte)))
                        .collect(),
                    value => value
                        .as_string()
                        .chars()
                        .map(|character| Value::String(character.to_string()))
                        .collect(),
                };
                values.reverse();
                Value::Array(values)
            }
            ("text.encoding", "getencoding") => Value::Object(format!(
                "Encoding:{}",
                args.first().map_or_else(String::new, Value::as_string)
            )),
            ("text.encoding", "utf8.getstring") => Value::String(decode_utf8(
                &args.first().map_or_else(Vec::new, Value::as_bytes),
            )),
            ("text.encoding", "utf8.getbytes") => Value::Bytes(encode_utf8(
                &args.first().map_or_else(String::new, Value::as_string),
            )),
            ("text.encoding", "unicode.getstring") => Value::String(decode_utf16_le(
                &args.first().map_or_else(Vec::new, Value::as_bytes),
            )),
            ("text.encoding", "unicode.getbytes") => Value::Bytes(encode_utf16_le(
                &args.first().map_or_else(String::new, Value::as_string),
            )),
            ("text.encoding", "bigendianunicode.getstring") => Value::String(decode_utf16_be(
                &args.first().map_or_else(Vec::new, Value::as_bytes),
            )),
            ("text.encoding", "bigendianunicode.getbytes") => Value::Bytes(encode_utf16_be(
                &args.first().map_or_else(String::new, Value::as_string),
            )),
            ("text.encoding", "utf32.getstring") => Value::String(decode_utf32_le(
                &args.first().map_or_else(Vec::new, Value::as_bytes),
            )),
            ("text.encoding", "utf32.getbytes") => Value::Bytes(encode_utf32_le(
                &args.first().map_or_else(String::new, Value::as_string),
            )),
            ("text.encoding", "ascii.getstring") => Value::String(decode_ascii(
                args.first().map_or_else(Vec::new, Value::as_bytes),
            )),
            ("text.encoding", "ascii.getbytes") => Value::Bytes(
                args.first()
                    .map_or_else(String::new, Value::as_string)
                    .bytes()
                    .collect(),
            ),
            ("regex", "escape") => Value::String(regex::escape(
                &args.first().map_or_else(String::new, Value::as_string),
            )),
            ("regex", "unescape") => Value::String(
                args.first()
                    .map_or_else(String::new, Value::as_string)
                    .replace("\\.", ".")
                    .replace("\\-", "-")
                    .replace("\\_", "_"),
            ),
            ("regex", "replace") => {
                let input = args.first().map_or_else(String::new, Value::as_string);
                let pattern = args.get(1).map_or_else(String::new, Value::as_string);
                let replacement = args.get(2).map_or_else(String::new, Value::as_string);
                Value::String(Regex::new(&pattern).map_or(input.clone(), |regex| {
                    regex.replace_all(&input, replacement.as_str()).into_owned()
                }))
            }
            ("regex", "split") => {
                let input = args.first().map_or_else(String::new, Value::as_string);
                let pattern = args.get(1).map_or_else(String::new, Value::as_string);
                Value::Array(Regex::new(&pattern).map_or_else(
                    |_| vec![Value::String(input.clone())],
                    |regex| {
                        regex
                            .split(&input)
                            .map(|part| Value::String(part.into()))
                            .collect()
                    },
                ))
            }
            ("io.path", "combine") => Value::String(
                args.iter()
                    .map(Value::as_string)
                    .filter(|part| !part.is_empty())
                    .collect::<Vec<_>>()
                    .join("\\"),
            ),
            ("io.path", "gettemppath") => {
                Value::String(r"C:\Users\analysis\AppData\Local\Temp\".into())
            }
            ("io.path", "getrandomfilename") => Value::String("cf_5f3759df.tmp".into()),
            ("io.path", "getfilename") => Value::String(
                args.first()
                    .map_or_else(String::new, Value::as_string)
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or_default()
                    .into(),
            ),
            ("io.file", "exists") => {
                let path = args.first().map_or_else(String::new, Value::as_string);
                Value::Bool(host.read_file(&path, Engine::PowerShell, depth).is_some())
            }
            ("io.file", "appendalltext") => {
                let path = args.first().map_or_else(String::new, Value::as_string);
                let bytes = args.get(1).map_or_else(Vec::new, Value::as_bytes);
                host.write_file(&path, &bytes, true, Engine::PowerShell, depth)?;
                Value::Null
            }
            ("io.file", "copy" | "move") => {
                let source = args.first().map_or_else(String::new, Value::as_string);
                let destination = args.get(1).map_or_else(String::new, Value::as_string);
                if let Some(bytes) = host.read_file(&source, Engine::PowerShell, depth) {
                    host.write_file(&destination, &bytes, false, Engine::PowerShell, depth)?;
                    if method == "move" {
                        host.delete_file(&source, Engine::PowerShell, depth);
                    }
                }
                Value::Null
            }
            ("io.file", "delete") => {
                let path = args.first().map_or_else(String::new, Value::as_string);
                Value::Bool(host.delete_file(&path, Engine::PowerShell, depth))
            }
            ("io.directory", "exists") => {
                let path = args.first().map_or_else(String::new, Value::as_string);
                Value::Bool(!host.list_files(&path, Engine::PowerShell, depth).is_empty())
            }
            ("io.directory", "getfiles") => {
                let path = args.first().map_or_else(String::new, Value::as_string);
                Value::Array(
                    host.list_files(&path, Engine::PowerShell, depth)
                        .into_iter()
                        .map(Value::String)
                        .collect(),
                )
            }
            ("io.directory", "createdirectory") => {
                Value::String(args.first().map_or_else(String::new, Value::as_string))
            }
            ("io.compression.zipfile", "extracttodirectory") => {
                let archive = args.first().map_or_else(String::new, Value::as_string);
                let destination = args.get(1).map_or_else(String::new, Value::as_string);
                let bytes = host
                    .read_file(&archive, Engine::PowerShell, depth)
                    .unwrap_or_default();
                let files = match extract_zip(&bytes) {
                    Ok(files) => files,
                    Err(error) => {
                        host.unsupported(
                            Engine::PowerShell,
                            depth,
                            &format!(
                                "[IO.Compression.ZipFile]::ExtractToDirectory could not parse {archive}: {error}"
                            ),
                        );
                        return Ok(DotNetDispatch::Handled(Value::Null));
                    }
                };
                for (entry, bytes) in files {
                    let path = format!(
                        "{}\\{}",
                        destination.trim_end_matches(['\\', '/']),
                        entry.trim_start_matches(['\\', '/'])
                    );
                    host.write_file(&path, &bytes, false, Engine::PowerShell, depth)?;
                }
                Value::Null
            }
            ("environment", "getenvironmentvariable") => {
                let name = args.first().map_or_else(String::new, Value::as_string);
                host.environment(&name)
                    .map_or(Value::Null, |value| Value::String(value.into()))
            }
            ("environment", "getenvironmentvariables") => Value::Map(
                host.environment_entries()
                    .into_iter()
                    .map(|(name, value)| (name, Value::String(value)))
                    .collect(),
            ),
            ("environment", "setenvironmentvariable") => {
                let name = args.first().map_or_else(String::new, Value::as_string);
                let value = args.get(1).cloned().unwrap_or(Value::Null);
                if matches!(value, Value::Null) {
                    host.remove_environment(&name);
                } else {
                    host.set_environment(&name, &value.as_string());
                }
                Value::Null
            }
            ("environment", "expandenvironmentvariables") => {
                Value::String(expand_environment_variables(
                    &args.first().map_or_else(String::new, Value::as_string),
                    host,
                ))
            }
            ("environment", "getfolderpath") => {
                let folder = args.first().map_or_else(String::new, Value::as_string);
                let path = match folder.to_ascii_lowercase().as_str() {
                    "applicationdata" => host.environment("APPDATA").unwrap_or_default().into(),
                    "localapplicationdata" => {
                        host.environment("LOCALAPPDATA").unwrap_or_default().into()
                    }
                    "commonapplicationdata" => {
                        host.environment("PROGRAMDATA").unwrap_or_default().into()
                    }
                    "programfiles" => host.environment("ProgramFiles").unwrap_or_default().into(),
                    "programfilesx86" => host
                        .environment("ProgramFiles(x86)")
                        .unwrap_or_default()
                        .into(),
                    "commonprogramfiles" => host
                        .environment("CommonProgramFiles")
                        .unwrap_or_default()
                        .into(),
                    "startup" => format!(
                        r"{}\Microsoft\Windows\Start Menu\Programs\Startup",
                        host.environment("APPDATA").unwrap_or_default()
                    ),
                    _ => host.environment("USERPROFILE").unwrap_or_default().into(),
                };
                Value::String(path)
            }
            ("security.principal.windowsidentity", "getcurrent") => Value::Map(
                [
                    ("Name".into(), Value::String(r"analysis\user".into())),
                    ("IsSystem".into(), Value::Bool(false)),
                ]
                .into_iter()
                .collect(),
            ),
            ("guid", "newguid") => Value::String("434c4943-4b46-4958-8000-000000000001".into()),
            ("net.webrequest" | "net.httpwebrequest", "create") => Value::Map(
                [
                    ("__type".into(), Value::String("WebRequest".into())),
                    ("Url".into(), args.first().cloned().unwrap_or(Value::Null)),
                    ("Method".into(), Value::String("GET".into())),
                ]
                .into_iter()
                .collect(),
            ),
            ("management.automation.scriptblock", "create") => Value::Object(format!(
                "ScriptBlock:{}",
                args.first().map_or_else(String::new, Value::as_string)
            )),
            ("security.cryptography.sha256", "hashdata") => Value::Bytes(
                sha256_hash(&args.first().map_or_else(Vec::new, Value::as_bytes)).to_vec(),
            ),
            ("security.cryptography.sha1", "hashdata") => Value::Bytes(
                sha1_hash(&args.first().map_or_else(Vec::new, Value::as_bytes)).to_vec(),
            ),
            ("security.cryptography.md5", "hashdata") => Value::Bytes(
                md5_hash(&args.first().map_or_else(Vec::new, Value::as_bytes)).to_vec(),
            ),
            (
                "security.cryptography.sha256"
                | "security.cryptography.sha256managed"
                | "security.cryptography.sha1"
                | "security.cryptography.sha1managed"
                | "security.cryptography.md5",
                "create",
            ) => Value::Object(format!("HashAlgorithm:{type_name}")),
            ("security.cryptography.aes", "create") => Value::Map(
                [
                    ("__type".into(), Value::String("Aes".into())),
                    ("Key".into(), Value::Null),
                    ("IV".into(), Value::Null),
                    ("Mode".into(), Value::String("CBC".into())),
                    ("Padding".into(), Value::String("PKCS7".into())),
                ]
                .into_iter()
                .collect(),
            ),
            ("io.compression.gzipstream", "compress") => Value::Bytes(
                gzip_compress(&args.first().map_or_else(Vec::new, Value::as_bytes))
                    .map_err(|error| PowerShellError::Evaluation(error.to_string()))?,
            ),
            ("io.compression.gzipstream", "decompress") => Value::Bytes(
                gzip_decompress(&args.first().map_or_else(Vec::new, Value::as_bytes))
                    .map_err(|error| PowerShellError::Evaluation(error.to_string()))?,
            ),
            ("io.compression.deflatestream" | "io.compression.zlibstream", "compress") => {
                Value::Bytes(
                    zlib_compress(&args.first().map_or_else(Vec::new, Value::as_bytes))
                        .map_err(|error| PowerShellError::Evaluation(error.to_string()))?,
                )
            }
            ("io.compression.deflatestream" | "io.compression.zlibstream", "decompress") => {
                Value::Bytes(
                    zlib_decompress(&args.first().map_or_else(Vec::new, Value::as_bytes))
                        .map_err(|error| PowerShellError::Evaluation(error.to_string()))?,
                )
            }
            ("emulator.transforms", "reverse") => {
                match args.first().cloned().unwrap_or(Value::Null) {
                    Value::Bytes(bytes) => Value::Bytes(reverse_bytes(&bytes)),
                    value => Value::String(reverse_string(&value.as_string())),
                }
            }
            ("emulator.transforms", "xor") => Value::Bytes(
                repeating_key_xor(
                    &args.first().map_or_else(Vec::new, Value::as_bytes),
                    &args.get(1).map_or_else(Vec::new, Value::as_bytes),
                )
                .map_err(|error| PowerShellError::Evaluation(error.to_string()))?,
            ),
            ("emulator.transforms", "rc4") => Value::Bytes(
                rc4(
                    &args.first().map_or_else(Vec::new, Value::as_bytes),
                    &args.get(1).map_or_else(Vec::new, Value::as_bytes),
                )
                .map_err(|error| PowerShellError::Evaluation(error.to_string()))?,
            ),
            ("emulator.transforms", "aesencrypt") => Value::Bytes(
                aes_cbc_encrypt(
                    &args.first().map_or_else(Vec::new, Value::as_bytes),
                    &args.get(1).map_or_else(Vec::new, Value::as_bytes),
                    &args.get(2).map_or_else(Vec::new, Value::as_bytes),
                )
                .map_err(|error| PowerShellError::Evaluation(error.to_string()))?,
            ),
            ("emulator.transforms", "aesdecrypt") => Value::Bytes(
                aes_cbc_decrypt(
                    &args.first().map_or_else(Vec::new, Value::as_bytes),
                    &args.get(1).map_or_else(Vec::new, Value::as_bytes),
                    &args.get(2).map_or_else(Vec::new, Value::as_bytes),
                )
                .map_err(|error| PowerShellError::Evaluation(error.to_string()))?,
            ),
            ("uri", "escapedatastring") | ("net.webutility", "urlencode") => Value::String(
                percent_encode(&args.first().map_or_else(String::new, Value::as_string)),
            ),
            ("runtime.interopservices.marshal", "securestringtobstr") => {
                args.first().cloned().unwrap_or(Value::Null)
            }
            ("runtime.interopservices.marshal", "ptrtostringbstr") => {
                match args.first().cloned().unwrap_or(Value::Null) {
                    Value::Map(values) => map_property(&values, "data")
                        .cloned()
                        .unwrap_or(Value::Null),
                    value => value,
                }
            }
            (
                "runtime.interopservices.marshal",
                "getdelegateforfunctionpointer" | "getfunctionpointerfordelegate" | "copy",
            ) => {
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    &format!("modeled native interop call Marshal.{method}"),
                );
                Value::Object(format!("NativeInterop:{method}"))
            }
            ("runtime.interopservices.nativelibrary", "load" | "getexport") => {
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    &format!("modeled native library resolution: NativeLibrary.{method}"),
                );
                Value::Object(format!("NativePointer:{method}"))
            }
            ("reflection.assembly", "load" | "loadfile" | "loadfrom") => {
                let bytes = if method == "load" {
                    args.first().map_or_else(Vec::new, Value::as_bytes)
                } else {
                    let path = args.first().map_or_else(String::new, Value::as_string);
                    host.read_file(&path, Engine::PowerShell, depth)
                        .unwrap_or_default()
                };
                host.add_artifact(
                    ArtifactKind::Binary,
                    "managed-assembly.bin",
                    "application/vnd.microsoft.portable-executable",
                    &bytes,
                    depth,
                );
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    "managed assembly load was recorded but not executed",
                );
                Value::Object("ModeledAssembly".into())
            }
            _ if is_reflection_or_evasion(&type_name, &method) => {
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    &format!("modeled reflection or defense-evasion call [{type_name}]::{method}"),
                );
                Value::Object(format!("[{type_name}]::{method}"))
            }
            _ => return Ok(DotNetDispatch::NotHandled),
        };
        Ok(DotNetDispatch::Handled(value))
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) fn eval_extended_instance_call(
        &mut self,
        receiver_expression: &str,
        receiver: &Value,
        method: &str,
        args: &[Value],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<DotNetDispatch, PowerShellError> {
        let method = method.to_ascii_lowercase();
        let value = match (receiver, method.as_str()) {
            (Value::Map(values), "write" | "writebyte")
                if map_type(values).is_some_and(|value| {
                    matches!(
                        value.to_ascii_lowercase().as_str(),
                        "memorystream" | "filestream" | "binarywriter"
                    )
                }) =>
            {
                let mut data = stream_data(values);
                let bytes = if method == "writebyte" {
                    args.first()
                        .and_then(Value::as_i64)
                        .and_then(|value| u8::try_from(value).ok())
                        .map_or_else(Vec::new, |value| vec![value])
                } else {
                    let bytes = args.first().map_or_else(Vec::new, Value::as_bytes);
                    let offset = args
                        .get(1)
                        .and_then(Value::as_i64)
                        .and_then(|value| usize::try_from(value).ok())
                        .unwrap_or_default();
                    let count = args
                        .get(2)
                        .and_then(Value::as_i64)
                        .and_then(|value| usize::try_from(value).ok())
                        .unwrap_or_else(|| bytes.len().saturating_sub(offset));
                    bytes
                        .get(offset..offset.saturating_add(count).min(bytes.len()))
                        .unwrap_or_default()
                        .to_vec()
                };
                data.extend(bytes);
                self.update_dotnet_properties(
                    receiver_expression,
                    [
                        ("Data".into(), Value::Bytes(data.clone())),
                        (
                            "Position".into(),
                            Value::Number(i64::try_from(data.len()).unwrap_or(i64::MAX)),
                        ),
                    ],
                );
                if map_type(values).is_some_and(|value| value.eq_ignore_ascii_case("FileStream")) {
                    let path = values
                        .get("Path")
                        .map_or_else(String::new, Value::as_string);
                    host.write_file(&path, &data, false, Engine::PowerShell, depth)?;
                }
                Value::Null
            }
            (Value::Map(values), "readbytes")
                if map_type(values)
                    .is_some_and(|value| value.eq_ignore_ascii_case("BinaryReader")) =>
            {
                let count = args
                    .first()
                    .and_then(Value::as_i64)
                    .and_then(|value| usize::try_from(value).ok())
                    .unwrap_or(usize::MAX);
                Value::Bytes(stream_data(values).into_iter().take(count).collect())
            }
            (Value::Map(values), "seek")
                if map_type(values).is_some_and(|value| {
                    matches!(
                        value.to_ascii_lowercase().as_str(),
                        "memorystream" | "filestream"
                    )
                }) =>
            {
                let position = args.first().and_then(Value::as_i64).unwrap_or_default();
                self.update_dotnet_properties(
                    receiver_expression,
                    [("Position".into(), Value::Number(position.max(0)))],
                );
                Value::Number(position.max(0))
            }
            (Value::Map(values), "setlength")
                if map_type(values).is_some_and(|value| {
                    matches!(
                        value.to_ascii_lowercase().as_str(),
                        "memorystream" | "filestream"
                    )
                }) =>
            {
                let length = args
                    .first()
                    .and_then(Value::as_i64)
                    .and_then(|value| usize::try_from(value.max(0)).ok())
                    .unwrap_or_default()
                    .min(host.limits().max_artifact_bytes);
                let mut data = stream_data(values);
                data.resize(length, 0);
                self.update_dotnet_properties(
                    receiver_expression,
                    [("Data".into(), Value::Bytes(data))],
                );
                Value::Null
            }
            (Value::Map(_), "close" | "dispose" | "flush") => Value::Null,
            (Value::Map(values), "downloadstring" | "downloaddata" | "downloadfile")
                if map_type(values)
                    .is_some_and(|value| value.eq_ignore_ascii_case("WebClient")) =>
            {
                let url = args.first().map_or_else(String::new, Value::as_string);
                let response = host.network_request(NetworkIntent {
                    method: "GET".into(),
                    url,
                    origin: format!("PowerShell WebClient.{method}"),
                    depth,
                });
                match (method.as_str(), response) {
                    (_, None) => Value::Object("BlockedNetworkResponse".into()),
                    ("downloadstring", Some(response)) => {
                        Value::String(decode_utf8(&response.body))
                    }
                    ("downloaddata", Some(response)) => Value::Bytes(response.body),
                    ("downloadfile", Some(response)) => {
                        let path = args.get(1).map_or_else(String::new, Value::as_string);
                        host.write_file(&path, &response.body, false, Engine::PowerShell, depth)?;
                        Value::Null
                    }
                    _ => Value::Null,
                }
            }
            (Value::String(value), "substring") => {
                let start = args.first().and_then(Value::as_i64).unwrap_or_default();
                let start = usize::try_from(start.max(0)).unwrap_or_default();
                let length = args.get(1).and_then(Value::as_i64);
                let characters = value.chars().collect::<Vec<_>>();
                let end = length.map_or(characters.len(), |length| {
                    start.saturating_add(usize::try_from(length.max(0)).unwrap_or_default())
                });
                Value::String(
                    characters
                        .get(start..end.min(characters.len()))
                        .unwrap_or_default()
                        .iter()
                        .collect(),
                )
            }
            (Value::String(value), "tochararray") => Value::Array(
                value
                    .chars()
                    .map(|character| Value::String(character.to_string()))
                    .collect(),
            ),
            (Value::String(value), "contains") => Value::Bool(
                value.to_ascii_lowercase().contains(
                    &args
                        .first()
                        .map_or_else(String::new, Value::as_string)
                        .to_ascii_lowercase(),
                ),
            ),
            (Value::String(value), "startswith") => Value::Bool(
                value.to_ascii_lowercase().starts_with(
                    &args
                        .first()
                        .map_or_else(String::new, Value::as_string)
                        .to_ascii_lowercase(),
                ),
            ),
            (Value::String(value), "endswith") => Value::Bool(
                value.to_ascii_lowercase().ends_with(
                    &args
                        .first()
                        .map_or_else(String::new, Value::as_string)
                        .to_ascii_lowercase(),
                ),
            ),
            (Value::String(value), "trimstart") => Value::String(
                value
                    .trim_start_matches(&args.first().map_or_else(String::new, Value::as_string))
                    .into(),
            ),
            (Value::String(value), "trimend") => Value::String(
                value
                    .trim_end_matches(&args.first().map_or_else(String::new, Value::as_string))
                    .into(),
            ),
            (Value::String(value), "insert") => {
                let index = args.first().and_then(Value::as_i64).unwrap_or_default();
                let index = usize::try_from(index.max(0))
                    .unwrap_or_default()
                    .min(value.len());
                let insertion = args.get(1).map_or_else(String::new, Value::as_string);
                let mut output = value.clone();
                output.insert_str(index, &insertion);
                Value::String(output)
            }
            (Value::String(value), "remove") => {
                let start = args.first().and_then(Value::as_i64).unwrap_or_default();
                let start = usize::try_from(start.max(0))
                    .unwrap_or_default()
                    .min(value.len());
                let count = args.get(1).and_then(Value::as_i64).unwrap_or(i64::MAX);
                let end = start
                    .saturating_add(usize::try_from(count.max(0)).unwrap_or(usize::MAX))
                    .min(value.len());
                let mut output = value.clone();
                output.replace_range(start..end, "");
                Value::String(output)
            }
            (Value::String(value), "padleft" | "padright") => {
                let width = args.first().and_then(Value::as_i64).unwrap_or_default();
                let width = usize::try_from(width.max(0)).unwrap_or_default();
                let fill = args
                    .get(1)
                    .map_or(' ', |value| value.as_string().chars().next().unwrap_or(' '));
                let padding = width.saturating_sub(value.chars().count());
                let padding = std::iter::repeat_n(fill, padding).collect::<String>();
                if method == "padleft" {
                    Value::String(format!("{padding}{value}"))
                } else {
                    Value::String(format!("{value}{padding}"))
                }
            }
            (Value::String(value), "reverse") => Value::String(reverse_string(value)),
            (Value::Array(values), "reverse") => {
                let mut values = values.clone();
                values.reverse();
                Value::Array(values)
            }
            (Value::Bytes(bytes), "reverse") => Value::Bytes(reverse_bytes(bytes)),
            (Value::Bytes(bytes), "toarray") => Value::Bytes(bytes.clone()),
            (Value::Map(values), "toarray")
                if map_type(values)
                    .is_some_and(|value| value.eq_ignore_ascii_case("MemoryStream")) =>
            {
                map_property(values, "data").cloned().unwrap_or(Value::Null)
            }
            (Value::Map(values), "readtoend")
                if map_type(values)
                    .is_some_and(|value| value.eq_ignore_ascii_case("StreamReader")) =>
            {
                let data = map_property(values, "data").cloned().unwrap_or(Value::Null);
                match data {
                    Value::Map(stream) => stream
                        .get("data")
                        .map_or(Value::Null, |value| Value::String(value.as_string())),
                    value => Value::String(value.as_string()),
                }
            }
            (Value::Map(values), "copyto")
                if map_type(values)
                    .is_some_and(|value| value.eq_ignore_ascii_case("CompressionStream")) =>
            {
                map_property(values, "data").cloned().unwrap_or(Value::Null)
            }
            (Value::Map(values), "createencryptor")
                if map_type(values).is_some_and(|value| value.eq_ignore_ascii_case("Aes")) =>
            {
                aes_transform(values, true)
            }
            (Value::Map(values), "createdecryptor")
                if map_type(values).is_some_and(|value| value.eq_ignore_ascii_case("Aes")) =>
            {
                aes_transform(values, false)
            }
            (Value::Map(values), "transformfinalblock")
                if map_type(values)
                    .is_some_and(|value| value.eq_ignore_ascii_case("AesTransform")) =>
            {
                let bytes = args.first().map_or_else(Vec::new, Value::as_bytes);
                let offset = args
                    .get(1)
                    .and_then(Value::as_i64)
                    .and_then(|value| usize::try_from(value).ok())
                    .unwrap_or_default();
                let count = args
                    .get(2)
                    .and_then(Value::as_i64)
                    .and_then(|value| usize::try_from(value).ok())
                    .unwrap_or_else(|| bytes.len().saturating_sub(offset));
                let end = offset.saturating_add(count).min(bytes.len());
                let input = bytes.get(offset..end).unwrap_or_default();
                let key = map_property(values, "Key").map_or_else(Vec::new, Value::as_bytes);
                let iv = map_property(values, "IV").map_or_else(Vec::new, Value::as_bytes);
                let encrypt = map_property(values, "Encrypt").is_some_and(Value::truthy);
                let transformed = if encrypt {
                    aes_cbc_encrypt(input, &key, &iv)
                } else {
                    aes_cbc_decrypt(input, &key, &iv)
                }
                .map_err(|error| PowerShellError::Evaluation(error.to_string()))?;
                Value::Bytes(transformed)
            }
            (Value::Map(values), "getresponse" | "getresponsestream")
                if map_type(values)
                    .is_some_and(|value| value.eq_ignore_ascii_case("WebRequest")) =>
            {
                let url = map_property(values, "Url").map_or_else(String::new, Value::as_string);
                let method = values
                    .get("Method")
                    .map_or_else(|| "GET".into(), Value::as_string);
                let origin = format!("PowerShell WebRequest.{method}");
                let response = host.network_request(NetworkIntent {
                    method,
                    url,
                    origin,
                    depth,
                });
                response.map_or_else(
                    || Value::Object("BlockedNetworkResponse".into()),
                    crate::builtins::network_response_value,
                )
            }
            (Value::Object(type_name), "getstring")
                if type_name.to_ascii_lowercase().starts_with("encoding:") =>
            {
                let bytes = args.first().map_or_else(Vec::new, Value::as_bytes);
                decode_encoding(type_name, &bytes)
            }
            (Value::Object(type_name), "getbytes")
                if type_name.to_ascii_lowercase().starts_with("encoding:") =>
            {
                let text = args.first().map_or_else(String::new, Value::as_string);
                encode_encoding(type_name, &text)
            }
            (Value::Object(type_name), "next") if type_name.eq_ignore_ascii_case("random") => {
                let minimum = args.first().and_then(Value::as_i64).unwrap_or_default();
                let maximum = args.get(1).and_then(Value::as_i64).unwrap_or(i64::MAX);
                self.random_state ^= self.random_state << 13;
                self.random_state ^= self.random_state >> 7;
                self.random_state ^= self.random_state << 17;
                let width = maximum.saturating_sub(minimum).max(1);
                let random = i64::try_from(self.random_state % u64::try_from(width).unwrap_or(1))
                    .unwrap_or_default();
                Value::Number(minimum.saturating_add(random))
            }
            (Value::Object(type_name), "computehash")
                if type_name.to_ascii_lowercase().starts_with("hashalgorithm:") =>
            {
                let bytes = args.first().map_or_else(Vec::new, Value::as_bytes);
                let algorithm = type_name.to_ascii_lowercase();
                if algorithm.contains("md5") {
                    Value::Bytes(md5_hash(&bytes).to_vec())
                } else if algorithm.contains("sha1") {
                    Value::Bytes(sha1_hash(&bytes).to_vec())
                } else {
                    Value::Bytes(sha256_hash(&bytes).to_vec())
                }
            }
            (_, "getstringasync" | "getbytearrayasync" | "getasync")
                if modeled_type(receiver).is_some_and(|type_name| {
                    type_name.to_ascii_lowercase().contains("httpclient")
                }) =>
            {
                let url = args.first().map_or_else(String::new, Value::as_string);
                let response = host.network_request(NetworkIntent {
                    method: "GET".into(),
                    url,
                    origin: format!("PowerShell HttpClient.{method}"),
                    depth,
                });
                match (method.as_str(), response) {
                    (_, None) => Value::Object("BlockedNetworkResponse".into()),
                    ("getstringasync", Some(response)) => {
                        Value::String(decode_utf8(&response.body))
                    }
                    ("getbytearrayasync", Some(response)) => Value::Bytes(response.body),
                    (_, Some(response)) => crate::builtins::network_response_value(response),
                }
            }
            (_, "postasync" | "postasjsonasync")
                if modeled_type(receiver).is_some_and(|type_name| {
                    type_name.to_ascii_lowercase().contains("httpclient")
                }) =>
            {
                let url = args.first().map_or_else(String::new, Value::as_string);
                let response = host.network_request(NetworkIntent {
                    method: "POST".into(),
                    url,
                    origin: format!("PowerShell HttpClient.{method}"),
                    depth,
                });
                response.map_or_else(
                    || Value::Object("BlockedNetworkResponse".into()),
                    crate::builtins::network_response_value,
                )
            }
            (Value::Object(type_name), "ismatch")
                if type_name.to_ascii_lowercase().starts_with("regex:") =>
            {
                let pattern = type_name.split_once(':').map_or("", |(_, value)| value);
                let input = args.first().map_or_else(String::new, Value::as_string);
                Value::Bool(Regex::new(pattern).is_ok_and(|regex| regex.is_match(&input)))
            }
            (Value::Object(type_name), "replace")
                if type_name.to_ascii_lowercase().starts_with("regex:") =>
            {
                let pattern = type_name.split_once(':').map_or("", |(_, value)| value);
                let input = args.first().map_or_else(String::new, Value::as_string);
                let replacement = args.get(1).map_or_else(String::new, Value::as_string);
                Value::String(Regex::new(pattern).map_or(input.clone(), |regex| {
                    regex.replace_all(&input, replacement.as_str()).into_owned()
                }))
            }
            (Value::Object(type_name), "invoke" | "invokereturnasis")
                if type_name.to_ascii_lowercase().starts_with("scriptblock:") =>
            {
                let script = type_name.split_once(':').map_or("", |(_, value)| value);
                self.execute_source(script, host, depth + 1)?
                    .unwrap_or(Value::Null)
            }
            (Value::Object(type_name), "getfield" | "getmethod" | "getproperty")
                if type_name.to_ascii_lowercase().starts_with("type:") =>
            {
                let name = args.first().map_or_else(String::new, Value::as_string);
                Value::Object(format!("ReflectionMember:{name}"))
            }
            (Value::Object(type_name), "gettype")
                if type_name.to_ascii_lowercase().starts_with("assembly:") =>
            {
                let name = args.first().map_or_else(String::new, Value::as_string);
                Value::Object(format!("Type:{name}"))
            }
            (Value::Object(type_name), "gettypes")
                if type_name.to_ascii_lowercase().starts_with("assembly:") =>
            {
                Value::Array(vec![
                    Value::Object("Type:System.Management.Automation.AmsiUtils".into()),
                    Value::Object("Type:System.Diagnostics.Eventing.EventProvider".into()),
                ])
            }
            (_, "gettype") => Value::Object(format!("Type:{}", receiver.type_name())),
            (Value::Object(type_name), "setvalue" | "invoke")
                if type_name
                    .to_ascii_lowercase()
                    .starts_with("reflectionmember:") =>
            {
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    &format!("modeled reflection mutation through {type_name}"),
                );
                Value::Null
            }
            (Value::Object(type_name), "getfunctionpointer")
                if type_name.eq_ignore_ascii_case("RuntimeMethodHandle") =>
            {
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    "modeled runtime method function pointer retrieval",
                );
                Value::Object("NativePointer:Modeled".into())
            }
            _ => return Ok(DotNetDispatch::NotHandled),
        };
        Ok(DotNetDispatch::Handled(value))
    }

    fn update_dotnet_properties(
        &mut self,
        receiver_expression: &str,
        updates: impl IntoIterator<Item = (String, Value)>,
    ) {
        if !receiver_expression.trim_start().starts_with('$') {
            return;
        }
        let name = crate::syntax::normalize_variable(receiver_expression);
        let Some(Value::Map(properties)) = self.variables.get_mut(&name) else {
            return;
        };
        properties.extend(updates);
    }
}

fn normalize_type(type_name: &str) -> String {
    type_name
        .trim()
        .trim_matches(['[', ']'])
        .strip_prefix("System.")
        .unwrap_or(type_name.trim().trim_matches(['[', ']']))
        .to_ascii_lowercase()
}

fn map_type(values: &BTreeMap<String, Value>) -> Option<&str> {
    values.get("__type").and_then(|value| match value {
        Value::String(value) => Some(value.as_str()),
        _ => None,
    })
}

fn map_property<'a>(values: &'a BTreeMap<String, Value>, name: &str) -> Option<&'a Value> {
    values
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn modeled_type(value: &Value) -> Option<&str> {
    match value {
        Value::Object(value) => Some(value),
        Value::Map(values) => map_type(values),
        _ => None,
    }
}

fn stream_data(values: &BTreeMap<String, Value>) -> Vec<u8> {
    if let Some(value) = values.get("Data") {
        return match value {
            Value::Map(stream) => stream_data(stream),
            value => value.as_bytes(),
        };
    }
    if let Some(Value::Map(stream)) = values.get("Stream") {
        return stream_data(stream);
    }
    Vec::new()
}

fn aes_transform(values: &BTreeMap<String, Value>, encrypt: bool) -> Value {
    Value::Map(
        [
            ("__type".into(), Value::String("AesTransform".into())),
            (
                "Key".into(),
                values.get("Key").cloned().unwrap_or(Value::Null),
            ),
            (
                "IV".into(),
                values.get("IV").cloned().unwrap_or(Value::Null),
            ),
            ("Encrypt".into(), Value::Bool(encrypt)),
        ]
        .into_iter()
        .collect(),
    )
}

fn decode_encoding(type_name: &str, bytes: &[u8]) -> Value {
    let encoding = type_name
        .split_once(':')
        .map_or("", |(_, encoding)| encoding)
        .to_ascii_lowercase();
    Value::String(match encoding.as_str() {
        "unicode" | "utf-16" | "utf-16le" | "1200" => decode_utf16_le(bytes),
        "bigendianunicode" | "utf-16be" | "1201" => decode_utf16_be(bytes),
        "utf-32" | "utf-32le" | "12000" => decode_utf32_le(bytes),
        "utf-32be" | "12001" => decode_utf32_be(bytes),
        "ascii" | "20127" => decode_ascii(bytes.to_vec()),
        _ => decode_utf8(bytes),
    })
}

fn encode_encoding(type_name: &str, input: &str) -> Value {
    let encoding = type_name
        .split_once(':')
        .map_or("", |(_, encoding)| encoding)
        .to_ascii_lowercase();
    Value::Bytes(match encoding.as_str() {
        "unicode" | "utf-16" | "utf-16le" | "1200" => encode_utf16_le(input),
        "bigendianunicode" | "utf-16be" | "1201" => encode_utf16_be(input),
        "utf-32" | "utf-32le" | "12000" => encode_utf32_le(input),
        "utf-32be" | "12001" => encode_utf32_be(input),
        "ascii" | "20127" => input.bytes().collect(),
        _ => encode_utf8(input),
    })
}

fn percent_encode(input: &str) -> String {
    input
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

fn expand_environment_variables(input: &str, host: &dyn Host) -> String {
    let mut output = String::with_capacity(input.len());
    let mut remainder = input;
    while let Some(start) = remainder.find('%') {
        output.push_str(&remainder[..start]);
        let after = &remainder[start + 1..];
        let Some(end) = after.find('%') else {
            output.push_str(&remainder[start..]);
            return output;
        };
        let name = &after[..end];
        if let Some(value) = host.environment(name) {
            output.push_str(value);
        } else {
            output.push('%');
            output.push_str(name);
            output.push('%');
        }
        remainder = &after[end + 1..];
    }
    output.push_str(remainder);
    output
}

fn is_reflection_or_evasion(type_name: &str, method: &str) -> bool {
    [
        "amsiutils",
        "eventprovider",
        "marshal",
        "runtime.interopservices",
        "reflection",
        "methodhandle",
        "virtualalloc",
        "virtualprotect",
        "writeprocessmemory",
        "createremotethread",
        "createthread",
        "ntallocatevirtualmemory",
        "scancontent",
        "amsiinitfailed",
        "m_enabled",
    ]
    .iter()
    .any(|needle| type_name.contains(needle) || method.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use emulator_core::{AnalysisLimits, VirtualHost};

    #[test]
    fn models_base64_and_compression_static_calls() {
        let mut host = VirtualHost::new(AnalysisLimits::default());
        let encoded = PowerShellEmulator::eval_extended_static_call(
            "Convert",
            "ToBase64String",
            &[Value::Bytes(b"safe".to_vec())],
            &mut host,
            0,
        )
        .unwrap();

        assert!(matches!(
            encoded,
            DotNetDispatch::Handled(Value::String(value)) if value == "c2FmZQ=="
        ));
    }
}
