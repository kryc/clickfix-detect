use emulator_core::{
    ArtifactKind, CausalEdge, CausalEntity, CausalRelation, Engine, Host, HostError, NetworkIntent,
};
use regex::Regex;
use std::sync::LazyLock;

use crate::command_line::trim_url_punctuation;
use crate::Runbox;

static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bhttps?://[^\s"'<>`]+"#).expect("valid URL regex"));

pub(crate) fn first_url(input: &str) -> Option<String> {
    URL_RE
        .find(input)
        .map(|matched| trim_url_punctuation(matched.as_str()))
}

pub(crate) fn urls(input: &str) -> impl Iterator<Item = String> + '_ {
    URL_RE
        .find_iter(input)
        .map(|matched| trim_url_punctuation(matched.as_str()))
}

impl Runbox {
    pub(crate) fn latest_network_source(&self) -> Vec<CausalEntity> {
        self.host
            .latest_network_activity_id()
            .map(|id| vec![CausalEntity::NetworkActivity { id }])
            .unwrap_or_default()
    }

    pub(crate) fn add_network_artifact(
        &mut self,
        kind: ArtifactKind,
        name: &str,
        media_type: &str,
        bytes: &[u8],
        depth: usize,
    ) -> usize {
        let sources = self.latest_network_source();
        let id = self.host.add_artifact(kind, name, media_type, bytes, depth);
        for source in sources {
            self.host.add_causal_edge(CausalEdge {
                from: source,
                to: CausalEntity::Artifact { id },
                relation: CausalRelation::Downloaded,
                depth,
            });
        }
        id
    }

    pub(crate) fn write_network_file(
        &mut self,
        path: &str,
        bytes: &[u8],
        engine: Engine,
        depth: usize,
    ) -> Result<(), HostError> {
        let sources = self.latest_network_source();
        self.host.write_file_from(
            path,
            bytes,
            false,
            engine,
            depth,
            &sources,
            CausalRelation::Downloaded,
        )
    }

    pub(crate) fn inspect_pe(&mut self, path: &str, engine: Engine, depth: usize) {
        let Some(bytes) = self.host.read_file(path, engine, depth) else {
            self.host.unsupported(
                engine,
                depth,
                &format!("DLL is absent from the virtual filesystem: {path}"),
            );
            return;
        };
        if !bytes.starts_with(b"MZ") {
            self.host
                .unsupported(engine, depth, &format!("{path} is not a PE image"));
            return;
        }
        self.host.inspect_binary_bytes(path, &bytes, engine, depth);
        let strings = ascii_strings(&bytes, 8);
        for value in strings {
            self.record_urls(&value, "static PE string", depth);
        }
    }

    pub(crate) fn record_urls(&mut self, input: &str, origin: &str, depth: usize) {
        for url in urls(input) {
            self.host.network_intent(NetworkIntent {
                method: "GET".into(),
                url,
                origin: origin.into(),
                depth,
            });
        }
    }
}

fn ascii_strings(bytes: &[u8], minimum_length: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();
    for byte in bytes {
        if byte.is_ascii_graphic() || *byte == b' ' {
            current.push(*byte);
        } else {
            if current.len() >= minimum_length {
                strings.push(String::from_utf8_lossy(&current).into_owned());
            }
            current.clear();
        }
    }
    if current.len() >= minimum_length {
        strings.push(String::from_utf8_lossy(&current).into_owned());
    }
    strings
}
