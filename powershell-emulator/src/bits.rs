use crate::parser::ParsedSource;
use crate::syntax::{find_switch, named_or_positional};
use crate::{Engine, Host, NetworkIntent, PowerShellEmulator, PowerShellError, Value};
use std::collections::BTreeMap;

pub(crate) enum BitsDispatch {
    NotHandled,
    Handled(Option<Value>),
}

#[derive(Debug, Clone)]
pub(crate) struct BitsJob {
    id: String,
    display_name: String,
    description: String,
    source: String,
    destination: String,
    state: String,
    bytes_total: usize,
    bytes_transferred: usize,
    error_description: String,
}

impl BitsJob {
    fn value(&self) -> Value {
        Value::Map(
            [
                ("__type".into(), Value::String("BitsJob".into())),
                ("JobId".into(), Value::String(self.id.clone())),
                (
                    "DisplayName".into(),
                    Value::String(self.display_name.clone()),
                ),
                (
                    "Description".into(),
                    Value::String(self.description.clone()),
                ),
                ("JobState".into(), Value::String(self.state.clone())),
                ("TransferType".into(), Value::String("Download".into())),
                (
                    "OwnerAccount".into(),
                    Value::String(r"ANALYSIS\analysis".into()),
                ),
                (
                    "BytesTotal".into(),
                    Value::Number(i64::try_from(self.bytes_total).unwrap_or(i64::MAX)),
                ),
                (
                    "BytesTransferred".into(),
                    Value::Number(i64::try_from(self.bytes_transferred).unwrap_or(i64::MAX)),
                ),
                ("FilesTotal".into(), Value::Number(1)),
                (
                    "FilesTransferred".into(),
                    Value::Number(i64::from(self.bytes_transferred == self.bytes_total)),
                ),
                ("Source".into(), Value::String(self.source.clone())),
                (
                    "Destination".into(),
                    Value::String(self.destination.clone()),
                ),
                (
                    "ErrorDescription".into(),
                    Value::String(self.error_description.clone()),
                ),
            ]
            .into_iter()
            .collect(),
        )
    }
}

impl PowerShellEmulator {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn execute_bits_command(
        &mut self,
        parser: &ParsedSource,
        command: &str,
        arguments: &[String],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<BitsDispatch, PowerShellError> {
        match command {
            "start-bitstransfer" => {
                let source =
                    self.eval_bits_argument(parser, arguments, &["-source"], 0, host, depth)?;
                let destination =
                    self.eval_bits_argument(parser, arguments, &["-destination"], 1, host, depth)?;
                let display_name = self.eval_bits_argument(
                    parser,
                    arguments,
                    &["-displayname"],
                    usize::MAX,
                    host,
                    depth,
                )?;
                let description = self.eval_bits_argument(
                    parser,
                    arguments,
                    &["-description"],
                    usize::MAX,
                    host,
                    depth,
                )?;
                self.bits_job_counter = self.bits_job_counter.saturating_add(1);
                let id = format!("00000000-0000-0000-0000-{:012}", self.bits_job_counter);
                let mut job = BitsJob {
                    id: id.clone(),
                    display_name: if display_name.is_empty() {
                        format!("BITS transfer {}", self.bits_job_counter)
                    } else {
                        display_name
                    },
                    description,
                    source: source.clone(),
                    destination: destination.clone(),
                    state: "Connecting".into(),
                    bytes_total: 0,
                    bytes_transferred: 0,
                    error_description: String::new(),
                };
                let response = host.network_request(NetworkIntent {
                    method: "GET".into(),
                    url: source,
                    origin: "PowerShell Start-BitsTransfer".into(),
                    depth,
                });
                let legacy_result = if let Some(response) = response {
                    job.bytes_total = response.body.len();
                    job.bytes_transferred = response.body.len();
                    job.state = "Transferred".into();
                    if destination.is_empty() {
                        Value::Bytes(response.body)
                    } else {
                        host.write_file(
                            &destination,
                            &response.body,
                            false,
                            Engine::PowerShell,
                            depth,
                        )?;
                        Value::String(destination)
                    }
                } else {
                    job.state = "TransientError".into();
                    job.error_description = "Network access is blocked by the virtual host".into();
                    Value::Object("BlockedNetworkResponse".into())
                };
                let job_value = job.value();
                self.bits_jobs.insert(id, job);
                Ok(BitsDispatch::Handled(Some(
                    if find_switch(arguments, "-asynchronous").is_some() {
                        job_value
                    } else {
                        legacy_result
                    },
                )))
            }
            "get-bitstransfer" => {
                let name = self.eval_bits_argument(
                    parser,
                    arguments,
                    &["-name", "-displayname"],
                    usize::MAX,
                    host,
                    depth,
                )?;
                let values = self
                    .bits_jobs
                    .values()
                    .filter(|job| name.is_empty() || job.display_name.eq_ignore_ascii_case(&name))
                    .map(BitsJob::value)
                    .collect();
                Ok(BitsDispatch::Handled(Some(Value::Array(values))))
            }
            "complete-bitstransfer"
            | "remove-bitstransfer"
            | "suspend-bitstransfer"
            | "resume-bitstransfer" => {
                let references = self.bits_job_references(parser, arguments, host, depth)?;
                let ids = self.matching_bits_job_ids(&references);
                for id in ids {
                    match command {
                        "complete-bitstransfer" => {
                            if self
                                .bits_jobs
                                .get(&id)
                                .is_some_and(|job| job.state == "Transferred")
                            {
                                self.bits_jobs.remove(&id);
                            }
                        }
                        "remove-bitstransfer" => {
                            self.bits_jobs.remove(&id);
                        }
                        "suspend-bitstransfer" => {
                            if let Some(job) = self.bits_jobs.get_mut(&id) {
                                job.state = "Suspended".into();
                            }
                        }
                        "resume-bitstransfer" => {
                            if let Some(job) = self.bits_jobs.get_mut(&id) {
                                job.state = if job.bytes_total > 0
                                    && job.bytes_transferred == job.bytes_total
                                {
                                    "Transferred"
                                } else {
                                    "Queued"
                                }
                                .into();
                            }
                        }
                        _ => {}
                    }
                }
                Ok(BitsDispatch::Handled(Some(Value::Null)))
            }
            _ => Ok(BitsDispatch::NotHandled),
        }
    }

    fn eval_bits_argument(
        &mut self,
        parser: &ParsedSource,
        arguments: &[String],
        names: &[&str],
        position: usize,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<String, PowerShellError> {
        named_or_positional(arguments, names, position).map_or_else(
            || Ok(String::new()),
            |value| {
                self.eval_expression(parser, &value, host, depth)
                    .map(|value| value.as_string())
            },
        )
    }

    fn bits_job_references(
        &mut self,
        parser: &ParsedSource,
        arguments: &[String],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Vec<String>, PowerShellError> {
        let value = named_or_positional(arguments, &["-bitsjob"], 0)
            .map(|expression| self.eval_expression(parser, &expression, host, depth))
            .transpose()?
            .or_else(|| self.variables.get("input").cloned());
        Ok(value.map_or_else(Vec::new, |value| bits_references(&value)))
    }

    fn matching_bits_job_ids(&self, references: &[String]) -> Vec<String> {
        if references.is_empty() {
            return self.bits_jobs.keys().cloned().collect();
        }
        self.bits_jobs
            .iter()
            .filter(|(id, job)| {
                references.iter().any(|reference| {
                    id.eq_ignore_ascii_case(reference)
                        || job.display_name.eq_ignore_ascii_case(reference)
                })
            })
            .map(|(id, _)| id.clone())
            .collect()
    }
}

fn bits_references(value: &Value) -> Vec<String> {
    match value {
        Value::Array(values) => values.iter().flat_map(bits_references).collect(),
        Value::Map(values) => member(values, "JobId")
            .or_else(|| member(values, "DisplayName"))
            .into_iter()
            .collect(),
        value => vec![value.as_string()],
    }
}

fn member(values: &BTreeMap<String, Value>, name: &str) -> Option<String> {
    values
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_string())
}
