use crate::syntax::{RedirectStream, RedirectTarget, Redirection};
use crate::{Host, PowerShellEmulator, PowerShellError, Value};

impl PowerShellEmulator {
    pub(crate) fn execute_redirected(
        &mut self,
        command: &str,
        redirections: &[Redirection],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Option<Value>, PowerShellError> {
        let error_start = self.error_output.len();
        let outcome = self.execute_script_collect(command, host, depth);
        let errors = self
            .error_output
            .split_off(error_start)
            .into_iter()
            .map(Value::String)
            .collect::<Vec<_>>();
        let (result, mut output, execution_error) = match outcome {
            Ok((result, output)) => (result, output, None),
            Err(error) => {
                let message = Value::String(error.to_string());
                (None, Vec::new(), Some((error, message)))
            }
        };
        let mut errors = errors;
        if let Some((_, message)) = &execution_error {
            errors.push(message.clone());
        }

        let merge_errors = redirections.iter().any(|redirection| {
            redirection.stream == RedirectStream::Error
                && redirection.target == RedirectTarget::Merge(RedirectStream::Success)
        });
        if merge_errors {
            output.extend(errors.clone());
        }

        let mut success_redirected = false;
        let mut errors_redirected = false;
        for redirection in redirections {
            let RedirectTarget::File(path) = &redirection.target else {
                continue;
            };
            let values = match redirection.stream {
                RedirectStream::Success => {
                    success_redirected = true;
                    output.as_slice()
                }
                RedirectStream::Error => {
                    errors_redirected = true;
                    errors.as_slice()
                }
                RedirectStream::All => {
                    success_redirected = true;
                    errors_redirected = true;
                    let mut combined = output.clone();
                    combined.extend(errors.clone());
                    self.write_redirected_output(path, &combined, redirection.append, host, depth)?;
                    continue;
                }
                RedirectStream::Other(_) => &[],
            };
            self.write_redirected_output(path, values, redirection.append, host, depth)?;
        }

        if let Some((error, _)) = execution_error {
            if !errors_redirected && !merge_errors {
                return Err(error);
            }
        }

        if success_redirected {
            Ok(None)
        } else if !output.is_empty() {
            Ok(Some(output_value(output)))
        } else {
            Ok(result)
        }
    }
}

fn output_value(mut values: Vec<Value>) -> Value {
    if values.len() == 1 {
        values.pop().unwrap_or(Value::Null)
    } else {
        Value::Array(values)
    }
}
