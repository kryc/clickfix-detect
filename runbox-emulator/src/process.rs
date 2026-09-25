use emulator_core::{
    AnalysisLimits, ArtifactKind, Engine, EventKind, Host, HostError, Ioc, NetworkIntent,
    NetworkRequest, NetworkResponse, ProcessIntent, ProcessResult, TraceEvent,
};

use crate::command_line::quote_argument;
use crate::{Runbox, RunboxError};

impl Runbox {
    pub(crate) fn queue_process(
        &mut self,
        program: &str,
        args: Vec<String>,
        origin: &str,
        depth: usize,
    ) -> Result<(), RunboxError> {
        let command_line = std::iter::once(program.to_owned())
            .chain(args.iter().map(|argument| quote_argument(argument)))
            .collect::<Vec<_>>()
            .join(" ");
        self.host.process_intent(ProcessIntent {
            program: program.into(),
            args,
            command_line,
            origin: origin.into(),
            depth: depth + 1,
            stdin: Vec::new(),
            current_directory: String::new(),
        })?;
        Ok(())
    }
}

impl Host for Runbox {
    fn limits(&self) -> &AnalysisLimits {
        self.host.limits()
    }

    fn consume_step(
        &mut self,
        engine: Engine,
        depth: usize,
        operation: &str,
    ) -> Result<(), HostError> {
        self.host.consume_step(engine, depth, operation)
    }

    fn emit(&mut self, event: TraceEvent) {
        self.host.emit(event);
    }

    fn add_ioc(&mut self, ioc: Ioc) {
        self.host.add_ioc(ioc);
    }

    fn add_artifact(
        &mut self,
        kind: ArtifactKind,
        name: &str,
        media_type: &str,
        bytes: &[u8],
        depth: usize,
    ) -> usize {
        self.host.add_artifact(kind, name, media_type, bytes, depth)
    }

    fn write_file(
        &mut self,
        path: &str,
        bytes: &[u8],
        append: bool,
        engine: Engine,
        depth: usize,
    ) -> Result<(), HostError> {
        self.host.write_file(path, bytes, append, engine, depth)
    }

    fn read_file(&mut self, path: &str, engine: Engine, depth: usize) -> Option<Vec<u8>> {
        self.host.read_file(path, engine, depth)
    }

    fn delete_file(&mut self, path: &str, engine: Engine, depth: usize) -> bool {
        self.host.delete_file(path, engine, depth)
    }

    fn list_files(&mut self, prefix: &str, engine: Engine, depth: usize) -> Vec<String> {
        self.host.list_files(prefix, engine, depth)
    }

    fn create_directory(
        &mut self,
        path: &str,
        engine: Engine,
        depth: usize,
    ) -> Result<(), HostError> {
        self.host.create_directory(path, engine, depth)
    }

    fn directory_exists(&self, path: &str) -> bool {
        self.host.directory_exists(path)
    }

    fn list_directories(&mut self, prefix: &str, engine: Engine, depth: usize) -> Vec<String> {
        self.host.list_directories(prefix, engine, depth)
    }

    fn delete_directory(
        &mut self,
        path: &str,
        recurse: bool,
        engine: Engine,
        depth: usize,
    ) -> bool {
        self.host.delete_directory(path, recurse, engine, depth)
    }

    fn register_executable(
        &mut self,
        path: &str,
        engine: Engine,
        depth: usize,
    ) -> Result<(), HostError> {
        self.host.register_executable(path, engine, depth)
    }

    fn is_executable(&self, path: &str) -> bool {
        self.host.is_executable(path)
    }

    fn set_environment(&mut self, name: &str, value: &str) {
        self.host.set_environment(name, value);
    }

    fn environment(&self, name: &str) -> Option<&str> {
        self.host.environment(name)
    }

    fn environment_entries(&self) -> Vec<(String, String)> {
        self.host.environment_entries()
    }

    fn remove_environment(&mut self, name: &str) -> bool {
        self.host.remove_environment(name)
    }

    fn write_registry(&mut self, path: &str, value: &str, engine: Engine, depth: usize) {
        self.host.write_registry(path, value, engine, depth);
    }

    fn read_registry(&mut self, path: &str, engine: Engine, depth: usize) -> Option<String> {
        self.host.read_registry(path, engine, depth)
    }

    fn list_registry(
        &mut self,
        prefix: &str,
        engine: Engine,
        depth: usize,
    ) -> Vec<(String, String)> {
        self.host.list_registry(prefix, engine, depth)
    }

    fn delete_registry(
        &mut self,
        path: &str,
        recurse: bool,
        engine: Engine,
        depth: usize,
    ) -> usize {
        self.host.delete_registry(path, recurse, engine, depth)
    }

    fn network_intent(&mut self, intent: NetworkIntent) {
        self.host.network_intent(intent);
    }

    fn network_request(&mut self, intent: NetworkIntent) -> Option<NetworkResponse> {
        self.host.network_request(intent)
    }

    fn network_request_detailed(&mut self, request: NetworkRequest) -> Option<NetworkResponse> {
        self.host.network_request_detailed(request)
    }

    fn process_intent(&mut self, intent: ProcessIntent) -> Result<(), HostError> {
        self.host.process_intent(intent)
    }

    fn process_request(
        &mut self,
        intent: ProcessIntent,
    ) -> Result<Option<ProcessResult>, HostError> {
        self.host.record_process_request(&intent)?;
        let trace_start = self.host.snapshot().trace.len();
        let mut result = ProcessResult::default();
        if let Err(error) = self.dispatch_process(&intent) {
            result.exit_code = 1;
            result.stderr.push(error.to_string());
        }
        let snapshot = self.host.snapshot();
        for event in snapshot.trace.iter().skip(trace_start) {
            if let Some(exit_code) = event
                .data
                .get("exit_code")
                .and_then(|value| value.parse::<i32>().ok())
            {
                result.exit_code = exit_code;
            }
            if event.kind == EventKind::Output {
                let value = event
                    .data
                    .get("value")
                    .cloned()
                    .unwrap_or_else(|| event.message.clone());
                if event
                    .data
                    .get("stream")
                    .is_some_and(|stream| stream == "stderr")
                {
                    result.stderr.push(value);
                } else {
                    result.stdout.push(value);
                }
            }
            if event.kind == EventKind::Unsupported
                && event.message.starts_with("unsupported executable:")
            {
                result.exit_code = 1;
                result.stderr.push(event.message.clone());
            }
        }
        Ok(Some(result))
    }

    fn unsupported(&mut self, engine: Engine, depth: usize, operation: &str) {
        self.host.unsupported(engine, depth, operation);
    }

    fn warning(&mut self, warning: String) {
        self.host.warning(warning);
    }
}
