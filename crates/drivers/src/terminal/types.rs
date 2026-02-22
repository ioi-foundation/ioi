use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Debug)]
pub enum ProcessStreamChannel {
    Stdout,
    Stderr,
    Status,
}

impl ProcessStreamChannel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
            Self::Status => "status",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProcessStreamChunk {
    pub channel: ProcessStreamChannel,
    pub chunk: String,
    pub seq: u64,
    pub is_final: bool,
    pub exit_code: Option<i32>,
}

pub type ProcessStreamObserver = Arc<dyn Fn(ProcessStreamChunk) + Send + Sync>;

#[derive(Clone)]
pub struct CommandExecutionOptions {
    pub timeout: Duration,
    pub stream_observer: Option<ProcessStreamObserver>,
    pub stdin_data: Option<Vec<u8>>,
}

impl Default for CommandExecutionOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            stream_observer: None,
            stdin_data: None,
        }
    }
}

impl CommandExecutionOptions {
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_stream_observer(mut self, stream_observer: Option<ProcessStreamObserver>) -> Self {
        self.stream_observer = stream_observer;
        self
    }

    pub fn with_stdin_data(mut self, stdin_data: Option<Vec<u8>>) -> Self {
        self.stdin_data = stdin_data;
        self
    }
}
