use anyhow::Result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt};

use super::types::{ProcessStreamChannel, ProcessStreamChunk, ProcessStreamObserver};

pub(crate) async fn read_stream<R: AsyncRead + Unpin>(
    mut reader: R,
    channel: ProcessStreamChannel,
    seq: Arc<AtomicU64>,
    observer: Option<ProcessStreamObserver>,
) -> Result<Vec<u8>> {
    let mut buf = [0u8; 2048];
    let mut out = Vec::<u8>::new();
    loop {
        let read = reader.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        out.extend_from_slice(&buf[..read]);
        if let Some(cb) = observer.as_ref() {
            let seq_value = seq.fetch_add(1, Ordering::Relaxed);
            (cb)(ProcessStreamChunk {
                channel: channel.clone(),
                chunk: String::from_utf8_lossy(&buf[..read]).to_string(),
                seq: seq_value,
                is_final: false,
                exit_code: None,
            });
        }
    }
    Ok(out)
}

pub(crate) fn combine_success_output(stdout_text: &str, stderr_text: &str) -> String {
    let stdout = stdout_text.trim_end_matches('\n');
    let stderr = stderr_text.trim_end_matches('\n');

    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => String::new(),
        (false, true) => stdout.to_string(),
        (true, false) => format!("Stderr:\n{}", stderr),
        (false, false) => format!("Stdout:\n{}\nStderr:\n{}", stdout, stderr),
    }
}
