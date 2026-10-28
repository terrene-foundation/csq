//! Bounded hook stdin collection. The one-shot CLI must exit after emitting its
//! decision: a deadline cannot cancel an OS stdin read already blocked in a thread.
use super::dispatch::MAX_PAYLOAD_BYTES;
use std::io::Read;
use std::sync::mpsc;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadReadError {
    Limit,
    Io,
    Timeout,
}

pub fn read_payload_until(
    reader: impl Read + Send + 'static,
    deadline: Instant,
) -> Result<Vec<u8>, PayloadReadError> {
    if Instant::now() >= deadline {
        return Err(PayloadReadError::Timeout);
    }
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("csq-hook-input".into())
        .spawn(move || {
            let mut bytes = Vec::new();
            let result = match reader
                .take(MAX_PAYLOAD_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
            {
                Err(_) => Err(PayloadReadError::Io),
                Ok(_) if bytes.len() > MAX_PAYLOAD_BYTES => Err(PayloadReadError::Limit),
                Ok(_) => Ok(bytes),
            };
            let _ = sender.send(result);
        })
        .map_err(|_| PayloadReadError::Io)?;
    let result = receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => PayloadReadError::Timeout,
            mpsc::RecvTimeoutError::Disconnected => PayloadReadError::Io,
        })?;
    if Instant::now() >= deadline {
        return Err(PayloadReadError::Timeout);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};
    use std::time::Duration;

    #[test]
    fn hook_input_collector_enforces_byte_limit_and_keeps_original_bytes() {
        let bytes = b"{ \"hook_event_name\": \"Stop\" }\n".to_vec();
        assert_eq!(
            read_payload_until(
                Cursor::new(bytes.clone()),
                Instant::now() + Duration::from_secs(1)
            ),
            Ok(bytes)
        );
        assert_eq!(
            read_payload_until(
                Cursor::new(vec![0; MAX_PAYLOAD_BYTES + 1]),
                Instant::now() + Duration::from_secs(1)
            ),
            Err(PayloadReadError::Limit)
        );
    }

    #[test]
    fn hook_input_collector_reports_io_failure() {
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
        assert_eq!(
            read_payload_until(Broken, Instant::now() + Duration::from_secs(1)),
            Err(PayloadReadError::Io)
        );
    }

    #[test]
    fn hook_input_collector_returns_before_blocked_reader_finishes() {
        struct Blocked(mpsc::Receiver<()>);
        impl Read for Blocked {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                self.0.recv().map_err(|_| io::ErrorKind::BrokenPipe)?;
                Ok(0)
            }
        }
        let (release, wait) = mpsc::channel();
        let start = Instant::now();
        assert_eq!(
            read_payload_until(Blocked(wait), start + Duration::from_millis(20)),
            Err(PayloadReadError::Timeout)
        );
        // Release the private fixture thread even if the assertion unwinds: sender
        // drop also unblocks recv. This is not a live stdin/process fixture.
        let _ = release.send(());
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
