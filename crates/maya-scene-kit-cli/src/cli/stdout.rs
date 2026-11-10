use std::io::{self, Write};

pub(super) struct Output {
    writer: io::BufWriter<io::StdoutLock<'static>>,
    error: Option<io::Error>,
}

impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.error.is_none() {
            if let Err(error) = self.writer.write_all(bytes) {
                self.error = Some(error);
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.error.is_none() {
            if let Err(error) = self.writer.flush() {
                self.error = Some(error);
            }
        }
        Ok(())
    }
}

pub(super) fn with_stdout(command: impl FnOnce(&mut Output) -> i32) -> i32 {
    let mut output = Output {
        writer: io::BufWriter::with_capacity(256 * 1024, io::stdout().lock()),
        error: None,
    };
    let code = command(&mut output);
    let _ = output.flush();
    let error = output.error;
    // Discard buffered bytes after failure instead of retrying during drop.
    let _ = output.writer.into_parts();
    match error {
        Some(error) if error.kind() != io::ErrorKind::BrokenPipe => {
            let _ = writeln!(
                io::stderr().lock(),
                "error: failed to write stdout: {error}"
            );
            1
        }
        _ => code,
    }
}
