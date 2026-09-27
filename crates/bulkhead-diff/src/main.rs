//! Reads protocol lines on stdin, writes one result line per input line.
use std::io::{self, BufRead, BufWriter, Write};

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut session = bulkhead_diff::Session::default();
    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        match session.run_line(trimmed) {
            Ok(r) => writeln!(out, "{r}").unwrap(),
            Err(e) => writeln!(out, "ERR {e}").unwrap(),
        }
    }
    out.flush().unwrap();
}
