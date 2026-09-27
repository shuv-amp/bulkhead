//! The Rust core must reproduce the Python reference's golden outputs exactly:
//! reference/golden/expected.txt (golden cases) and
//! reference/golden/regressions-expected.txt (regression fixtures).

use std::fs;
use std::path::PathBuf;

#[test]
fn golden_vectors_match_python_reference() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../reference/golden");
    let cases = fs::read_to_string(root.join("cases.txt")).expect("cases.txt");
    let expected = fs::read_to_string(root.join("expected.txt")).expect("expected.txt");
    let mut s = bulkhead_diff::Session::default();
    let got: Vec<String> = cases
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| s.run_line(l).unwrap_or_else(|e| format!("ERR {e}")))
        .collect();
    let want: Vec<&str> = expected.lines().collect();
    assert_eq!(got.len(), want.len(), "number of outputs");
    for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
        assert_eq!(g, w, "golden line {i}");
    }
}

#[test]
fn every_regression_fixture_reproduces_the_reference_output() {
    // reference/golden/regressions-expected.txt holds each fixture's output
    // under the current Python reference (`python3 reference/golden.py` writes
    // it and `--check` keeps it fresh). The Rust core must match it line for line.
    let reference = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../reference");
    let dir = reference.join("regressions");
    let expected = fs::read_to_string(reference.join("golden/regressions-expected.txt"))
        .expect("regressions-expected.txt");
    let mut checked = 0;
    for block in expected.split("== ").filter(|b| !b.trim().is_empty()) {
        let mut lines = block.lines();
        let name = lines.next().unwrap().trim();
        let want: Vec<&str> = lines.filter(|l| !l.is_empty()).collect();
        let text = fs::read_to_string(dir.join(name)).unwrap();
        let mut s = bulkhead_diff::Session::default();
        let got: Vec<String> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| s.run_line(l).unwrap_or_else(|e| format!("ERR {e}")))
            .collect();
        assert_eq!(got, want, "{name}");
        checked += 1;
    }
    let fixtures = fs::read_dir(&dir)
        .unwrap()
        .filter(|e| {
            let p = e.as_ref().unwrap().path();
            p.extension().and_then(|x| x.to_str()) == Some("txt")
        })
        .count();
    assert_eq!(checked, fixtures, "every fixture has an expected output");
}
