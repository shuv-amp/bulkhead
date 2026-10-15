#!/usr/bin/env python3
"""claims: the counts the docs state, checked against the tree.

    python3 tools/claims.py              # fail if any stated count is stale
    python3 tools/claims.py --self-test  # the matcher on planted drift

The Markdown files, the CI workflow and the status page state counts that go
stale as the code moves:
Kani harnesses, tests per suite, golden vectors, fuzz targets, findings. Each
count here is computed from the files themselves (a `#[kani::proof]`, a
`#[test]`, a row of `09 §4`), and each phrasing of it listed in RULES must
equal it wherever it appears, across line breaks too. A count stated in a new
phrasing is not checked until a rule names it; a rule that matches nothing
fails, so a reworded sentence can't leave its rule checking nothing. A test
counted here is a test function in the source that is not `#[ignore]`d; `09 §3`
gives the commands that run them.

A statement that is not of the current count (a dated past state, a subset) is
listed in KEPT with its reason and left as written. An entry there must match
exactly once: one that matches nothing fails, so the list can't go stale, and
one that matches twice would hide a current statement.

Standard library only.
"""
from __future__ import annotations

import os
import argparse
import re
import subprocess
import sys
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
CORE = "crates/bulkhead-core"


def read(path: str) -> str:
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return f.read()


def files(directory: str, suffix: str) -> list:
    """Every file under `directory` (recursively, never into build output)
    ending in `suffix`, sorted."""
    out = []
    for d, dirs, names in os.walk(os.path.join(ROOT, directory)):
        dirs[:] = [x for x in dirs if x not in {".git", "target", "node_modules"}]
        out += [os.path.relpath(os.path.join(d, n), ROOT) for n in names if n.endswith(suffix)]
    return sorted(out)


# A string (raw or not) or char literal, or a comment: matched as one token,
# so a "/*" in a string or a '"' never starts anything. (Rust nests block
# comments; this reads the first `*/` as the end, so don't nest them around tests.)
LITERAL_OR_COMMENT = re.compile(r'b?r(#*)".*?"\1|"(?:[^"\\]|\\.)*"|\'(?:[^\'\\\n]|\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|.))\'|//[^\n]*|/\*.*?\*/', re.S)
FN = re.compile(r'(?:pub(?:\([^)]*\))?\s+)?(?:(?:async|const|unsafe|extern(?:\s+"[^"]*")?)\s+)*fn\s+(\w+)')


def code(source: str) -> str:
    """Rust source without its comments (doc comments and their examples too)
    and literals (so no attribute holds a quoted bracket or word)."""
    return LITERAL_OR_COMMENT.sub("", source)


def functions(source: str) -> list:
    """(attributes, name) of each function that has attributes. An attribute's
    brackets may nest to any depth; anything but whitespace between two
    attributes, or between them and the `fn`, ends the run."""
    src, out, attrs, end = code(source), [], [], 0
    for m in re.finditer(r"#\[|\b(?:pub|async|const|unsafe|extern|fn)\b", src):
        if m.start() < end:
            continue
        if src[end:m.start()].strip():
            attrs = []
        if m.group(0) == "#[":
            depth, j = 0, m.start() + 1
            while j < len(src):
                depth += {"[": 1, "]": -1}.get(src[j], 0)
                if depth == 0:
                    break
                j += 1
            attrs.append(src[m.start():j + 1])
            end = j + 1
        else:
            f = FN.match(src, m.start())
            if f and attrs:
                out.append((attrs, f.group(1)))
            attrs, end = [], f.end() if f else m.end()
    return out


def tests_in(source: str) -> int:
    """Test functions that run by default: one marked `#[ignore]` is not counted.
    A function's attributes may come in any order; comments don't count.
    This reads the source, so a test under a `#[cfg]` counts whatever the cfg:
    after adding one, compare with what `cargo test` runs."""
    return sum(
        any(re.fullmatch(r"#\[\s*test\s*\]", a) for a in attrs) and not any(re.match(r"#\[\s*ignore\b", a) for a in attrs)
        for attrs, _ in functions(source)
    )


def kani_names(source: str) -> list:
    """The function name of each Kani harness, in order: `#[kani::proof]` or
    `#[kani::proof_for_contract(..)]`, either under a `cfg_attr`; not in a comment."""
    proof = re.compile(r"#\[\s*(?:cfg_attr\(.*,\s*)?kani::proof(?:_for_contract)?\b", re.S)
    return [name for attrs, name in functions(source) if any(proof.match(a) for a in attrs)]


def kani_table(text: str) -> tuple:
    """`09 §5.1`: the harness names its table lists, and how many are SMALL-WIDTH."""
    if "\n### 5.1 " not in text or "\n### 5.2 " not in text:
        raise SystemExit("claims: 09 has no '### 5.1 ' or '### 5.2 ' heading; update kani_table()")
    section = text.split("\n### 5.1 ", 1)[1].split("\n### 5.2 ", 1)[0]
    rows = re.findall(r"^\| `(\w+)` \| ([A-Z-]+)", section, re.M)
    return sorted(name for name, _ in rows), sum(domain == "SMALL-WIDTH" for _, domain in rows)


JS_LITERAL_OR_COMMENT = re.compile(r"""("|')(?:(?!\1)[^\\\n]|\\.)*\1|`(?:[^`\\]|\\.)*`|//[^\n]*|/\*.*?\*/""", re.S)


def js_tests_in(source: str) -> int:
    """`test(` or `it(` calls at the start of a line, less those skipped or todo
    on that line; not in a comment or a string. A test registered in a loop
    counts once, and options on a later line are not read: write such tests out."""
    # A string becomes its empty self (`skip: ""` still reads as skipped); a
    # comment or a template literal, which may span lines, goes.
    src = JS_LITERAL_OR_COMMENT.sub(lambda m: 2 * m.group(1) if m.group(1) else "", source)
    return sum(
        bool(re.match(r"\s*(?:test|it)\(", line)) and not re.search(r"""\b(?:skip|todo)\s*:\s*(?:true|['"])""", line)
        for line in src.splitlines()
    )


def js_tests(*paths: str) -> int:
    return sum(js_tests_in(read(p)) for p in paths)


def rust_tests(*paths: str) -> int:
    return sum(tests_in(read(p)) for p in paths)


def findings(text: str) -> int:
    """Rows of the `09 §4` table, which must be numbered 1..n without a gap."""
    if "\n## 4. " not in text or "\n## 5. " not in text:
        raise SystemExit("claims: 09 has no '## 4. ' or '## 5. ' heading; update findings()")
    section = text.split("\n## 4. ", 1)[1].split("\n## 5. ", 1)[0]
    ids = [int(m) for m in re.findall(r"^\| ?(\d+) ?\|", section, re.M)]
    for want, got in zip(range(1, len(ids) + 1), ids):
        if got != want:
            raise SystemExit(f"claims: 09 §4 is not numbered 1..n: row {want} is numbered {got}")
    return len(ids)


# Each test file the docs count, by the count it feeds; and each one they
# don't, with the reason. A test file in neither list fails, so a new suite
# can't go uncounted.
TEST_FILES = {
    f"{CORE}/tests/properties.rs": "property",
    f"{CORE}/tests/exhaustive.rs": "exhaustive",
    f"{CORE}/tests/floor.rs": "floor_core",
    f"{CORE}/tests/units.rs": "targeted",
    f"{CORE}/tests/adversarial.rs": "adversarial",
    f"{CORE}/tests/cascade.rs": "cascade",
    "programs/tests/tests/floor.rs": "floor_programs",
    "programs/tests/tests/vault.rs": "vault_programs",
}
UNCOUNTED = {
    "programs/tests/tests/differential.rs": "a program-vs-model differential, reported in steps (09 §2)",
    "programs/tests/tests/differential_wide.rs": "a program-vs-model differential, reported in steps (09 §2)",
    "programs/tests/tests/floor_differential.rs": "a program-vs-model differential, reported in steps (09 §2)",
    "programs/tests/tests/curve_vectors.rs": "an #[ignore]d generator of the curve vectors, run by hand",
    "programs/tests/tests/e2e_world.rs": "an #[ignore]d builder of the end-to-end world, run by hand",
}


def truth() -> dict:
    """Every count a claim can name, computed from the tree."""
    # What cargo builds as a test target: tests/x.rs and tests/x/main.rs.
    found = [
        p
        for d in (f"{CORE}/tests", "programs/tests/tests")
        for p in files(d, ".rs")
        if os.path.dirname(p) == d or (os.path.basename(p) == "main.rs" and os.path.dirname(os.path.dirname(p)) == d)
    ]
    unmapped = sorted(set(found) - set(TEST_FILES) - set(UNCOUNTED))
    if unmapped:
        raise SystemExit(f"claims: test files in neither TEST_FILES nor UNCOUNTED: {unmapped}")
    t = {key: 0 for key in TEST_FILES.values()}
    for path, key in TEST_FILES.items():
        t[key] += rust_tests(path)
    t.update({
        # What `golden.py --check` compares: one output line per case, one block per fixture.
        "golden": len([l for l in read("reference/golden/expected.txt").splitlines() if l.strip()]),
        "regressions": len(re.findall(r"^== ", read("reference/golden/regressions-expected.txt"), re.M)),
        "client": js_tests(*files("cloud/test", ".test.mjs")),
        "fuzz": len(re.findall(r"^\[\[bin\]\]", read("fuzz/Cargo.toml"), re.M)),
        "findings": findings(read("docs/09-VERIFICATION.md")),
    })
    t["programs"] = t["floor_programs"] + t["vault_programs"]
    names = sorted(n for p in files(f"{CORE}/src", ".rs") for n in kani_names(read(p)))
    t["kani"] = len(names)
    listed, t["kani_small"] = kani_table(read("docs/09-VERIFICATION.md"))
    if names != listed:
        missing, extra = sorted(set(names) - set(listed)), sorted(set(listed) - set(names))
        raise SystemExit(f"claims: 09 §5.1 must list each Kani harness once; missing {missing}, not harnesses {extra}")
    t["kani_full"] = t["kani"] - t["kani_small"]
    return t


# (pattern, the count each group must equal). Patterns are matched in every
# document, so a new sentence in an old phrasing is checked too. A space in a
# pattern matches any whitespace, a line break included; a number may have
# thousands separators. A result "passed/total" must be all passed: a run with
# failures is a red CI, not a state the docs describe. After raising a total,
# run the check before writing the new result.
D = r"(\d{1,3}(?:,\d{3})+|\d+)"
N = r"(?<![\w.,])" + D  # a whole number, not the tail of "5.1" or "S10"

RULES = [
    (N + r" Kani (?:harnesses|proofs)", ["kani"]),
    (r"Kani_proofs-(\d+)%2F(\d+)", ["kani", "kani"]),
    (r"\*\*(\d+)/(\d+) harnesses verified\*\*", ["kani", "kani"]),
    (r"Bounded proofs \(Kani\)\*\* \| (\d+) harnesses[^|]*\| \*\*(\d+)/(\d+) verified\*\*", ["kani", "kani", "kani"]),
    (r"\((\d+) for every value of their types\)", ["kani_full"]),
    (r"harnesses: logic at full width, (\d+) at small width", ["kani_small"]),
    (r"Kani, (\d+) harnesses", ["kani"]),
    (r"Kani harnesses \((\d+)\)", ["kani"]),
    (r"Complete - (\d+) successfully verified harnesses, 0 failures, (\d+) total", ["kani", "kani"]),
    (r"The core's source \| The (\d+) harnesses", ["kani"]),
    (r"checking of the core's (\d+) harnesses", ["kani"]),
    (N + r" property tests", ["property"]),
    (r"\*\*Property tests\*\* \| (\d+) tests", ["property"]),
    (r"Property tests \([^)|]*\) \| (\d+)/(\d+)", ["property", "property"]),
    (N + r" exhaustive tests", ["exhaustive"]),
    (r"\*\*Exhaustive checks\*\* \| (\d+) tests", ["exhaustive"]),
    (r"Exhaustive checks \((\d+) tests", ["exhaustive"]),
    (r"\*\*Floor core tests\*\* \| (\d+) tests", ["floor_core"]),
    (r"\*\*Targeted unit tests\*\* \| (\d+) tests", ["targeted"]),
    (r"\*\*Adversarial tests\*\* \| (\d+) tests", ["adversarial"]),
    (r"\*\*Crash scenario\*\* \| (\d+) tests", ["cascade"]),
    (N + r" program tests", ["programs"]),
    (N + r" Floor tests", ["floor_programs"]),
    (r"program_tests-(\d+)%2F(\d+)", ["programs", "programs"]),
    (r"Programs on the real runtime [^|]*\| \*\*(\d+)/(\d+)\*\*", ["programs", "programs"]),
    (r"\*\*Program tests\*\* \| Floor \((\d+)\) and Vault \((\d+)\)[^|]*\| (\d+)/(\d+)", ["floor_programs", "vault_programs", "programs", "programs"]),
    (N + r" curated outputs", ["golden"]),
    (N + r"/(\d+) identical", ["golden", "golden"]),
    (r"`reference/regressions/`: (\d+) cases", ["regressions"]),
    (N + r" fixtures with expected outputs", ["regressions"]),
    (N + r"/(\d+) reproduced", ["regressions", "regressions"]),
    (N + r" JavaScript tests", ["client"]),
    (r"\*\*Client tests\*\* \|[^|]*\| (\d+)/(\d+)", ["client", "client"]),
    (N + r" libFuzzer targets", ["fuzz"]),
    (r"libFuzzer, (\d+) targets", ["fuzz"]),
    (r"fuzzing, (\d+) targets", ["fuzz"]),
    (N + r" findings", ["findings"]),
]
RULES = [(re.compile(pattern.replace(" ", r"\s+").replace(r"(\d+)", D), re.I), keys) for pattern, keys in RULES]

# (file, exact text, reason). Statements not of the current count, kept as written.
KEPT = [
    ("docs/00-DECISION.md", "14 Kani harnesses", "decision log entry of 26 Sep"),
    ("docs/12-SUBMISSION.md", "95 findings at submission", "the count when the project was submitted"),
]


def documents() -> list:
    """Every Markdown file in git's index (so a new doc counts once added, and
    local notes never do), the CI workflow and the status page."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--", "*.md", ".github/workflows/*.yml", "cloud/status/*.html"],
            cwd=ROOT, check=True, capture_output=True, text=True,
        ).stdout.split("\0")
    except (OSError, subprocess.CalledProcessError):  # not a git checkout (a source archive): every file
        out = files(".", ".md")
        out += files(".github/workflows", ".yml") + files("cloud/status", ".html")
    return sorted(p for p in set(out) if p and os.path.exists(os.path.join(ROOT, p)))


def check(texts: dict, t: dict, kept_list: list) -> tuple:
    """Every stated count that differs from `t`, as `file:line: message`, and
    the rules that matched outside the kept statements."""
    errors, live, used, found_any = [], set(), set(), set()
    kept = {}
    for path, snippet, _ in kept_list:
        flexible = r"(?<![\w.,])" + r"\s+".join(re.escape(word) for word in snippet.split()) + r"(?!\w)"
        found = list(re.finditer(flexible, texts.get(path, "")))
        hits = [(m.start(), m.end()) for m in found]
        if hits:
            found_any.add((path, snippet))
        if len(hits) != 1:
            errors.append(f"{path}: kept entry {snippet!r} matches {len(hits)} times; it must name exactly one statement")
        kept.setdefault(path, []).extend((a, b, snippet) for a, b in hits)
    for path, text in texts.items():
        for pattern, keys in RULES:
            for m in re.finditer(pattern, text):
                spans = [snippet for a, b, snippet in kept.get(path, []) if a < m.end() and m.start() < b]
                if spans:
                    used.update((path, snippet) for snippet in spans)
                    continue
                live.add(pattern.pattern)
                wrong = [
                    f"{m.group(i)} (the tree has {key} = {t[key]})"
                    for i, key in enumerate(keys, 1)
                    if int(m.group(i).replace(",", "")) != t[key]
                ]
                if wrong:
                    line = text.count("\n", 0, m.start()) + 1
                    errors.append(f"{path}:{line}: {m.group(0)!r} states " + ", ".join(wrong))
    for path, snippet, _ in kept_list:
        if (path, snippet) in found_any and (path, snippet) not in used:
            errors.append(f"{path}: kept entry {snippet!r} holds no statement a rule checks; remove it")
    return errors, live


def self_test() -> int:
    """The matcher and the test counter on planted text: right counts pass, a wrong one fails."""
    t = {key: 10 for _, keys in RULES for key in keys}
    t.update(kani=17, kani_full=14, kani_small=3, floor_programs=4, vault_programs=6, findings=1103)
    old = [("doc.md", "14 Kani harnesses", "a past state")]
    cases = [
        ("15 Kani harnesses", [], 1),
        ("15 Kani\n  harnesses", [], 1),
        ("17 Kani harnesses", [], 0),
        ("### 5.1 Kani harnesses (17)", [], 0),
        ("badge/Kani_proofs-17%2F15-x", [], 1),
        ("badge/Kani_proofs-16%2F17-x", [], 1),
        ("17/17 verified (14 for every value of their types)", [], 0),
        ("(15 for every value of their types)", [], 1),
        ("**17/17 harnesses verified**", [], 0),
        ("| **Bounded proofs (Kani)** | 17 harnesses: x | **16/17 verified** (14 Oct) |", [], 1),
        ("| **Bounded proofs (Kani)** | 17 harnesses: x | **17/18 verified** (14 Oct) |", [], 1),
        ("| **Program tests** | Floor (4) and Vault (6) on x | 10/10 |", [], 0),
        ("| **Program tests** | Floor (4) and Vault (6) on x | 10/11 |", [], 1),
        ("| **Program tests** | Floor (5) and Vault (6) on x | 10/10 |", [], 1),
        ("we found 1,103 findings", [], 0),
        ("we found 1,102 findings", [], 1),
        ("then: 14 Kani harnesses", old, 0),
        ("then: 14 Kani harnesses; now: 14 Kani harnesses", old, 1),
        ("then: 14 Kani harnesses", [("doc.md", "then:", "x")], 2),
        ("then: 14 Kani\nharnesses", old, 0),
        ("then: 114 Kani harnesses", old, 2),
        ("| **Bounded proofs (Kani)** | 16 harnesses: x | **16/16 verified** (8 Oct) |", [("doc.md", "16/16 verified", "x")], 0),
        ("Bounded model checking of the core's 15 harnesses", [], 1),
        ("the 3 harnesses at small width", [], 0),
        ("the S10 Floor tests and G2 property tests", [], 0),
        ("now: 15 Kani harnesses", old, 2),
    ]
    failed = []
    for text, kept, want in cases:
        got, _ = check({"doc.md": text}, t, kept)
        if len(got) != want:
            failed.append(f"{text!r}: {len(got)} errors, expected {want}: {got}")
    if check({"doc.md": "then: 14 Kani harnesses"}, t, old)[1]:
        failed.append("a rule matched only inside a kept statement counts as live")
    if not check({"doc.md": "17 Kani harnesses"}, t, [])[1]:
        failed.append("a rule that matched does not count as live")
    sources = [
        ("#[test]\nfn a() {}\n#[test] fn b() {}\n", 2),
        ("#[test]\n/// says why\n// and how\n/* and\n more */\nfn a() {}\n", 1),
        ("#[test]\n#[ignore]\nfn a() {}\n#[ignore = \"slow\"]\n#[test]\nfn b() {}\n", 0),
        ("#[test]\n#[should_panic(expected = \"index [0] must ignore\")]\n#[cfg_attr(miri, ignore)]\nfn a() {}\n", 1),
        ("#[test]\npub(crate) async fn a() {}\n#[test]\nunsafe fn b() {}\n", 2),
        ("#[cfg(test)]\nfn helper() {}\nfn b() {} // #[test]\n", 0),
        ("#[test]\n#[case([1, 2])]\nfn a() {}\n", 1),
        ("#[test]\n#[case(&[[1, 2], [3]])]\nfn a() {}\n#[test]\nlet x = 1;\nfn b() {}\n", 1),
        ("#[derive(Debug)]\npub struct S;\nfn not_a_test() {}\n", 0),
        ("/*\n#[test]\nfn old() {}\n*/\n/// #[test] fn x() {}\nstruct S;\n", 0),
        ("const A: char = '\"';\n#[test]\nfn a() {}\nconst B: char = '\"';\n", 1),
        ("const A: [char; 2] = ['\\x00','\"'];\n#[test]\nfn a() {}\nconst B: &str = \"x\";\n", 1),
        ('const A: &str = r"\\";\n#[test]\nfn a() {}\nconst B: &str = "x";\n', 1),
    ]
    for source, want in sources:
        if tests_in(source) != want:
            failed.append(f"{source!r}: {tests_in(source)} tests, expected {want}")
    harnesses = [
        ("#[kani::proof]\nfn a() {}\n#[kani::proof_for_contract(f)]\nfn b() {}\n#[cfg_attr(kani, kani::proof)]\nfn c() {}\n", 3),
        ("// #[kani::proof]\n/* #[kani::proof]\n#[kani::proof] */\n#[kani::unwind(4)]\nfn a() {}\n", 0),
        ('let s = "/*";\n#[kani::proof]\nfn a() {}\n// */\n', 1),
    ]
    for source, want in harnesses:
        if len(kani_names(source)) != want:
            failed.append(f"{source!r}: {len(kani_names(source))} harnesses, expected {want}")
    names = kani_names("#[kani::proof]\n#[kani::unwind(3)]\nfn a() {}\n#[cfg_attr(kani, kani::proof)]\npub fn b() {}\n")
    if names != ["a", "b"]:
        failed.append(f"harness names {names}, expected ['a', 'b']")
    table = "\n### 5.1 K\n| `a` | FULL | x |\n| `b` | SMALL-WIDTH (x) | y |\n| `c` | FULL (every byte) | z |\n### 5.2 E\n"
    if kani_table(table) != (["a", "b", "c"], 1):
        failed.append(f"09 §5.1 table read as {kani_table(table)}, expected (['a', 'b', 'c'], 1)")
    js = [
        ("test('a', () => {});\n  it('b', () => {});\ntest('c', { skip: true }, () => {});\n", 2),
        ("test('d', { todo: 'later' });\n// test('e')\nconst f = test('g');\n", 0),
        ("test('h', { skip: false }, () => {});\n", 1),
        ("/*\ntest('old', () => {});\n*/\n", 0),
        ("const g = 'cloud/test/*.mjs';\ntest('a', () => {});\ntest('b', () => { /* x */ });\n", 2),
        ("const py = `\ntest(1)\n`;\ntest('c', { skip: \"why\" }, () => {});\n", 0),
    ]
    for source, want in js:
        if js_tests_in(source) != want:
            failed.append(f"{source!r}: {js_tests_in(source)} JavaScript tests, expected {want}")
    start = time.monotonic()
    tests_in("#[derive(Debug)]\n" + "// see https://x" * 40 + "\nstruct S;\n")
    if time.monotonic() - start > 5:
        failed.append("counting tests backtracks on a line with many `//`")
    for pattern, keys in RULES:
        if pattern.groups != len(keys):
            failed.append(f"{pattern.pattern!r} has {pattern.groups} groups for {len(keys)} counts")
    for f in failed:
        print("self-test FAILED:", f)
    if not failed:
        print(f"self-test OK: {len(cases)} claim cases, {len(sources) + len(harnesses) + len(js)} count cases, {len(RULES)} rules")
    return 1 if failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Check the counts the docs state against the tree.")
    ap.add_argument("--self-test", action="store_true", help="check the matcher and the counters on planted text")
    if ap.parse_args().self_test:
        return self_test()
    t = truth()
    texts = {p: read(p) for p in documents()}
    errors, live = check(texts, t, KEPT)
    # A rule whose phrasing left the docs checks nothing: reword the rule too.
    errors += [f"rule {p.pattern!r} matches no current statement" for p, _ in RULES if p.pattern not in live]
    for e in errors:
        print(e)
    if errors:
        print(f"claims: {len(errors)} problems; a stated count must equal the tree")
        return 1
    print(f"claims OK ({len(texts)} files): " + ", ".join(f"{k} {v}" for k, v in sorted(t.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
