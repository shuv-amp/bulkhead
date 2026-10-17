#!/usr/bin/env python3
"""mutant exclusions: .cargo/mutants.toml still excludes exactly the equivalents.

    python3 tools/mutant_exclusions.py ALL KEPT   # the two `cargo mutants --list` outputs
    python3 tools/mutant_exclusions.py --self-test

ALL is the list without the config (`--no-config`), KEPT the list with it;
scripts/mutants.sh makes both. The config's exclude_re patterns name the
equivalent mutants of docs/09 §6. A pattern pinned by line stops matching when
its code moves (the murmur3 tail did on 9 Oct, unnoticed until 15 Oct), and
any pattern could start matching another mutant and hide it. So each pattern
ends with the number of mutants it excludes (`# 3`) and must match exactly
that many, no two patterns may match the same mutant (the counts' sum is the
docs' number of equivalents, tools/claims.py), and cargo-mutants must exclude
exactly the mutants the patterns match: a pattern this parser can't see, or
reads differently, fails too.

Not caught: an edit that leaves a pattern on as many mutants as before but
different ones, such as a change to an excluded line itself, or to murmur3_32
that moves a body XOR onto a pinned line. Such an edit needs the mutant judged
again by hand.

Standard library only (no tomllib), so Python 3.9 runs it.
"""
from __future__ import annotations

import contextlib
import io
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
CONFIG = ".cargo/mutants.toml"


def exclusions(text: str) -> list:
    """(pattern, count or None) for each entry of the exclude_re array.

    Reads only that array's body. An entry is one single-quoted (literal) TOML
    string per line; anything after its comma must be the `# N` count.
    """
    body = re.search(r"^exclude_re = \[\n(.*?)^\]", text, re.M | re.S)
    if not body:
        return []
    entries = []
    for pattern, rest in re.findall(r"^\s*'([^']*)',(.*)$", body.group(1), re.M):
        count = re.fullmatch(r"\s*#\s*(\d+)\s*", rest)
        entries.append((pattern, int(count.group(1)) if count else None))
    return entries


def problems(text: str, names: list, kept: set) -> list:
    """What is wrong with the config `text`, given both lists of mutant names."""
    entries = exclusions(text)
    if not entries:
        return ["no patterns found in its exclude_re array"]
    if any("\x1b" in n for n in names) or any("\x1b" in n for n in kept):
        return ["the mutant list has colour codes, which no pattern matches (list with --colors never)"]
    bad = []
    for pattern, count in entries:
        got = sum(bool(re.search(pattern, n)) for n in names)
        if count is None:
            bad.append(f"{pattern}: no '# N' count after it")
        elif got != count:
            bad.append(f"{pattern}: matches {got} mutants, its count says {count}"
                       " (judge them against docs/09 §6, then fix the pattern or the count)")
    if not kept <= set(names):
        bad.append(f"the kept list has {len(kept - set(names))} mutants the full list lacks (make both with the same options)")
    excluded = sorted(n for n in names if n not in kept)
    matched = sorted(n for n in names if any(re.search(p, n) for p, _ in entries))
    if excluded != matched:
        bad.append(f"cargo-mutants excludes {len(excluded)} mutants, the patterns match {len(matched)};"
                   f" {len(set(excluded) ^ set(matched))} are in one set only")
    if not bad and sum(c for _, c in entries) != len(matched):
        bad.append(f"the counts add up to {sum(c for _, c in entries)}, the patterns match {len(matched)} mutants:"
                   " two patterns match the same mutant")
    return bad


def self_test() -> int:
    names = ["a.rs:1:5: replace > with >= in f", "a.rs:9:5: replace > with >= in f", "b.rs:3:2: replace < with <= in g"]
    head = "# config\nexclude_re = [\n"
    one = head + "  # why\n  'a\\.rs:1:5: replace > with >= in f$',  # 1\n]\n"
    a1 = set(names[1:])
    count, total, empty, overlap = "its count says", "the patterns match", "no patterns", "add up to"
    coloured = ["\x1b[33m" + n + "\x1b[0m" for n in names]
    cases = [
        # (config, kept by cargo-mutants, the problems it must report, in order)
        (one, a1, []),
        (one + "exclude_globs = [\n  'x',\n]\n", a1, []),
        # The pattern's line moved: it matches nothing.
        (one.replace(":1:5", ":2:5"), set(names), [count]),
        # It matches a second mutant: cargo-mutants hides both, the count says 1.
        (one.replace(":1:5", ":\\d+:5"), {names[2]}, [count]),
        # Two patterns drift so the total is unchanged.
        (head + "  'a\\.rs:\\d+:5: replace > with >= in f$',  # 1\n  'b\\.rs:7:2: replace < with <= in g$',  # 1\n]\n", {names[2]}, [count, count]),
        # A double-quoted entry cargo-mutants honours and this parser can't see.
        (head + "  'a\\.rs:1:5: replace > with >= in f$',  # 1\n  \"b\\\\.rs\",\n]\n", {names[1]}, [total]),
        # As many excluded as matched, but not the same ones.
        (one, {names[0], names[2]}, [total]),
        (one.replace("  # 1\n", "\n"), a1, ["no '# N' count"]),
        (one.replace("  # 1\n", "  # 1 or so\n"), a1, ["no '# N' count"]),
        (one.replace("exclude_re", "exclude_regex"), set(names), [empty]),
        (head + "]\n", set(names), [empty]),
        # Two patterns name the same mutant: each count holds, the sum does not.
        (head + "  'a\\.rs:1:5: replace > with >= in f$',  # 1\n  'a\\.rs:1:5: replace >',  # 1\n]\n", a1, [overlap]),
        # The kept list was made with other options than the full one.
        (one, a1 | {"c.rs:1:1: replace + with - in h"}, ["full list lacks"]),
        # Listed with colours (CI sets CARGO_TERM_COLOR=always).
        (one, {coloured[1], coloured[2]}, ["colour codes"], coloured),
        # Only the kept list has colours.
        (one, {coloured[1], coloured[2]}, ["colour codes"]),
    ]
    failed = []
    for text, kept, want, *listed in cases:
        got = problems(text, listed[0] if listed else names, kept)
        if len(got) != len(want) or not all(w in g for w, g in zip(want, got)):
            failed.append(f"{text!r}: problems {got}, expected ones saying {want}")
    entries = exclusions(head + "  'p',  # 3\n  'q',\n]\n")
    if entries != [("p", 3), ("q", None)]:
        failed.append(f"entries read as {entries}, expected [('p', 3), ('q', None)]")
    # CI's mutants job acts on main's exit status, so run main too, on a planted
    # config: each run's exit status and every line it prints on each stream.
    with tempfile.TemporaryDirectory() as d:
        def put(name, text):
            with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                f.write(text)
            return os.path.join(d, name)
        config = put("mutants.toml", one)
        full = put("all.txt", "\n".join(names))
        part = put("kept.txt", "\n".join(a1))
        tinted = put("coloured.txt", "\n".join(coloured))
        usage = ["ALL KEPT", "--self-test"]
        runs = [
            # (arguments, exit status, what stdout's lines say, what stderr's lines say, in order)
            ([full, part], 0, ["1 of 3 mutants excluded"], []),
            # The lists the other way round: KEPT is not read as ALL.
            ([part, full], 1, [], [count, "full list lacks"]),
            ([tinted, tinted], 1, [], ["colour codes"]),
            ([full], 2, [], usage),
            ([full, part, part], 2, [], usage),
        ]
        for args, code, want_out, want_err in runs:
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                got = main(args, config)
            printed = [out.getvalue().splitlines(), err.getvalue().splitlines()]
            if got != code or not all(len(p) == len(w) and all(x in y for x, y in zip(w, p))
                                      for p, w in zip(printed, [want_out, want_err])):
                failed.append(f"main({args}): exit {got}, printed {printed};"
                              f" expected {code}, {want_out} and {want_err}")
            report = printed[0] if code == 0 else printed[1]
            if code < 2 and any(not line.startswith(config + ": ") for line in report):
                failed.append(f"main({args}): printed {report}, not each line naming {config}")
        # The command line with two lists and the repo's config, as in
        # scripts/mutants.sh: a list no pattern can match is a mismatch. Which
        # problems it reports depends on the config, so only their form is checked.
        # It runs in the temporary directory, so the config is found from ROOT.
        nothing = put("nothing.txt", "none.rs:0:0: no mutant\n")
        run = subprocess.run([sys.executable, "-I", os.path.abspath(__file__), nothing, nothing],
                             capture_output=True, text=True, timeout=60, cwd=d)
        lines = run.stderr.splitlines()
        if run.returncode != 1 or run.stdout or not lines or not all(x.startswith(CONFIG + ": ") for x in lines):
            failed.append(f"the command line: exit {run.returncode}, stdout {run.stdout!r}, stderr {run.stderr!r};"
                          f" expected 1 and problems naming {CONFIG}")
    for f in failed:
        print("self-test FAILED:", f)
    if not failed:
        print(f"self-test OK: {len(cases) + len(runs) + 2} cases")
    return 1 if failed else 0


def main(argv: list | None = None, config: str | None = None) -> int:
    """argv without the program name; config defaults to the repo's (the self-test plants one)."""
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--self-test"]:
        return self_test()
    if len(argv) != 2:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8") as f:
        names = f.read().splitlines()
    with open(argv[1], encoding="utf-8") as f:
        kept = set(f.read().splitlines())
    label = config or CONFIG
    with open(config or os.path.join(ROOT, CONFIG), encoding="utf-8") as f:
        bad = problems(f.read(), names, kept)
    for b in bad:
        print(f"{label}: {b}", file=sys.stderr)
    if not bad:
        print(f"{label}: {len(names) - len(kept)} of {len(names)} mutants excluded, each pattern matching its count")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
