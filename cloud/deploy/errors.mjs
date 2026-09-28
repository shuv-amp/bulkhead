// Names for the programs' custom error codes, read from their own source
// (programs/*/src/error.rs), so a check can require one exact error and the
// names can never drift from the code: Floor 7000+, Vault 8000+, and the
// abort binary's 0x464C4F52 ("FLOR").

import { readFileSync } from "node:fs";

function variants(program, enumName, base) {
  const src = readFileSync(new URL(`../../programs/${program}/src/error.rs`, import.meta.url), "utf8");
  const body = src.slice(src.indexOf(`pub enum ${enumName}`));
  const names = [...body.slice(body.indexOf("{") + 1, body.indexOf("}")).matchAll(/^\s*([A-Z]\w*)/gm)].map((m) => m[1]);
  return new Map(names.map((n, i) => [base + i, n]));
}

const NAMES = new Map([...variants("floor", "FloorError", 7000), ...variants("vault", "VaultError", 8000), [0x464c4f52, "FLOR (stopped by Floor)"]]);

/** A simulation's error as a name: "NotLiveGuardian", "ok", or the raw JSON. */
export function errorName(err) {
  if (!err) return "ok";
  const code = err.InstructionError?.[1]?.Custom;
  if (code !== undefined) return NAMES.get(code) ?? `Custom(${code})`;
  const inner = err.InstructionError?.[1];
  return typeof inner === "string" ? inner : JSON.stringify(err);
}
