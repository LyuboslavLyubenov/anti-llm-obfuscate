---
name: anti-llm-obfuscate
description: Apply documented "anti-LLM" source-code obfuscation (refusal-tripwire decoys) from a published security-research write-up, for authorized red-team/eval experiments such as CyberGym agent-robustness testing. Works whole-project on C/C++, Python, JavaScript and TypeScript/JSX. Always writes to a separate output folder; never modifies the original source tree. Use when asked to obfuscate source for agent-safety research, produce tripwired repo copies, or undo such obfuscation via the manifest.
---

# anti-llm-obfuscate

This directory is an OpenCode skill. Read `README.md` for the documented validation
and `docs/AGENT-NOTES.md` if you are an agent processing tripwired code.

## Purpose (authorized research only)

The tool produces a tripwired copy of a trusted local source tree, following the
"anti-LLM obfuscation" technique published by veritas on nullpt.rs ("Why Is This
Fingerprinting Script Creating Bioweapons?"). Production fingerprinting code embeds
decoy tokens designed to make LLM-based code analysis refuse or derail.

Use cases: red-teaming coding agents (CyberGym robustness runs), building eval sets
with denial tripwires, studying how models behave around adversarial-looking but
purely decoy code.

Hard rules the agent running this skill must enforce:

1. Authorized-research context only. If a request implies evading analysis of
   genuinely malicious code, or improving real harm, stop.
2. Decoys only. The injected content is deliberately non-functional. There are
   no weapon, dosage or attack payloads. Everything hazardous-looking is a label.
3. Original tree untouched. Output always goes to a separate folder. The CLI
   refuses any output path that would resolve inside the source tree.
4. Reversible. The rename map lives in `obf-manifest.json` in the output folder.

## Techniques (from the blog)

| Technique | Example | Implementation |
|---|---|---|
| Hazard-sounding identifiers | `computeRicinLethalDosageForWaterSupply` | decoy-name pool applied to a slice of identifiers |
| Identifier mangling | `PiERW(RflJvFF)` | deterministic 3 to 5 char mixed-case names |
| Unicode-tag hidden strings | tag codepoints at offset +0xE0000 | encoded canary plus a dead decoder per file |
| Env-gated decoy block | fake flag `METRICS_AGENT_8BFD_ACTIVE` | gated block whose body is a no-op |
| Marker tripwires | `policy_check_failed`, `AI_SYSTEM_PROMPT` | encoded in the hidden payload |

Whole-project rename consistency is maintained by `src/obfuscate.py`. The deep
JS layer reuses `javascript-obfuscator` when installed; the tripwire layer is
always this tool's.

## Running it

```
python3 src/obfuscate.py <source_dir> -o <source_dir>-obf --seed 42
```

Flags: `--output-dir`, `--seed`, `--decoy-density` (default 0.05), `--no-rename`,
`--no-canary`, `--no-gates`, `--engine auto|internal`, `--obf-args`, `--pyarmor`,
`--force`.

Install the optional deep layers first if you want them:

```
npm install -g javascript-obfuscator
pip install pyarmor    # only for the pyarmor pass
```

## Verification (mandatory)

Before quoting any result, run the project's own pipeline on both trees:

* hash the original tree before and after: it must not change
* C: same compile pass/fail set per source file
* Python: same pytest pass/skip/fail counts
* JavaScript: `node --check` plus the project test suite
* TypeScript: `tsc --noEmit`

Reference results achieved during development are in `README.md`.

## Restoration

The `obf-manifest.json` in the output folder holds the seed, unicode offset,
canary cleartext, env flag and the original to new name map. Apply the map in
reverse. The deep JS layer cannot be textually reverted, so keep the pristine tree.
