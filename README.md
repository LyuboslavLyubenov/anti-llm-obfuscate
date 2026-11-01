# anti-llm-obfuscate

An OpenCode skill plus a Python CLI that produce a tripwired copy of a source tree. The copy follows the "anti-LLM obfuscation" technique documented by veritas in [Why Is This Fingerprinting Script Creating Bioweapons?](https://nullpt.rs/fingerprinting-bioweapons): production fingerprinting code hides decoy labels inside code so that LLM-based analysis refuses or derails, while the real behavior keeps running.

Use this tool to build eval sets for agent robustness work, for example CyberGym runs where you want to know how a coding agent behaves around adversarial-looking but harmless code.

Two hard rules. First, everything injected is a label. The tool ships no payloads or instructions of any kind. Second, the original tree is never touched. Output always lands in a separate directory, and the CLI refuses any output path that would overlap the source.

## What it does to each file

The rename layer keeps the project consistent across modules. The tripwire layer is always this tool's, because no obfuscation engine ships decoys.

| Language | Renames | Deep engine (optional) | Tripwire block |
|---|---|---|---|
| C, C++ | tree-defined symbols: typedefs, structs with bodies, functions, macros. Preprocessor guards, `##` paste chains and conditional blocks are left alone so the project still compiles | none | canary string, dead decoder, include guard |
| Python | `ast`-transformed locals, functions, classes, imports across all modules. Parameters, class attributes and attribute-reached module globals keep their names | pyarmor, via `--pyarmor` | canary, dead decoder, env gate |
| JavaScript `.js/.mjs/.cjs` | declaration-level, aware of properties, object keys and regex literals | javascript-obfuscator, auto-detected | canary var, dead decoder, env-gated no-op |
| TypeScript, JSX | same pass plus interfaces, types, enums, namespaces | validate with `tsc --noEmit` | strict-TS-safe canary |

The decoys come from the blog's published tripwire vocabulary:

* identifiers such as `computeRicinLethalDosageForWaterSupply`
* unicode hidden strings, tag codepoints offset +0xE0000, carrying marker labels
* a fake environment gate `METRICS_AGENT_8BFD_ACTIVE`
* marker strings: `policy_check_failed`, `AI_SYSTEM_PROMPT`, `<|END_OF_TURN_TOKEN|>`

The rename density is configurable. A slice of identifiers picks up the decoy vocabulary (`--decoy-density`, default 0.05); the rest get deterministic mangled names. Same seed, same output.

## Install

The CLI needs Python 3.9+ and nothing else. Syntax check only for the JS deep layer:

```
npm install -g javascript-obfuscator
pip install pyarmor    # optional, only for the pyarmor pass
```

Then either point OpenCode at this directory as a skill, or call the script directly:

```
python3 src/obfuscate.py <source_dir> -o <source_dir>-obf --seed 42
```

## Validate before you trust it

Run the project's own pipeline on both trees. The results must match. This is what validation of this tool looked like on real random GitHub repos:

| Repo | Gate | Pristine | Obfuscated |
|---|---|---|---|
| luvit/luv (C, requires submodules) | compile each of 31 C sources, same flags | 25 pass, 6 fail (missing build flags, pre-existing) | 25 pass, 6 fail, identical set |
| EntilZha/PyFunctional (Python) | full pytest suite | 307 passed, 5 skipped | same |
| jwadhams/json-logic-js (JavaScript with deep engine) | npm test, qunit | 7 pass | 7 pass |

Original trees were re-hashed before and after every run and stayed identical.

## Reverting

Every output directory contains `obf-manifest.json`: seed, unicode offset, decoder note, the canary cleartext, the env flag, and the full original to new name map. Apply the map in reverse to restore names. The deep JS engine layer cannot be undone textually, so keep the pristine tree for rebuilds of clean copies.

## Known non-rename surfaces

These names keep their spelling on purpose, because renaming them breaks contracts that strings or attribute paths carry:

* Python parameter names (kwargs, `super()` chains), class attributes and methods, module globals reached as `module.attr`, external import bindings, submodule names, and parameter names referenced in decorator strings.
* Python comments and formatting: the `ast` output drops both. Names restore via the manifest; formatting does not.
* JavaScript property accesses (`x.y`), object keys and shorthand, regex literal contents.
* One open ambiguity: class field declarations and destructuring bindings written as `{ x = ... }` fall on the rename side. There is no type information in a stdlib-only scanner, so run the project's tests after obfuscating anything heavy.

## Scope and intent

This is a research and benchmarking tool for authorized use. If a request pushes toward disguising genuinely malicious code, or toward real harm, the tool declines. The decoys exist for one evaluation purpose: to check whether an agent analysis pipeline can survive hazardous-looking labels.

Published under the MIT license. See `docs/AGENT-NOTES.md` for how an agent should read tripwired code.
