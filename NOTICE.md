# Third-Party Licenses

Vooda is licensed under the [Vooda Community Licence, Version 1.0](LICENSE.md). This file lists notable third-party components bundled with or depended upon by Vooda, and the licenses they carry.

For the complete, machine-generated dependency inventory, see `requirements.txt` (Python) and `apps/web/package-lock.json` (JavaScript).

## Directly vendored / notable components

| Component | License | Usage |
|---|---|---|
| [Tree-sitter](https://tree-sitter.github.io/tree-sitter/) | MIT | Incremental parsing for AST-based code context extraction |
| [defusedxml](https://github.com/tiran/defusedxml) | PSF-2.0 | Hardened XML parsing for scanner finding import |
| [google-re2](https://github.com/google/re2) | BSD-3-Clause | Non-backtracking regex engine; the ReDoS-immune fast path for the rule pack |
| [regex](https://github.com/mrabarnett/mrab-regex) | Apache-2.0 | Fallback engine for lookahead / large-repetition patterns, with per-match timeout |

## Python dependencies

All Python dependencies are MIT, BSD, Apache-2.0, or PSF licensed, with two exceptions carrying LGPL-family licenses:

| Component | License | Note |
|---|---|---|
| `psycopg2-binary` | LGPL-3.0-or-later | Used as an unmodified, dynamically-imported library. Replaceable by the user. |
| `fpdf2` | LGPL-3.0-or-later | Used as an unmodified, dynamically-imported library for PDF report export. |

Neither is modified, and neither is statically linked into Vooda — this is the standard LGPL library-use case.

## JavaScript dependencies

Of the packages resolved in `apps/web/package-lock.json`, the overwhelming majority are MIT, ISC, Apache-2.0, or BSD. Non-permissive entries:

| Component | License | Note |
|---|---|---|
| `@img/sharp-libvips-*` | LGPL-3.0-or-later | Optional per-platform native prebuilds pulled in transitively by Next.js image optimization. Loaded dynamically as separate binaries; never bundled into application JavaScript. Only one platform's binary installs per machine. |
| `axe-core` | MPL-2.0 | Development dependency only; not shipped in any build output. |
| `caniuse-lite` | CC-BY-4.0 | Build-time browser-support dataset. |

## Reporting

If you believe a component is misattributed here, or a license notice is missing, please open an issue or email **report@vooda.ai**. We will correct it.
