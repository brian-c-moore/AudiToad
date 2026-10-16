# Bundled Verus grammar

These unmodified files come from
[secure-foundations/tree-sitter-verus](https://github.com/secure-foundations/tree-sitter-verus)
at commit [`0c939ef2ec0a188c3cf24518474fb8082db02ec4`](https://github.com/secure-foundations/tree-sitter-verus/tree/0c939ef2ec0a188c3cf24518474fb8082db02ec4).
They are distributed under the upstream [MIT license](LICENSE).

AudiToad's `build.rs` compiles the upstream generated parser and scanner using
`cc`, C11 and the upstream MSVC UTF-8 flag. The three upstream Tree-sitter headers
are retained alongside them. The grammar is not regenerated during builds.
The private `src/verus.rs` binding connects its generated `tree_sitter_verus`
entry point to Tree-sitter's `LanguageFn`; syntax observations retain the upstream
commit identity. The grammar interprets source and does not execute it or check proofs.

Bundling these files lets the Cargo archive contain the same Verus parser used
by source builds. The upstream Cargo package is named `tree-sitter-rust` and is
not a published Verus grammar dependency; using that registry package would
select the ordinary Rust grammar instead.

| Upstream path | SHA-256 |
|---|---|
| `src/parser.c` | `927fcc31b62a626a0c17dc702458ac855a737c27b9780f05c5a2726dbe36c359` |
| `src/scanner.c` | `190eac7ebca1977681438d79175604b28bcd2fe0527cd934264eafc1dec93259` |
| `src/tree_sitter/alloc.h` | `b29c1c9fb7cc82f58c84b376df1297d6e2737a1d655fd356db0859e3c29c2fea` |
| `src/tree_sitter/array.h` | `5bdf6ed1a78e3409fd443e085ca967a64c188a5d082aaf7f819bccd53a471c94` |
| `src/tree_sitter/parser.h` | `11b654fbba7770b1c710cc14b169be2deb5d89c0f87233d4605037c26c1ff657` |
| `LICENSE` | `31d5b6f4243d5c7c6e1c4ebbbb9f6407bd1457a08bcc4f706521710341acba36` |

When updating this grammar, review the upstream commit and license, replace the
files together, update these hashes and the syntax grammar identity, and run the
syntax controls and ordinary Cargo checks.
