# TheShowLang

## S-Expression

Deschodt [function](params) -> [return_type] => create the function [function_name] with [params] and return [return_type]
Deschodt Eric() -> int => create the main function Eric with no parameters and return int

eric [var_name] -> [type] => create the variable [var_name] with type [type]
eric [var_name] = [value] => create the variable [var_name] and assign it the value [value]

erif [condition]:
    [code_block]
deschelse:
    [code_block]

    VERT
# TheShowLang — Minimal native compiler (tsc)

This repository contains a tiny, self-contained compiler for a small educational language called "TheShowLang". The compiler (written in C) emits standalone ELF/x86_64 binaries that can be executed on Linux without requiring gcc/clang for the produced targets.

This README documents the current functionality, build and run instructions, language features supported, known limitations, and how to add or test examples.

## Project layout

- `src/tsc.c` — single-file compiler implementation (parser, compile-time executor, symbol table, and ELF emitter).
- `Makefile` — builds `bin/tsc` from `src/tsc.c`.
- `bin/tsc` — produced compiler binary (not committed; produced by `make`).
- `examples/` — sample TheShowLang programs used to test language features.
- `includes/` — header-like files that can be inlined by the compiler using the `johnsenat` include keyword.

## Build

Make sure you have a C compiler (gcc/cc/clang) on Linux x86_64. Then:

```sh
make
```

This produces `bin/tsc`.

## Usage

The compiler is a simple command-line tool that concatenates input source files and emits a single ELF executable.

Basic usage:

```sh
./bin/tsc <input1.tslang> [<input2.tslang> ...] <output_binary>
```

Examples:

- Compile a single file and run:

```sh
./bin/tsc examples/example1.tslang a.out && ./a.out
```

- Compile multiple files (useful for splitting headers/implementation). The compiler treats the provided files as a concatenated source stream; use `johnsenat "file.hlang"` in sources to include header-like content if needed.

```sh
./bin/tsc examples/with_header/example1.tslang examples/with_header/my_strlen.tslang a.out && ./a.out
```

## Language features supported (as implemented in `src/tsc.c`)

This compiler is intentionally small and implements a subset of features to demonstrate parsing, compile-time execution, and native ELF emission.

Top-level constructs
- Function declaration: `Deschodt Name(params) -> return_type` — defines a function. `Deschodt Eric() -> int` is commonly used as the entrypoint.
- `desconst` / `desenum` — declare compile-time constants and enums (available during compile-time evaluation).
- `johnsenat "file"` — include (inline) the named file's contents at parse time (basic include behavior).

Variables and types
- `eric name -> type` — declares a variable with a type (int or char * supported currently).
- Assignments: `eric x = 5` or `x = 3` are supported.
- Arrays: `eric vals -> int[5]` creates indexed symbols `vals[0]..vals[4]` accessible in compile-time evaluation.
- Strings: character data stored as string symbols. Indexing like `s[i]` returns the character code when used in expressions if no explicit `s[i]` integer symbol exists.

Control flow
- `erif (cond):` / `deschelse:` — conditional blocks.
- `darius (cond):` — while loops. The language parser recognizes `darius` lines and nested blocks.
- `aer var in start,end:` — (for-like) ranges are supported (simple forms implemented).
- `deschontinue`, `deschreak` — continue and break within loops (named slightly differently in sources; handled where present).

Functions and calling
- Functions can be called at compile-time by the compiler when needed: the compiler executes function bodies during compilation to produce strings (peric output) and integer return values.
- Parameter passing supports by-value and by-reference (via aliasing) for strings and arrays; the compiler creates alias symbols when a callee parameter is passed by reference so writes inside the callee reflect back to the caller when appropriate.

Peric (printing) and placeholders
- `peric("text {var} more")` — peric statements are evaluated at compile-time and embedded into the produced binary as message bytes. Placeholders of the form `{name}` inside peric strings are replaced by the current value of `name` (integer or string) during compile-time evaluation.
- Escape sequences `\\n` and `\\t` inside peric strings are supported.

Compile-time symbol table
- The compiler maintains a simple symbol table used while executing function bodies at compile-time. It supports integer symbols, string symbols, and alias symbols that point to another symbol. This enables by-ref semantics and struct/array-like field aliasing.

ELF emission
- The compiler writes an ELF64 binary with a single loadable segment and small machine code that issues write syscalls to print the collected peric messages and then exits with the function's return code.

## Examples

The `examples/` folder contains sample programs demonstrating features like:
- basic functions and peric output
- includes and multi-file compilation (see `examples/with_header/`)
- arrays, dotted names, and struct-like fields
- by-reference parameter passing and aliasing
- simple `my_strlen` and `my_strcmp` implementations exercised at compile-time

Run the examples to see how the compiler executes functions at compile-time and writes the produced messages into an ELF target.

## Known limitations and TODOs

- The parser is line-based and indentation-sensitive; it is intentionally minimal and fragile. It may not handle all whitespace or malformed inputs robustly.
- The expression evaluator handles basic integer arithmetic and comparisons but is not a full language expression evaluator (no short-circuit boolean logic outside implemented patterns).
- The include handling (`johnsenat`) simply inlines file content; there is no include-path search, include-once prevention, or conditional includes.
- The emitted ELF is minimal and uses direct syscalls; it does not produce sections, relocation, or C runtime support. It is designed for small demo binaries that just print pre-collected messages.
- Debug prints are present in `src/tsc.c` to aid development and may clutter output; a cleanup step should remove or conditionally compile them.

## Contributing and next steps

If you want to extend this compiler, some straightforward improvements:
- Replace ad-hoc parsing with a proper tokenizer and AST to make the language robust.
- Implement a proper code generator for functions to produce native code per function instead of using compile-time execution to collect messages.
- Add include path support and include guards for `johnsenat` semantics.
- Remove or gate debug messages and add a test harness to validate examples automatically.

If you'd like, I can:
- Run the full test suite of `examples/` and fix failing examples until all run correctly.
- Clean up debug prints and add a `--quiet` flag to `tsc`.
- Implement include-path and include-once semantics.

## License

This project is provided "as is" for educational/demo purposes. No license is declared in the repository; add one if you intend to open-source it.