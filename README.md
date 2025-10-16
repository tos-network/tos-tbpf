# tos-tbpf

**TOS BPF (TBPF)** - Virtual machine and JIT compiler for eBPF programs

## Description

TOS TBPF is a high-performance virtual machine for executing eBPF bytecode, forked from the Anza-xyz SBPF project and maintained by the TOS Network team.

This crate provides a complete eBPF execution environment featuring:

- **Interpreter**: Execute eBPF bytecode in a secure sandboxed environment
- **JIT Compiler**: x86_64 just-in-time compiler for high-performance execution
- **Assembler & Disassembler**: Tools for working with eBPF assembly
- **Verifier**: Static analysis to ensure program safety before execution

Based on _Berkeley Packet Filter_ (BPF), an assembly-like language originally developed for BSD packet filtering, TBPF implements the extended BPF (eBPF) instruction set with TOS-specific enhancements. While eBPF was designed for kernel-space execution, TBPF brings this capability to user-space applications with additional safety guarantees and features.

**Platform Support**: Linux, macOS, and Windows (JIT compiler not available on Windows)

## Developer

### Dependencies
- rustc version 1.83 or higher
- nightly toolchain (required for benchmarks)

### Build and test instructions
- To build run `cargo build`
- To test run `cargo test`
- To run benchmarks run `cargo +nightly bench --features=jit -- --test`

## License

Following the effort of the Rust language project itself in order to ease
integration with other projects, the tbpf crate is distributed under the terms
of both the MIT license and the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.
