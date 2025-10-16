// Copyright 2025 Tos Maintainers <info@tos.network>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![feature(test)]

extern crate test;
extern crate test_utils;
extern crate tos_tbpf;

use std::{fs::File, io::Read, sync::Arc};
use test::Bencher;
use test_utils::{syscalls, TestContextObject};
use tos_tbpf::{elf::Executable, program::BuiltinProgram, vm::Config};

fn loader() -> Arc<BuiltinProgram<TestContextObject>> {
    let mut loader = BuiltinProgram::new_loader(Config::default());
    loader
        .register_function("log", syscalls::SyscallString::vm)
        .unwrap();
    Arc::new(loader)
}

#[bench]
fn bench_load_sbpfv0(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/syscall_reloc_64_32_tbpfv0.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let loader = loader();
    bencher.iter(|| Executable::<TestContextObject>::from_elf(&elf, loader.clone()).unwrap());
}
