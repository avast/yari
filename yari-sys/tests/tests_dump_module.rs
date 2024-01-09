use log::debug;
use yari_sys::MODULES;

mod common;

#[test]
fn test_function_dump_plain() {
    let mut context = common::context();
    debug!("test_function_dump_plain");

    for module in MODULES {
        context.dump_module(*module).unwrap();
    }
}

#[test]
fn test_function_dump_cuckoo() {
    let mut context = common::context_with_cuckoo();
    debug!("test_function_dump_cuckoo");

    for module in MODULES {
        context.dump_module(*module).unwrap();
    }
}

#[test]
fn test_function_dump_pe() {
    let mut context = common::context_with_pe_sample_and_rule();
    debug!("test_function_dump_pe");

    for module in MODULES {
        context.dump_module(*module).unwrap();
    }
}

#[test]
fn test_function_dump_elf() {
    let mut context = common::context_with_elf_sample();
    debug!("test_function_dump_elf");

    for module in MODULES {
        context.dump_module(*module).unwrap();
    }
}
