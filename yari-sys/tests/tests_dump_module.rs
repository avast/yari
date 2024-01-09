use yari_sys::MODULES;

mod common;

#[test]
fn test_function_dump_plain() {
    let mut context = common::context();

    for module in MODULES {
        context.dump_module(*module).unwrap();
    }
}

#[test]
fn test_function_dump_cuckoo() {
    let mut context = common::context_with_cuckoo();

    for module in MODULES {
        context.dump_module(*module).unwrap();
    }
}

#[test]
fn test_function_dump_pe() {
    let mut context = common::context_with_pe_sample_and_rule();

    for module in MODULES {
        context.dump_module(*module).unwrap();
    }
}

#[test]
fn test_function_dump_elf() {
    let mut context = common::context_with_elf_sample();

    for module in MODULES {
        context.dump_module(*module).unwrap();
    }
}
