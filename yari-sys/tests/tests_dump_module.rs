use yari_sys::Module;

mod common;

#[test]
fn test_function_dump_plain() {
    let mut context = common::context();

    for module in Module::ALL_MODULES {
        context.dump_module(module);
    }
}

#[test]
fn test_function_dump_cuckoo() {
    let mut context = common::context_with_cuckoo();

    for module in Module::ALL_MODULES {
        context.dump_module(module);
    }
}

#[test]
fn test_function_dump_pe() {
    let mut context = common::context_with_pe_sample_and_rule();

    for module in Module::ALL_MODULES {
        context.dump_module(module);
    }
}

#[test]
fn test_function_dump_elf() {
    let mut context = common::context_with_elf_sample();

    for module in Module::ALL_MODULES {
        context.dump_module(module);
    }
}
