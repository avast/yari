#![allow(dead_code)]
use std::path::Path;
use yari_sys::Module;
use yari_sys::{Context, ContextBuilder};

pub fn context() -> Context {
    ContextBuilder::default().build().unwrap()
}

pub fn context_with_cuckoo() -> Context {
    let test_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let cuckoo_report = test_root.join("tests/assets/cuckoo.json");

    ContextBuilder::default()
        .with_module_data(Module::Cuckoo, cuckoo_report)
        .build()
        .unwrap()
}

fn context_with_sample(path: &str, rule: Option<&str>) -> Context {
    let test_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let file = test_root.join(path);

    ContextBuilder::default()
        .with_sample(Some(file.to_str().unwrap()))
        .with_rule_string(rule)
        .build()
        .unwrap()
}

pub fn context_with_elf_sample() -> Context {
    context_with_sample("tests/assets/elf_hello_world", None)
}

pub fn context_with_pe_signed_sample() -> Context {
    context_with_sample("tests/assets/pe_signed", None)
}

pub fn context_with_pe_sample_and_rule() -> Context {
    context_with_sample(
        "tests/assets/pe_hello_world",
        Some(
            "import \"pe\"
private rule PRIVATE {
    condition:
        pe.number_of_sections == 4
}

rule r {
    strings:
        $s00 = \"Hello\"
        $s01 = \"this is a pretty unique string that should not be found in the provided sample\"
    condition:
        all of them and PRIVATE
}",
        ),
    )
}
