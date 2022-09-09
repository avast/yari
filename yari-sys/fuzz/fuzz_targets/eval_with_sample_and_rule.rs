#![no_main]
use libfuzzer_sys::fuzz_target;
extern crate yari_sys;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let sample_path = crate_root.join("../tests/assets/pe_hello_file");
        assert!(sample_path.exists());
        let rule = "rule test { strings: $s00 = \"test\" condition: all of them}".to_string();
        let mut c = yari_sys::ContextBuilder::default()
            .with_sample(Some(sample_path))
            .with_rule_string(Some(rule))
            .build()
            .unwrap();
        let _ = c.eval(&format!("!{}", s));
        let _ = c.eval(&format!("@{}", s));
        let _ = c.eval(&format!("${}", s));
        let _ = c.eval(&format!("#{}", s));
        let _ = c.eval(&format!("!s00{}", s));
        let _ = c.eval(&format!("@s00{}", s));
        let _ = c.eval(&format!("$s00{}", s));
        let _ = c.eval(&format!("#s00{}", s));
    }
});
