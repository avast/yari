#![no_main]
use libfuzzer_sys::fuzz_target;
extern crate yari_sys;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let sample_path = crate_root.join("../tests/assets/pe_hello_file");
        assert!(sample_path.exists());
        let mut c = yari_sys::ContextBuilder::default()
            .with_sample(Some(sample_path))
            .build()
            .unwrap();
        let _ = c.eval(s);
    }
});
