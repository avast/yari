#![no_main]
use libfuzzer_sys::fuzz_target;
extern crate yari_sys;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let expr = yari_sys::parser::parse(s);
        if let Ok((_, expr)) = expr {
            let _module = expr.get_module();
        }
    }
});
