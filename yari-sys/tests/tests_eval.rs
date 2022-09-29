extern crate yari_sys;

mod common;

use yari_sys::error::YariError;
use yari_sys::ContextBuilder;
use yari_sys::YrValue;

#[test]
fn test_create_context() {
    ContextBuilder::default().build().unwrap();
}

#[test]
fn test_math_max() {
    let mut context = common::context();

    let res = context.eval("math.max(123, 600)");
    assert_eq!(res, Ok(YrValue::Integer(600)));
}

#[test]
fn test_math_mean() {
    let mut context = common::context();

    let res = context.eval("math.mean(\"test\")");
    assert_eq!(res, Ok(YrValue::Float(112.0)));
}

#[test]
fn test_math_mean_empty_string() {
    let mut context = common::context();

    let res = context.eval("math.mean(\"\")");
    // We can't compare NaN like this:
    // assert_eq!(res, Ok(YrResult::Float(f64::NAN.into())));
    assert!(std::matches!(res, Ok(YrValue::Float(val)) if val.is_nan()));
}

#[test]
fn test_cuckoo_dot_star_match() {
    let mut context = common::context_with_cuckoo();

    let res = context.eval("cuckoo.filesystem.file_access(/.*/)");
    assert_eq!(res, Ok(YrValue::Integer(1)));
}

#[test]
fn test_cuckoo_full_match() {
    let mut context = common::context_with_cuckoo();

    let res = context
        .eval(r"cuckoo.filesystem.file_access(/C:\\Users\\Administrator\\AppData\\Local\\Temp\\hello.txt/)");
    assert_eq!(res, Ok(YrValue::Integer(1)));
}

#[test]
fn test_cuckoo_regex_no_case() {
    let mut context = common::context_with_cuckoo();

    let res = context.eval(r"cuckoo.filesystem.file_access(/.*AdMiNiStRaToR.*local.*HELLO\.TxT/i)");
    assert_eq!(res, Ok(YrValue::Integer(1)));
}

#[test]
fn test_cuckoo_no_match() {
    let mut context = common::context_with_cuckoo();

    let res =
        context.eval(r"cuckoo.filesystem.file_access(/C:\\Some\\File\\That\\Does\\Not\\Match/)");
    assert_eq!(res, Ok(YrValue::Integer(0)));
}

#[test]
fn test_elf_values() {
    let mut context = common::context_with_elf_sample();

    let res = context.eval("elf.entry_point");
    assert_eq!(res, Ok(YrValue::Integer(0x1040)));

    let res = context.eval("elf.number_of_sections");
    assert_eq!(res, Ok(YrValue::Integer(0x1e)));

    let res = context.eval("elf.number_of_segments");
    assert_eq!(res, Ok(YrValue::Integer(0xd)));
}

#[test]
fn test_pe_imphash() {
    let mut context = common::context_with_pe_sample_and_rule();
    let res = context.eval("pe.imphash()");
    assert_eq!(
        res,
        Ok(YrValue::String(Some(
            "61be25042c4f886d1c1894cc5f14523c".to_string()
        )))
    );
}

#[test]
fn test_pe_imphash_without_sample() {
    let mut context = common::context();
    let res = context.eval("pe.imphash()");
    assert_eq!(res, Ok(YrValue::String(None)));
}

#[test]
fn test_yara_ascii_escaped_string() {
    let mut context = common::context_with_pe_signed_sample();
    let res = context.eval("pe.rich_signature.clear_data");
    assert_eq!(res, Ok(YrValue::String(Some("DanS\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00V\\x1f\\x13\\x00%\\x00\\x00\\x00\\x00\\x00\\x00\\x00/\\x00\\x00\\x00b\\x1f\\x13\\x00\\x12\\x00\\x00\\x00\\x83\\x1c\\x0e\\x00\\x1d\\x00\\x00\\x006&\\n\\x00\\x8c\\x00\\x00\\x00\\x00\\x00\\x01\\x00\\x02\\x02\\x00\\x00\\xff \\x04\\x00\\t\\x00\\x00\\x006&\\x0b\\x00y\\x00\\x00\\x00\\xc7\\x06\\x06\\x00\\x01\\x00\\x00\\x00".to_string()))));
}

#[test]
fn test_string_match() {
    let mut context = common::context_with_pe_sample_and_rule();

    // match
    let res = context.eval("r|$s00");
    assert_eq!(res, Ok(YrValue::Integer(1)));

    // no match
    let res = context.eval("r|$s01");
    assert_eq!(res, Ok(YrValue::Integer(0)));
}

#[test]
fn test_string_count_matches() {
    let mut context = common::context_with_pe_sample_and_rule();
    let res = context.eval("r|#s00");
    assert_eq!(res, Ok(YrValue::Integer(1)));
}

#[test]
fn test_string_count_matches_without_rule() {
    let mut context = common::context_with_elf_sample();
    let res = context.eval("r|#s00");
    assert_eq!(res, Err(yari_sys::error::YariError::RuleMissingError));
}

#[test]
fn test_string_match_offset() {
    let mut context = common::context_with_pe_sample_and_rule();
    let res = context.eval("r|@s00[1]");
    assert_eq!(res, Ok(YrValue::Integer(1212)));

    let res = context.eval("@s00[0]");
    assert!(std::matches!(res, Err(YariError::ParserError)));
}

#[test]
fn test_string_match_length() {
    let mut context = common::context_with_pe_sample_and_rule();
    let res = context.eval("r|!s00[1]");
    assert_eq!(res, Ok(YrValue::Integer(5)));
}

#[test]
fn test_string_index_out_of_bounds() {
    let mut context = common::context_with_pe_sample_and_rule();
    let res = context.eval("r|!s00[2]");
    assert_eq!(res, Err(YariError::IndexOutOfBounds));
}

#[test]
fn test_common_values() {
    let mut context = common::context();

    let res = context.eval("elf.ET_NONE").unwrap();
    assert_eq!(res, YrValue::Integer(0));

    let res = context.eval("elf.EM_ARM").unwrap();
    assert_eq!(res, YrValue::Integer(0x28));

    let res = context.eval("pe.NO_SEH").unwrap();
    assert_eq!(res, YrValue::Integer(0x400));

    let res = context.eval("pe.DLL").unwrap();
    assert_eq!(res, YrValue::Integer(0x2000));
}

#[test]
fn test_invalid_symbol_as_function() {
    let mut context = common::context();

    let res = context.eval("hash()");
    assert_eq!(
        res,
        Err(yari_sys::error::YariError::SymbolNotFound(
            "hash".to_string()
        ))
    );
}

#[test]
fn test_invalid_symbol() {
    let mut context = common::context();

    let res = context.eval("time.then()");
    assert_eq!(
        res,
        Err(yari_sys::error::YariError::SymbolNotFound(
            "time.then".to_string()
        ))
    );
}

#[test]
fn test_invalid_access_to_array() {
    let mut context = common::context();

    let res = context.eval("pe.resources.type_string");
    assert_eq!(
        res,
        Err(yari_sys::error::YariError::SymbolNotFound(
            "pe.resources.type_string".to_string()
        ))
    );
}

#[test]
fn test_array_access() {
    let mut context = common::context_with_pe_sample_and_rule();
    let res = context.eval("pe.sections[0].virtual_size");
    assert_eq!(res, Ok(YrValue::Integer(4178)));
}

#[test]
fn test_array() {
    let mut context = common::context_with_pe_sample_and_rule();
    let res = context.eval("pe.sections").unwrap();

    let array = if let YrValue::Array(a) = res {
        assert_eq!(a.len(), 4);
        a
    } else {
        panic!("Expected `Array`");
    };

    for (idx, structure) in array.iter().enumerate() {
        let yara_section_name = context.eval(&format!("pe.sections[{}].name", idx)).unwrap();
        if let YrValue::Structure(Some(s1)) = structure {
            assert_eq!(*s1.get("name").unwrap(), yara_section_name);
        } else {
            panic!("Expected `Structure(Some())`")
        }
    }
}

#[test]
fn test_dictionary_access() {
    let mut context = common::context_with_pe_signed_sample();
    let res = context.eval("pe.version_info[\"OriginalFilename\"]");
    assert_eq!(res, Ok(YrValue::String(Some("Demo.EXE".to_string()))));
}

#[test]
fn test_dictionary() {
    let mut context = common::context_with_pe_signed_sample();
    let res = context.eval("pe.version_info").unwrap();

    match res {
        YrValue::Dictionary(res_map) => {
            assert_eq!(
                *res_map.get("OriginalFilename").unwrap(),
                YrValue::String(Some("Demo.EXE".to_string()))
            );
            assert_eq!(
                *res_map.get("FileVersion").unwrap(),
                YrValue::String(Some("2, 0, 0, 0".to_string()))
            );
            assert_eq!(
                *res_map.get("CompanyName").unwrap(),
                YrValue::String(Some("".to_string()))
            );
            assert_eq!(
                *res_map.get("FileDescription").unwrap(),
                YrValue::String(Some("Demo MFC Application".to_string()))
            );
            assert_eq!(
                *res_map.get("ProductName").unwrap(),
                YrValue::String(Some("Demo Application".to_string()))
            );
            assert_eq!(
                *res_map.get("LegalCopyright").unwrap(),
                YrValue::String(Some("Copyright (C) 2004".to_string()))
            );

            assert_eq!(res_map.len(), 12)
        }
        _ => {
            panic!("Expected `Dictionary` from eval");
        }
    }
}

#[test]
fn test_invalid_dictionary_access() {
    let mut context = common::context_with_pe_signed_sample();
    let res = context.eval("pe.version_info[\"InvalidKey\"]");
    assert_eq!(
        res,
        Err(yari_sys::error::YariError::SymbolNotFound(
            "pe.version_info[\"InvalidKey\"]".to_string()
        ))
    );
}

#[test]
fn test_invalid_arguments_to_function() {
    let mut context = common::context();

    let res = context.eval("pe.imphash(0)");
    assert_eq!(
        res,
        Err(yari_sys::error::YariError::SymbolNotFound(
            "pe.imphash".to_string()
        ))
    );
}

#[test]
fn test_value_with_context() {
    let mut context = common::context_with_pe_sample_and_rule();
    let res = context.eval("r|pe.number_of_sections").unwrap();
    assert_eq!(res, YrValue::Integer(4));
}

#[test]
fn test_public_rule() {
    let mut context = common::context_with_pe_sample_and_rule();
    let res = context.eval("r").unwrap();
    assert_eq!(res, YrValue::Integer(0));
}

#[test]
fn test_private_rule_with_context() {
    let mut context = common::context_with_pe_sample_and_rule();
    let res = context.eval("r|PRIVATE").unwrap();
    assert_eq!(res, YrValue::Integer(1));
}

#[test]
fn test_complex_value_with_context() {
    let mut context = common::context_with_pe_sample_and_rule();
    let res = context.eval("r|pe.number_of_sections == 4").unwrap();
    assert_eq!(res, YrValue::Integer(1));
}

#[test]
fn test_invalid_rule_context() {
    let mut context = common::context_with_pe_sample_and_rule();
    let res = context.eval("invalid_rule|$str");
    assert_eq!(res, Err(yari_sys::error::YariError::RuleMissingError));
}

#[test]
fn test_invalid_complex_value() {
    let mut context = common::context_with_pe_sample_and_rule();
    let res = context.eval("r|this is not valid");
    assert_eq!(
        res,
        Err(yari_sys::error::YariError::SymbolNotFound("r".to_string()))
    );
}

#[test]
fn test_invalid_data() {
    let val = ContextBuilder::parse_module_data_str("test_no_equals");
    assert_eq!(val, None);
    let val = ContextBuilder::parse_module_data_str("cuckoo=too_many=equals");
    assert_eq!(val, None);
}

#[test]
fn test_eval_filesize() {
    let mut context = common::context_with_pe_sample_and_rule();
    assert_eq!(
        context.eval("r|filesize == 8704").unwrap(),
        YrValue::Integer(1)
    );
    assert_eq!(
        context.eval("r|filesize == 0").unwrap(),
        YrValue::Integer(0)
    );
    assert_eq!(
        context.eval("r|filesize == 0x2200").unwrap(),
        YrValue::Integer(1)
    );
    assert_eq!(
        context.eval("r|filesize != 0").unwrap(),
        YrValue::Integer(1)
    );
    assert_eq!(
        context.eval("r|filesize <= 0x10000").unwrap(),
        YrValue::Integer(1)
    );
    assert_eq!(context.eval("r|filesize > 0").unwrap(), YrValue::Integer(1));
}

#[test]
fn test_eval_entrypoint() {
    let mut context = common::context_with_pe_sample_and_rule();
    assert_eq!(
        context.eval("r|entrypoint == 2166").unwrap(),
        YrValue::Integer(1)
    );
    assert_eq!(
        context.eval("r|entrypoint == 0").unwrap(),
        YrValue::Integer(0)
    );
    assert_eq!(
        context.eval("r|entrypoint == 0x876").unwrap(),
        YrValue::Integer(1)
    );
    assert_eq!(
        context.eval("r|entrypoint != 0").unwrap(),
        YrValue::Integer(1)
    );
    assert_eq!(
        context.eval("r|entrypoint <= 0x10000").unwrap(),
        YrValue::Integer(1)
    );
    assert_eq!(
        context.eval("r|entrypoint > 0").unwrap(),
        YrValue::Integer(1)
    );

    let mut context = common::context_with_elf_sample_and_rule();
    assert_eq!(
        context.eval("r|entrypoint == 4160").unwrap(),
        YrValue::Integer(1)
    );
}

#[test]
fn test_eval_integer_postfix() {
    let mut context = common::context_with_pe_sample_and_rule();
    assert_eq!(
        context.eval("r|filesize <= 10KB").unwrap(),
        YrValue::Integer(1)
    );
    assert_eq!(
        context.eval("r|filesize >= 10KB").unwrap(),
        YrValue::Integer(0)
    );
    assert_eq!(
        context.eval("r|filesize <= 1MB").unwrap(),
        YrValue::Integer(1)
    );
    assert_eq!(
        context.eval("r|filesize > 1MB").unwrap(),
        YrValue::Integer(0)
    );
    assert_eq!(
        context.eval("r|filesize == 123MB").unwrap(),
        YrValue::Integer(0)
    );
    assert_eq!(
        context.eval("r|filesize > 0MB").unwrap(),
        YrValue::Integer(1)
    );
}
