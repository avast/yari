extern crate lazy_static;

use lazy_static::lazy_static;
use regex::Regex;

use crate::error::YariError;

pub fn expression_to_rules_with_condition(
    rules: &str,
    target_rule: &str,
    expression: &str,
) -> Result<String, YariError> {
    lazy_static! {
        static ref IMPORT_RE: Regex = Regex::new(r#"(?m)^import "\w+"$"#).unwrap();
        static ref RULE_RE: Regex =
            Regex::new(r"(?m)^(private )?rule (?P<name>\w+)(.|\n)+?condition:(.|\n)+?}$").unwrap();
        static ref STRINGS_RE: Regex = Regex::new(r"\s+strings:\s+\$").unwrap();
        static ref CONDITION_RE: Regex = Regex::new("condition:(.|\n)+}\n").unwrap();
    }

    let mut new_rules = String::new();

    // Preserve imports from original rules
    for caps in IMPORT_RE.captures_iter(rules) {
        new_rules.push_str(caps.get(0).ok_or(YariError::EvalError)?.as_str());
        new_rules.push('\n');
    }

    for caps in RULE_RE.captures_iter(rules) {
        let mut rule_text = caps.get(0).ok_or(YariError::EvalError)?.as_str().to_owned();
        rule_text.push('\n');

        if caps.name("name").ok_or(YariError::EvalError)?.as_str() == target_rule {
            let mut first = String::new();
            if STRINGS_RE.is_match(&rule_text) {
                first = "(all of them and not all of them) or ".to_owned();
            }
            let second = String::from(expression);
            let condition = format!("condition: {}({}) }}\n", first, second).replace('$', "$$"); // $ has to be escaped in order to work with regex.replace

            rule_text = CONDITION_RE.replace(&rule_text, condition).to_string();
        }
        new_rules.push_str(&rule_text);
    }
    Ok(new_rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expression_simple() {
        let res = expression_to_rules_with_condition(
            "rule test {
	condition:
		true
}",
            "test",
            "time.now() > 2",
        );
        assert_eq!(
            res,
            Ok(String::from(
                "rule test {\n\tcondition: (time.now() > 2) }\n"
            ))
        );
    }

    #[test]
    fn test_expression_to_condition_with_string() {
        let res = expression_to_rules_with_condition(
            "rule test {
                strings:
                    $s00 = \"This is a test.\"
                condition:
                    !s00
}",
            "test",
            "time.now() > 2",
        );
        assert_eq!(
            res,
            Ok(String::from(
                "rule test {
                strings:
                    $s00 = \"This is a test.\"
                condition: (all of them and not all of them) or (time.now() > 2) }
"
            ))
        );
    }

    #[test]
    fn test_expression_to_condition_simple_oneline() {
        let res = expression_to_rules_with_condition(
            "import \"pe\"\nrule test { condition: true }",
            "test",
            "pe.number_of_signatures > 2",
        );
        assert_eq!(
            res,
            Ok(String::from(
                "import \"pe\"\nrule test { condition: (pe.number_of_signatures > 2) }\n"
            ))
        );
    }

    #[test]
    fn test_expression_to_condition_oneline_with_string() {
        let res = expression_to_rules_with_condition(
            "rule test { strings: $s00 = \"This is a test.\" condition: !s00 }",
            "test",
            "time.now() > 2",
        );
        assert_eq!(
            res,
            Ok(String::from("rule test { strings: $s00 = \"This is a test.\" condition: (all of them and not all of them) or (time.now() > 2) }\n"))
        );
    }
}
