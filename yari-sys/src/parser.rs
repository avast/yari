use crate::error::YariError;
use crate::module::Module;
use nom::branch::alt;
use nom::bytes::complete::is_not;
use nom::bytes::complete::take_while;
use nom::bytes::complete::take_while1;
use nom::character::complete::alpha0;
use nom::character::complete::anychar;
use nom::character::complete::char;
use nom::character::complete::digit1;
use nom::character::is_alphabetic;
use nom::character::is_digit;
use nom::combinator::cut;
use nom::combinator::map;
use nom::combinator::map_res;
use nom::combinator::opt;
use nom::combinator::recognize;
use nom::combinator::verify;
use nom::error::{context, ErrorKind};
use nom::multi::many0;
use nom::multi::separated_list0;
use nom::number::complete::double;
use nom::sequence::delimited;
use nom::sequence::pair;
use nom::sequence::preceded;
use nom::sequence::terminated;
use nom::sequence::tuple;
use nom::Err;
use nom::IResult;
use std::str::FromStr;

/// YARA function argument
#[derive(Debug, PartialEq, PartialOrd)]
pub enum Argument<'a> {
    String(&'a str),
    Regexp(&'a str, &'a str),
    Float(f64),
    Integer(i64),
}

impl Argument<'_> {
    pub fn to_str(&self) -> &'static str {
        match self {
            Argument::String(_) => "s",
            Argument::Regexp(_, _) => "r",
            Argument::Integer(_) => "i",
            Argument::Float(_) => "f",
        }
    }

    pub fn to_char(&self) -> char {
        match self {
            Argument::String(_) => 's',
            Argument::Regexp(_, _) => 'r',
            Argument::Integer(_) => 'i',
            Argument::Float(_) => 'f',
        }
    }
}

/// YARA string operation
#[derive(Debug, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum StrOperation {
    MatchesOnce,
    MatchesCount,
    MatchOffset,
    MatchLength,
}

impl TryFrom<char> for StrOperation {
    type Error = ();

    fn try_from(val: char) -> Result<StrOperation, Self::Error> {
        match val {
            '$' => Ok(Self::MatchesOnce),
            '#' => Ok(Self::MatchesCount),
            '@' => Ok(Self::MatchOffset),
            '!' => Ok(Self::MatchLength),
            _ => Err(()),
        }
    }
}

/// Yara expression enum.
#[derive(Debug, PartialEq, PartialOrd)]
pub enum Expression<'a> {
    Function {
        name: &'a str,
        args: Vec<Argument<'a>>,
    },
    Value(&'a str),
    String {
        operator: StrOperation,
        prefix: &'a str,
        index: Option<i64>,
    },
    Complex(&'a str),
}

impl Expression<'_> {
    /// Try to extract the module from expression.
    ///
    /// ```
    /// # use yari_sys::parser::parse;
    /// # use yari_sys::Module;
    ///
    /// assert_eq!(Some(Module::Time), parse("time.now()").unwrap().1.get_module());
    /// assert_eq!(Some(Module::Pe), parse("pe.number_of_sections").unwrap().1.get_module());
    /// assert_eq!(None, parse("invalid.now()").unwrap().1.get_module());
    /// ```
    pub fn get_module(&self) -> Option<Module> {
        let name = match *self {
            Expression::Function { name, .. } => name,
            Expression::Value(name) => name,
            Expression::String { .. } => return None,
            Expression::Complex(_) => return None,
        };

        name.split('.')
            .next()
            .and_then(|s| Module::from_str(s).ok())
    }
}

fn whitespace(input: &str) -> IResult<&str, &str> {
    let chars = " \t\r\n";
    take_while(move |c| chars.contains(c))(input)
}

fn is_identifier_char(c: char) -> bool {
    is_alphabetic(c as u8) || is_digit(c as u8) || c == '_'
}

fn identifier(input: &str) -> IResult<&str, &str> {
    context("identifier", take_while1(is_identifier_char))(input)
}

fn array_access(input: &str) -> IResult<&str, i64> {
    delimited(char('['), map_res(digit1, i64::from_str), char(']'))(input)
}

fn dict_access(input: &str) -> IResult<&str, &str> {
    delimited(char('['), string, char(']'))(input)
}

fn iterable_access_multi(input: &str) -> IResult<&str, &str> {
    alt((
        recognize(tuple((dict_access, opt(iterable_access_multi)))),
        recognize(tuple((array_access, opt(iterable_access_multi)))),
    ))(input)
}

fn rule_context(input: &str) -> IResult<&str, &str> {
    delimited(whitespace, terminated(identifier, char('|')), whitespace)(input)
}

fn identifier_multi(input: &str) -> IResult<&str, &str> {
    recognize(tuple((
        identifier,
        opt(iterable_access_multi),
        opt(tuple((char('.'), cut(identifier_multi)))),
    )))(input)
}

fn string_escape(input: &str) -> IResult<&str, &str> {
    recognize(tuple((char('\\'), anychar)))(input)
}

fn string_str(input: &str) -> IResult<&str, &str> {
    recognize(many0(alt((is_not("\\\""), string_escape))))(input)
}

fn string(input: &str) -> IResult<&str, &str> {
    delimited(char('"'), string_str, char('"'))(input)
}

fn regexp_escape(input: &str) -> IResult<&str, &str> {
    recognize(tuple((char('\\'), anychar)))(input)
}

fn regexp_str(input: &str) -> IResult<&str, &str> {
    recognize(many0(alt((is_not("\\/"), regexp_escape))))(input)
}

fn regexp_modifiers(input: &str) -> IResult<&str, &str> {
    cut(verify(alpha0, |mods: &str| {
        let mut i = 0;
        let mut s = 0;
        for c in mods.chars() {
            match c {
                'i' => i += 1,
                's' => s += 1,
                _ => return false,
            }
        }

        (i <= 1) && (s <= 1)
    }))(input)
}

fn regexp(input: &str) -> IResult<&str, (&str, &str)> {
    pair(
        delimited(char('/'), regexp_str, char('/')),
        regexp_modifiers,
    )(input)
}

fn argument(input: &str) -> IResult<&str, Argument> {
    preceded(
        whitespace,
        alt((
            map(string, Argument::String),
            map(regexp, |(r, m)| Argument::Regexp(r, m)),
            map_res(is_not(",)"), |i: &str| {
                i.parse::<i64>().map(Argument::Integer)
            }),
            map(double, Argument::Float),
        )),
    )(input)
}

fn arguments(input: &str) -> IResult<&str, Vec<Argument>> {
    context(
        "argument_list",
        preceded(
            char('('),
            terminated(
                separated_list0(preceded(whitespace, char(',')), argument),
                preceded(whitespace, char(')')),
            ),
        ),
    )(input)
}

fn function_call(input: &str) -> IResult<&str, (&str, Vec<Argument>)> {
    let res = delimited(whitespace, pair(identifier_multi, arguments), whitespace)(input);

    if res.is_ok() && !res.as_ref().unwrap().0.is_empty() {
        Err(Err::Error(nom::error::Error::new(
            res.as_ref().unwrap().0,
            ErrorKind::Verify,
        )))
    } else {
        res
    }
}

fn value_access(input: &str) -> IResult<&str, &str> {
    let res = delimited(whitespace, identifier_multi, whitespace)(input);

    if res.is_ok() && !res.as_ref().unwrap().0.is_empty() {
        Err(Err::Error(nom::error::Error::new(
            res.as_ref().unwrap().0,
            ErrorKind::Verify,
        )))
    } else {
        res
    }
}

fn string_index(input: &str) -> IResult<&str, i64> {
    cut(verify(array_access, |i: &i64| *i > 0))(input)
}

fn string_operation(input: &str) -> IResult<&str, (StrOperation, &str, Option<i64>)> {
    let res = delimited(
        whitespace,
        alt((
            map(
                pair(
                    verify(
                        map_res(anychar, StrOperation::try_from),
                        |op: &StrOperation| *op == StrOperation::MatchesOnce,
                    ),
                    identifier,
                ),
                |(op, identifier)| (op, identifier, None),
            ),
            map(
                pair(
                    verify(
                        map_res(anychar, StrOperation::try_from),
                        |op: &StrOperation| *op == StrOperation::MatchesCount,
                    ),
                    identifier,
                ),
                |(op, identifier)| (op, identifier, None),
            ),
            map(
                tuple((
                    verify(
                        map_res(anychar, StrOperation::try_from),
                        |op: &StrOperation| *op == StrOperation::MatchLength,
                    ),
                    identifier,
                    string_index,
                )),
                |(op, identifier, index)| (op, identifier, Some(index)),
            ),
            map(
                tuple((
                    verify(
                        map_res(anychar, StrOperation::try_from),
                        |op: &StrOperation| *op == StrOperation::MatchOffset,
                    ),
                    identifier,
                    string_index,
                )),
                |(op, identifier, index)| (op, identifier, Some(index)),
            ),
        )),
        whitespace,
    )(input);

    if res.is_ok() && !res.as_ref().unwrap().0.is_empty() {
        Err(Err::Error(nom::error::Error::new(
            res.as_ref().unwrap().0,
            ErrorKind::Verify,
        )))
    } else {
        res
    }
}

fn complex_value(input: &str) -> IResult<&str, &str> {
    take_while1(|_| true)(input)
}

fn expression(input: &str) -> IResult<&str, (Option<&str>, Expression)> {
    alt((
        pair(
            opt(rule_context),
            alt((
                map(string_operation, |s| Expression::String {
                    operator: s.0,
                    prefix: s.1,
                    index: s.2,
                }),
                map(function_call, |func| Expression::Function {
                    name: func.0,
                    args: func.1,
                }),
                map(value_access, Expression::Value),
            )),
        ),
        map(pair(rule_context, complex_value), |(rule, value)| {
            (Some(rule), Expression::Complex(value))
        }),
    ))(input)
}

/// Parse YARA expression with optional rule context.
///
/// ```
/// # use yari_sys::parser::parse;
/// # use yari_sys::parser::Expression;
///
/// assert_eq!(
///     parse("time.now()"),
///     Ok(
///         (
///             None,
///             Expression::Function {
///                 name: "time.now",
///                 args: Vec::new(),
///             },
///         )
///     )
/// );
/// ```
pub fn parse(input: &str) -> Result<(Option<&str>, Expression), YariError> {
    expression(input)
        .map(|(_, exp)| exp)
        .map_err(|_| YariError::ParserError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::error::ErrorKind;
    use nom::Err;

    #[test]
    fn test_function_call_no_args() {
        let res = expression("time.now()");
        assert_eq!(
            res,
            Ok((
                "",
                (
                    None,
                    Expression::Function {
                        name: "time.now",
                        args: Vec::new()
                    },
                ),
            ))
        );
    }

    #[test]
    fn test_function_call_ignore_leading_whitespace() {
        let res = expression("              time.now()");
        assert_eq!(
            res,
            Ok((
                "",
                (
                    None,
                    Expression::Function {
                        name: "time.now",
                        args: Vec::new()
                    },
                ),
            ))
        );
    }

    #[test]
    fn test_function_call_ignore_trailing_whitespace() {
        let res = expression("time.now()\n");
        assert_eq!(
            res,
            Ok((
                "",
                (
                    None,
                    Expression::Function {
                        name: "time.now",
                        args: Vec::new()
                    },
                ),
            ))
        );
    }

    #[test]
    fn test_function_call_args_one_regexp() {
        let res = expression("cuckoo.filesystem.file_access(/.*/)");
        assert_eq!(
            res,
            Ok((
                "",
                (
                    None,
                    Expression::Function {
                        name: "cuckoo.filesystem.file_access",
                        args: vec![Argument::Regexp(".*", "")]
                    },
                ),
            ))
        );
    }

    #[test]
    fn test_function_call_args_ii() {
        let res = expression("math.mean(0, 123)");
        assert_eq!(
            res,
            Ok((
                "",
                (
                    None,
                    Expression::Function {
                        name: "math.mean",
                        args: vec![Argument::Integer(0), Argument::Integer(123)]
                    },
                ),
            ))
        );
    }

    #[test]
    fn test_function_call_args_empty_string() {
        let res = expression("math.mean(\"\")");
        assert_eq!(
            res,
            Ok((
                "",
                (
                    None,
                    Expression::Function {
                        name: "math.mean",
                        args: vec!(Argument::String(""))
                    },
                ),
            ))
        );
    }

    #[test]
    fn test_function_call_fff() {
        let res = expression("math.in_range(1.0, 63.9, 64.1)");
        assert_eq!(
            res,
            Ok((
                "",
                (
                    None,
                    Expression::Function {
                        name: "math.in_range",
                        args: vec![
                            Argument::Float(1.0),
                            Argument::Float(63.9),
                            Argument::Float(64.1),
                        ]
                    },
                ),
            ))
        );
    }

    #[test]
    fn test_function_call_sf() {
        let res = expression("math.deviation(\"data\", 64.1)");
        assert_eq!(
            res,
            Ok((
                "",
                (
                    None,
                    Expression::Function {
                        name: "math.deviation",
                        args: vec![Argument::String("data"), Argument::Float(64.1)]
                    },
                ),
            ))
        );
    }

    #[test]
    fn test_long_float() {
        // Nom 7.0 cannot handle this case and panics
        let res = argument("0.00000000000000000087");
        assert_eq!(res, Ok(("", Argument::Float(0.00000000000000000087))));
    }

    #[test]
    fn test_parse_function_call_ri() {
        assert_eq!(
            parse(r"cuckoo.network.tcp(/192\.168\.1\.1/, 443)"),
            Ok((
                None,
                Expression::Function {
                    name: "cuckoo.network.tcp",
                    args: vec![
                        Argument::Regexp(r"192\.168\.1\.1", ""),
                        Argument::Integer(443)
                    ]
                },
            ))
        );
    }

    #[test]
    fn test_function_call_ri() {
        let res = expression(r"cuckoo.network.tcp(/192\.168\.1\.1/, 443)");
        assert_eq!(
            res,
            Ok((
                "",
                (
                    None,
                    Expression::Function {
                        name: "cuckoo.network.tcp",
                        args: vec![
                            Argument::Regexp(r"192\.168\.1\.1", ""),
                            Argument::Integer(443)
                        ]
                    },
                ),
            ))
        );
    }

    #[test]
    fn test_function_call_i() {
        let res = expression(r"pe.rich_signature.version(24215)");
        assert_eq!(
            res,
            Ok((
                "",
                (
                    None,
                    Expression::Function {
                        name: "pe.rich_signature.version",
                        args: vec![Argument::Integer(24215)]
                    },
                ),
            ))
        );
    }

    #[test]
    fn test_function_call_ii() {
        let res = expression(r"pe.rich_signature.version(24215, 261)");
        assert_eq!(
            res,
            Ok((
                "",
                (
                    None,
                    Expression::Function {
                        name: "pe.rich_signature.version",
                        args: vec![Argument::Integer(24215), Argument::Integer(261)]
                    },
                ),
            ))
        );
    }

    #[test]
    fn test_function_call_identifier_with_numbers() {
        let res = expression("hash.crc32(\"data\")");
        assert_eq!(
            res,
            Ok((
                "",
                (
                    None,
                    Expression::Function {
                        name: "hash.crc32",
                        args: vec![Argument::String("data")]
                    },
                ),
            ))
        );
    }

    #[test]
    fn test_function_call_args_one_regexp_hard() {
        let res =
            expression(r"cuckoo.filesystem.file_write(/^\/root\/\.po1kitd\.thumb\/\.po1kitd-/)");
        assert_eq!(
            res,
            Ok((
                "",
                (
                    None,
                    Expression::Function {
                        name: "cuckoo.filesystem.file_write",
                        args: vec![Argument::Regexp(
                            r"^\/root\/\.po1kitd\.thumb\/\.po1kitd-",
                            ""
                        )]
                    },
                ),
            ))
        );
    }

    #[test]
    fn test_function_call_with_hexa_arguments() {
        // Hexa arguments are not implemented yet, however parsing should still be successful to allow fallback evaluation
        let res = parse("rule|hash.sha256(0x0, 0x400)");
        assert_eq!(
            res,
            Ok((Some("rule"), Expression::Complex("hash.sha256(0x0, 0x400)")))
        );
    }

    #[test]
    fn test_identifier_array_access() {
        let res = identifier_multi("pe.sections[0].name");
        assert_eq!(res, Ok(("", "pe.sections[0].name")));
    }

    #[test]
    fn test_identifier_dictionary_access() {
        let res = identifier_multi("pe.version_info[\"CompanyName\"]");
        assert_eq!(res, Ok(("", "pe.version_info[\"CompanyName\"]")));
    }

    #[test]
    fn test_identifier_dot_before_iterable_access() {
        let res = identifier_multi("pe.version_info.[\"CompanyName\"]");
        assert_eq!(
            res,
            Err(Err::Failure(nom::error::Error::new(
                "[\"CompanyName\"]",
                ErrorKind::TakeWhile1
            )))
        );
    }

    #[test]
    fn test_identifier_double_dot() {
        let res = identifier_multi("pe..version_info");
        assert_eq!(
            res,
            Err(Err::Failure(nom::error::Error::new(
                ".version_info",
                ErrorKind::TakeWhile1
            )))
        );
    }

    #[test]
    fn test_identifier_starts_with_dot() {
        let res = identifier_multi(".pe.version_info");
        assert_eq!(
            res,
            Err(Err::Error(nom::error::Error::new(
                ".pe.version_info",
                ErrorKind::TakeWhile1
            )))
        );
    }

    #[test]
    fn test_identifier_ends_with_dot() {
        let res = identifier_multi("pe.version_info[\"CompanyName\"].");
        assert_eq!(
            res,
            Err(Err::Failure(nom::error::Error::new(
                "",
                ErrorKind::TakeWhile1
            )))
        );
    }

    #[test]
    fn test_regexp_hard() {
        let res = regexp(r"/\./");
        assert_eq!(res, Ok(("", (r"\.", ""))));
    }

    #[test]
    fn test_regexp_no_modifiers() {
        let res = regexp("/.*/");
        assert_eq!(res, Ok(("", (".*", ""))));
    }

    #[test]
    fn test_regexp_modifiers_no_case() {
        let res = regexp("/.*/i");
        assert_eq!(res, Ok(("", (".*", "i"))));
    }

    #[test]
    fn test_regexp_modifiers_dot_all() {
        let res = regexp("/.*/s");
        assert_eq!(res, Ok(("", (".*", "s"))));
    }

    #[test]
    fn test_regexp_modifiers_invalid() {
        let res = regexp("/.*/abc");
        assert_eq!(
            res,
            Err(Err::Failure(nom::error::Error::new(
                "abc",
                ErrorKind::Verify
            )))
        );
    }

    #[test]
    fn test_regexp_modifiers_combined() {
        let res = regexp("/.*/is");
        assert_eq!(res, Ok(("", (".*", "is"))));
    }

    #[test]
    fn test_regexp() {
        let res = regexp("/.*/");
        assert_eq!(res, Ok(("", (".*", ""))));
    }

    #[test]
    fn test_regexp_string() {
        let res = regexp(r"/abc/");
        assert_eq!(res, Ok(("", ("abc", ""))));
    }

    #[test]
    fn test_regexp_escaped_forwardslash() {
        let res = regexp(r"/a\/b/");
        assert_eq!(res, Ok(("", (r"a\/b", ""))));
    }

    #[test]
    fn test_string_escaped_quotes() {
        let res = string(r#""\"""#);
        assert_eq!(res, Ok(("", r#"\""#)));
    }

    #[test]
    fn test_value() {
        let res = expression("pe.entry_point");
        assert_eq!(res, Ok(("", (None, Expression::Value("pe.entry_point")))));
    }

    #[test]
    fn test_rule_name() {
        let res = expression("rule_name");
        assert_eq!(res, Ok(("", (None, Expression::Value("rule_name")))));
    }

    #[test]
    fn test_value_with_context() {
        let res = expression("rule_name|pe.entry_point");
        assert_eq!(
            res,
            Ok(("", (Some("rule_name"), Expression::Value("pe.entry_point"))))
        );
    }

    #[test]
    fn test_escape() {
        let res = regexp_escape(r"\/");
        assert_eq!(res, Ok(("", r"\/")));
    }

    #[test]
    fn test_escape_dot() {
        let res = regexp_escape(r"\.");
        assert_eq!(res, Ok(("", r"\.")));
    }

    #[test]
    fn test_escape_char() {
        let res = regexp_escape(r"\a");
        assert_eq!(res, Ok(("", r"\a")));
    }

    #[test]
    fn test_escape_star() {
        let res = regexp_escape(r"\*");
        assert_eq!(res, Ok(("", r"\*")));
    }

    #[test]
    fn test_escape_plus() {
        let res = regexp_escape(r"\+");
        assert_eq!(res, Ok(("", r"\+")));
    }

    #[test]
    fn test_escape_paren() {
        let res = regexp_escape(r"\[");
        assert_eq!(res, Ok(("", r"\[")));
    }

    #[test]
    fn test_regexp_escape2() {
        let res = regexp(r"/123\.\\/");
        assert_eq!(res, Ok(("", (r"123\.\\", ""))));
    }

    #[test]
    fn test_string_match() {
        let res = expression("r|$s00");
        assert_eq!(
            res,
            Ok((
                "",
                (
                    Some("r"),
                    Expression::String {
                        operator: StrOperation::MatchesOnce,
                        prefix: "s00",
                        index: None,
                    },
                ),
            )),
        );
    }

    #[test]
    fn test_string_count() {
        let res = expression("rule|#02");
        assert_eq!(
            res,
            Ok((
                "",
                (
                    Some("rule"),
                    Expression::String {
                        operator: StrOperation::MatchesCount,
                        prefix: "02",
                        index: None,
                    },
                ),
            )),
        );
    }

    #[test]
    fn test_string_match_offset() {
        let res = expression("a12|@str[1]");
        assert_eq!(
            res,
            Ok((
                "",
                (
                    Some("a12"),
                    Expression::String {
                        operator: StrOperation::MatchOffset,
                        prefix: "str",
                        index: Some(1),
                    },
                ),
            )),
        );
    }

    #[test]
    fn test_string_match_length() {
        let res = expression("22|!str[4]");
        assert_eq!(
            res,
            Ok((
                "",
                (
                    Some("22"),
                    Expression::String {
                        operator: StrOperation::MatchLength,
                        prefix: "str",
                        index: Some(4),
                    },
                ),
            )),
        );
    }

    #[test]
    fn test_string_match_invalid_index_use() {
        let res = string_operation("$s01[3]");
        assert_eq!(
            res,
            Err(Err::Error(nom::error::Error::new("[3]", ErrorKind::Verify)))
        );
    }

    #[test]
    fn test_string_match_missing_index() {
        let res = string_operation("!s01");
        assert_eq!(
            res,
            Err(Err::Failure(nom::error::Error::new("", ErrorKind::Char))),
        );
    }

    #[test]
    fn test_string_match_invalid_index() {
        let res = string_operation("!s01[0]");
        assert_eq!(
            res,
            Err(Err::Failure(nom::error::Error::new(
                "[0]",
                ErrorKind::Verify
            ))),
        );
    }

    #[test]
    fn test_string_missing_operation() {
        let res = string_operation("s00");
        assert_eq!(
            res,
            Err(Err::Error(nom::error::Error::new("s00", ErrorKind::MapRes))),
        );
    }

    #[test]
    fn test_complex_expression_eq() {
        let res = expression("rule|pe.num_of_sections == 4");
        assert_eq!(
            res,
            Ok((
                "",
                (Some("rule"), Expression::Complex("pe.num_of_sections == 4")),
            ))
        );
    }

    #[test]
    fn test_complex_expression_and() {
        let res = expression("rule|$s00 and pe.num_of_sections == 4");
        assert_eq!(
            res,
            Ok((
                "",
                (
                    Some("rule"),
                    Expression::Complex("$s00 and pe.num_of_sections == 4")
                ),
            ))
        );
    }

    #[test]
    fn test_complex_expression_without_context() {
        let res = expression("pe.num_of_sections == 4");
        assert_eq!(
            res,
            Err(Err::Error(nom::error::Error::new(
                ".num_of_sections == 4",
                ErrorKind::Char
            ))),
        );
    }

    #[test]
    fn test_empty() {
        let res = expression("");
        assert!(res.is_err());
    }
}
