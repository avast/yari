import pytest
import yari


@pytest.mark.parametrize(
    "expr, res",
    [
        ('hash.md5("dummy")', "275876e34cf609db118f3d84b799a790"),
    ],
)
def test_eval(expr, res, context, context_with_pe_and_rule, context_with_elf):
    """Those expressions should be valid in all context with samples or rules."""
    assert context.eval(expr) == res
    assert context_with_pe_and_rule.eval(expr) == res
    assert context_with_elf.eval(expr) == res


@pytest.mark.parametrize(
    "expr",
    [
        "time.now()",
        'hash.md5("dummy")',
    ],
)
def test_eval_bool(expr, context):
    assert context.eval_bool(expr)


@pytest.mark.parametrize(
    "expr, res",
    [
        ("pe.number_of_sections", 4),
        (
            "hash.sha256(0, 100)",
            "f852ce40ef76aae540d7e316271215235d984fef26359be2b25cfabea8da4ace",
        ),
        ("r|1 == 1", 1),
        ("r|$s00", 1),
        ("r|$s01", 0),
        ("r|#s00", 1),
        ("r|@s00[1]", 1212),
        ("r|!s00[1]", 5),
    ],
)
def test_eval_pe_and_rule(expr, res, context_with_pe_and_rule):
    assert context_with_pe_and_rule.eval(expr) == res


@pytest.mark.parametrize(
    "expr, res",
    [
        ("r|$s00", True),
        ("r|$s01", False),
    ],
)
def test_eval_rule_strings(expr, res, context_with_pe_and_rule):
    assert context_with_pe_and_rule.eval(expr) == res


@pytest.mark.parametrize(
    "expr",
    ("time.now", "invalid_module", "time.not_now()", ""),
)
def test_eval_raises(expr, context):
    with pytest.raises(yari.YariError) as e:
        context.eval(expr)

    with pytest.raises(yari.YariError) as e:
        context.eval_bool(expr)


def test_eval_with_missing_string_raises_exception(context_with_pe_and_rule):
    with pytest.raises(yari.YariError) as e:
        context_with_pe_and_rule.eval("r|$s123")


def test_eval_with_missing_rule_raises_excpetion(context_with_pe_and_rule):
    with pytest.raises(yari.YariError) as e:
        context_with_pe_and_rule.eval("this_rule_should_be_missing|$s123")
