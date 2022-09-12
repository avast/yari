import pytest
import yari


@pytest.mark.parametrize(
    "expr, res",
    [
        ('hash.md5("dummy")', "275876e34cf609db118f3d84b799a790"),
    ],
)
def test_eval(expr, res, context):
    assert context.eval(expr) == res


@pytest.mark.parametrize(
    "expr",
    [
        "time.now()",
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
    ],
)
def test_eval_pe(expr, res, context_with_pe_and_rule):
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
