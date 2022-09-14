import pytest
import yari


def test_core():
    c = yari.Context()
    c.eval("time.now()")


@pytest.mark.parametrize(
    "context_kwargs", [{"module_data": {"invalid_module": "test"}}]
)
def test_raise(context_kwargs):
    with pytest.raises(yari.YariError) as e:
        _ = yari.Context(**context_kwargs)


def test_context_with_rule_path(tmp_path):
    rule_path = tmp_path / "test.yar"
    rule_path.write_text(
        """rule test {
    condition:
        true
}"""
    )
    c = yari.Context(rule_path=str(rule_path))
    c.eval("time.now()")
