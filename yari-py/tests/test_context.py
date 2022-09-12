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
        c = yari.Context(**context_kwargs)
