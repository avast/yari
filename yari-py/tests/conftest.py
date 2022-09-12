import pytest
import yari


@pytest.fixture
def assets(pytestconfig):
    return pytestconfig.rootdir / ".." / "yari-sys" / "tests" / "assets"


@pytest.fixture
def context():
    return yari.Context()


@pytest.fixture
def context_with_pe_and_rule(assets):
    return yari.Context(sample=str(assets / "pe_hello_world"))


@pytest.fixture
def context_with_elf():
    return yari.Context(sample="")
