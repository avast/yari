import pytest
import yari

TEST_RULE = """import "pe"
private rule PRIVATE {
    condition:
        pe.number_of_sections == 4
}

rule r {
    strings:
        $s00 = "Hello"
        $s01 = "this is a pretty unique string that should not be found in the provided sample"
    condition:
        all of them and PRIVATE
}
"""


@pytest.fixture
def assets(pytestconfig):
    return pytestconfig.rootdir / ".." / "yari-sys" / "tests" / "assets"


@pytest.fixture
def context():
    return yari.Context()


@pytest.fixture
def context_with_pe_and_rule(assets):
    return yari.Context(sample=str(assets / "pe_hello_world"), rule_string=TEST_RULE)


@pytest.fixture
def context_with_elf(assets):
    return yari.Context(sample=str(assets / "elf_hello_world"))
