# policies/default.toml is where an operator learns what a policy can say: every layer, masking layer, session limit
# and tool spec key the code accepts is in it, and nothing it lists is something the code ignores.
import re
import tomllib

from sieve.integrations import tenant
from sieve.integrations.tenant import LETTERED, SESSION_KEYS, load_policy
from sieve.output import OUTPUT_CHECKS
from sieve.paths import POLICIES
from sieve.pipeline import LAYERS, default_check_layers
from sieve.tools import SPEC_KEYS, TYPES

DEFAULT = POLICIES / "default.toml"


def read():
    return DEFAULT.read_text(encoding="utf-8"), tomllib.loads(DEFAULT.read_text(encoding="utf-8"))


def test_every_layer_masking_layer_and_session_limit_is_listed():
    _, data = read()
    layers = {layer.name for layer in default_check_layers()} | {"prompt_injection_ml", "session", tenant.TOOL_CHECK,
                                                                 "indirect_injection", *OUTPUT_CHECKS}
    assert set(data["layers"]) == layers
    assert set(data["masking"]) == {layer.name for layer in LAYERS} | {LETTERED}
    assert set(data["session"]) == SESSION_KEYS
    assert set(data) == tenant.KEYS - {"thresholds", "actions"}  # those two are commented examples


def test_the_tool_example_names_every_spec_key_and_type():
    text, _ = read()
    example = text[text.index("[tools.para_transferi]"):]
    assert {key for key in SPEC_KEYS if re.search(rf"#\s+{key} =", example)} == SPEC_KEYS
    types = re.search(r"#\s*(str \|.*)$", example, re.MULTILINE).group(1)  # the comment after params
    assert {name for name in TYPES if re.search(rf"\b{name}\b", types)} == set(TYPES)


# A tenant with its own version would hide a change to default.toml in its events; the version names both.
def test_a_tenants_version_names_the_base_one_too(tmp_path):
    _, data = read()
    (tmp_path / "default.toml").write_text(DEFAULT.read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "own.toml").write_text('version = "t-7"\n', encoding="utf-8")
    (tmp_path / "plain.toml").write_text('mode = "monitor"\n', encoding="utf-8")
    assert load_policy("default", tmp_path).version == data["version"]
    assert load_policy("plain", tmp_path).version == data["version"]
    assert load_policy("own", tmp_path).version == f"t-7+default.{data['version']}"
