import json
from pathlib import Path

VECTORS_PATH = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "spec"
    / "provenance"
    / "v1"
    / "test-vectors.json"
)


def identity_assurance_result(vector: dict[str, str]) -> str:
    """Evaluate identity assurance for the synthetic provenance vectors."""

    if vector["identity_resolution_method"] != "platform_api":
        return "FAIL"

    human_principal_id = vector["human_principal_id"]
    human_principal_login = vector["human_principal_login"]

    if not human_principal_id:
        return "FAIL"

    if vector["pusher_principal_id"] != human_principal_id:
        return "FAIL"

    if not human_principal_login:
        return "FAIL"

    asserted_author = vector["asserted_artifact_author"]
    if not asserted_author:
        return "FAIL"

    # Synthetic source-control author format used only by these test vectors.
    # This is not a Raucle provenance specification requirement.
    expected_author = f"{human_principal_id}+{human_principal_login}@platform.noreply.example"

    if asserted_author != expected_author:
        return "FAIL"

    return "PASS"


def load_identity_vectors() -> list[dict[str, str]]:
    with VECTORS_PATH.open(encoding="utf-8") as handle:
        data = json.load(handle)

    return data["identity_resolution_policy_vectors"]


def test_identity_resolution_policy_vectors() -> None:
    vectors = load_identity_vectors()

    assert vectors

    for vector in vectors:
        assert identity_assurance_result(vector) == vector["expected_identity_result"], vector[
            "name"
        ]


def test_ambient_os_username_collision_fails_identity_assurance() -> None:
    vectors = {vector["name"]: vector for vector in load_identity_vectors()}

    collision = vectors["principal_resolution_ambient_namespace_collision"]

    assert collision["ambient_identifier"] == "asmith"
    assert collision["ambient_namespace"] == "os_username"

    # Exact string reuse across namespaces must not establish identity.
    assert collision["identity_resolution_method"] == "ambient_os_username"
    assert identity_assurance_result(collision) == "FAIL"


def test_authoritative_resolution_passes_identity_assurance() -> None:
    vectors = {vector["name"]: vector for vector in load_identity_vectors()}

    authoritative = vectors["principal_resolution_authoritative"]

    assert authoritative["identity_resolution_method"] == "platform_api"
    assert identity_assurance_result(authoritative) == "PASS"


def test_unavailable_authoritative_source_fails_closed() -> None:
    vectors = {vector["name"]: vector for vector in load_identity_vectors()}

    unavailable = vectors["principal_resolution_authoritative_source_unavailable"]

    assert unavailable["identity_resolution_method"] == "unavailable"
    assert identity_assurance_result(unavailable) == "FAIL"
