"""Tests for ``POST /redact`` (JSON Pointer glob redaction)."""

import hashlib
from copy import deepcopy

from fastapi.testclient import TestClient

from app.canonicalize import canonicalize
from app.main import app
from app.redact import apply_redactions

client = TestClient(app)


def redact(document, rules):
    return client.post("/redact", json={"document": document, "rules": rules})


def sha256_of(value):
    """The digest a ``hash`` action must produce for ``value``."""
    return hashlib.sha256(canonicalize(value).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- remove


def test_remove_object_key():
    r = redact({"a": 1, "b": 2}, [{"path": "/a", "action": "remove"}])
    assert r.status_code == 200
    assert r.json() == {"document": {"b": 2}, "matched": ["/a"]}


def test_remove_nested_path():
    r = redact(
        {"a": {"b": {"c": 1, "d": 2}}},
        [{"path": "/a/b/c", "action": "remove"}],
    )
    assert r.status_code == 200
    assert r.json() == {
        "document": {"a": {"b": {"d": 2}}},
        "matched": ["/a/b/c"],
    }


def test_remove_array_element():
    r = redact({"l": ["a", "b", "c"]}, [{"path": "/l/1", "action": "remove"}])
    assert r.status_code == 200
    assert r.json() == {"document": {"l": ["a", "c"]}, "matched": ["/l/1"]}


def test_remove_all_array_elements_via_star():
    r = redact({"l": [1, 2]}, [{"path": "/l/*", "action": "remove"}])
    assert r.status_code == 200
    assert r.json() == {"document": {"l": []}, "matched": ["/l/0", "/l/1"]}


def test_remove_two_array_indices_addresses_original_document():
    # Both indices address the original array; removing one must not
    # shift the other's target.
    r = redact(
        {"l": ["a", "b", "c"]},
        [
            {"path": "/l/0", "action": "remove"},
            {"path": "/l/2", "action": "remove"},
        ],
    )
    assert r.status_code == 200
    assert r.json() == {"document": {"l": ["b"]}, "matched": ["/l/0", "/l/2"]}


def test_remove_null_value_removes_key():
    r = redact({"a": None, "b": 1}, [{"path": "/a", "action": "remove"}])
    assert r.status_code == 200
    assert r.json() == {"document": {"b": 1}, "matched": ["/a"]}


# ------------------------------------------------------------------ mask


def test_mask_scalar():
    r = redact({"pw": "secret"}, [{"path": "/pw", "action": "mask"}])
    assert r.status_code == 200
    assert r.json() == {"document": {"pw": "***"}, "matched": ["/pw"]}


def test_mask_whole_subtree():
    r = redact(
        {"a": {"b": [1, {"c": 2}]}, "z": 0},
        [{"path": "/a", "action": "mask"}],
    )
    assert r.status_code == 200
    assert r.json() == {"document": {"a": "***", "z": 0}, "matched": ["/a"]}


def test_mask_null_value():
    r = redact({"a": None}, [{"path": "/a", "action": "mask"}])
    assert r.status_code == 200
    assert r.json() == {"document": {"a": "***"}, "matched": ["/a"]}


def test_mask_boolean_and_number():
    r = redact(
        {"a": True, "b": 4.5},
        [{"path": "/a", "action": "mask"}, {"path": "/b", "action": "mask"}],
    )
    assert r.status_code == 200
    assert r.json()["document"] == {"a": "***", "b": "***"}


# ------------------------------------------------------------------ hash


def test_hash_string_is_sha256_of_canonical_json():
    # sha256 of the RFC 8785 canonical text '"secret"'.
    r = redact({"pw": "secret"}, [{"path": "/pw", "action": "hash"}])
    assert r.status_code == 200
    assert r.json() == {
        "document": {
            "pw": "c1980264fc223a890afae83c91bd2d438ef2ad0dae751fdea3660c3e556b1396"
        },
        "matched": ["/pw"],
    }


def test_hash_number_is_sha256_of_canonical_json():
    # sha256 of the canonical text '42'.
    r = redact({"n": 42}, [{"path": "/n", "action": "hash"}])
    assert r.status_code == 200
    assert r.json() == {
        "document": {
            "n": "73475cb40a568e8da8a045ced110137e159f890ac4da883b6b17dc651b3a8049"
        },
        "matched": ["/n"],
    }


def test_hash_object_subtree():
    r = redact({"obj": {"a": 1}}, [{"path": "/obj", "action": "hash"}])
    assert r.status_code == 200
    # sha256 of the canonical text '{"a":1}'.
    assert r.json() == {
        "document": {
            "obj": "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"
        },
        "matched": ["/obj"],
    }


def test_hash_array_uses_canonical_form():
    r = redact({"l": [1, "x", None]}, [{"path": "/l", "action": "hash"}])
    assert r.status_code == 200
    assert r.json() == {"document": {"l": sha256_of([1, "x", None])}, "matched": ["/l"]}


def test_hash_matches_canonicalize_endpoint():
    # The hash action and /canonicalize must agree on the digest.
    value = {"b": [1, 2.5, "€"], "a": True}
    canonical = client.post("/canonicalize", json={"document": value}).json()
    r = redact({"v": value}, [{"path": "/v", "action": "hash"}])
    assert r.json()["document"]["v"] == canonical["sha256"]


def test_hash_uncanonicalizable_value_is_422():
    r = redact({"big": 10**400}, [{"path": "/big", "action": "hash"}])
    assert r.status_code == 422
    body = r.json()
    assert body["detail"] == "value cannot be hashed"
    assert "IEEE 754" in body["reason"]


# ------------------------------------------------------------- glob: `*`


def test_star_matches_each_object_member():
    r = redact(
        {"users": {"a": 1, "b": 2}},
        [{"path": "/users/*", "action": "mask"}],
    )
    assert r.status_code == 200
    assert r.json() == {
        "document": {"users": {"a": "***", "b": "***"}},
        "matched": ["/users/a", "/users/b"],
    }


def test_star_matches_array_elements():
    r = redact({"l": [1, 2]}, [{"path": "/l/*", "action": "mask"}])
    assert r.status_code == 200
    assert r.json() == {
        "document": {"l": ["***", "***"]},
        "matched": ["/l/0", "/l/1"],
    }


def test_star_matches_exactly_one_level():
    r = redact(
        {"a": {"b": {"c": 1}}},
        [{"path": "/a/*", "action": "mask"}],
    )
    assert r.status_code == 200
    # /a/b matched (and masked wholesale); /a/b/c was never addressed.
    assert r.json() == {"document": {"a": {"b": "***"}}, "matched": ["/a/b"]}


def test_star_does_not_descend_into_scalars():
    r = redact(
        {"a": 1, "b": {"c": 2}},
        [{"path": "/*/*", "action": "mask"}],
    )
    assert r.status_code == 200
    assert r.json() == {"document": {"a": 1, "b": {"c": "***"}}, "matched": ["/b/c"]}


def test_star_in_array_of_objects():
    r = redact(
        {"users": [{"pw": 1}, {"pw": 2}]},
        [{"path": "/users/*/pw", "action": "mask"}],
    )
    assert r.status_code == 200
    assert r.json() == {
        "document": {"users": [{"pw": "***"}, {"pw": "***"}]},
        "matched": ["/users/0/pw", "/users/1/pw"],
    }


# ------------------------------------------------------------ glob: `**`


def test_double_star_matches_any_depth():
    r = redact(
        {"a": {"password": 1, "b": {"password": 2}}, "password": 3},
        [{"path": "/**/password", "action": "mask"}],
    )
    assert r.status_code == 200
    assert r.json() == {
        "document": {"a": {"password": "***", "b": {"password": "***"}}, "password": "***"},
        "matched": ["/a/b/password", "/a/password", "/password"],
    }


def test_double_star_suffix_includes_the_base_itself():
    r = redact(
        {"a": {"b": {"c": 1}}, "z": 0},
        [{"path": "/a/**", "action": "remove"}],
    )
    assert r.status_code == 200
    assert r.json() == {
        "document": {"z": 0},
        "matched": ["/a", "/a/b", "/a/b/c"],
    }


def test_double_star_matches_root_and_everything_below():
    r = redact({"a": 1}, [{"path": "/**", "action": "mask"}])
    assert r.status_code == 200
    assert r.json() == {"document": "***", "matched": ["", "/a"]}


def test_double_star_on_scalar_document_matches_root_only():
    r = redact(5, [{"path": "/**", "action": "mask"}])
    assert r.status_code == 200
    assert r.json() == {"document": "***", "matched": [""]}


def test_multiple_double_stars():
    r = redact(
        {"a": {"x": {"pw": 1}}, "b": {"y": {"pw": 2}}, "pw": 3},
        [{"path": "/**/pw", "action": "remove"}],
    )
    assert r.status_code == 200
    assert r.json() == {
        "document": {"a": {"x": {}}, "b": {"y": {}}},
        "matched": ["/a/x/pw", "/b/y/pw", "/pw"],
    }


# ------------------------------------------------------- literal tokens


def test_specific_array_index():
    r = redact([10, 20, 30], [{"path": "/1", "action": "mask"}])
    assert r.status_code == 200
    assert r.json() == {"document": [10, "***", 30], "matched": ["/1"]}


def test_numeric_token_matches_object_key():
    r = redact({"l": {"0": "x"}}, [{"path": "/l/0", "action": "mask"}])
    assert r.status_code == 200
    assert r.json() == {"document": {"l": {"0": "***"}}, "matched": ["/l/0"]}


def test_leading_zero_token_matches_object_key_but_not_array():
    r = redact({"01": "x"}, [{"path": "/01", "action": "mask"}])
    assert r.status_code == 200
    assert r.json() == {"document": {"01": "***"}, "matched": ["/01"]}
    r = redact([10, 20], [{"path": "/01", "action": "mask"}])
    assert r.status_code == 200
    assert r.json() == {"document": [10, 20], "matched": []}


def test_dash_token_never_matches_an_array_element():
    r = redact({"l": [1, 2]}, [{"path": "/l/-", "action": "mask"}])
    assert r.status_code == 200
    assert r.json() == {"document": {"l": [1, 2]}, "matched": []}


def test_out_of_range_index_matches_nothing():
    r = redact({"l": [1]}, [{"path": "/l/5", "action": "mask"}])
    assert r.status_code == 200
    assert r.json() == {"document": {"l": [1]}, "matched": []}


def test_rfc6901_escaping_in_pattern_and_reported_paths():
    r = redact(
        {"a/b": {"~x": 1}},
        [{"path": "/a~1b/~0x", "action": "mask"}],
    )
    assert r.status_code == 200
    assert r.json() == {
        "document": {"a/b": {"~x": "***"}},
        "matched": ["/a~1b/~0x"],
    }


def test_glob_reports_special_keys_escaped():
    r = redact({"a/b": 1, "plain": 2}, [{"path": "/*", "action": "mask"}])
    assert r.status_code == 200
    assert r.json()["matched"] == ["/a~1b", "/plain"]


# -------------------------------------------------------------- priority


def test_fewer_wildcards_win():
    r = redact(
        {"a": {"b": 1, "c": 2}},
        [
            {"path": "/a/*", "action": "remove"},
            {"path": "/a/b", "action": "mask"},
        ],
    )
    assert r.status_code == 200
    assert r.json() == {"document": {"a": {"b": "***"}}, "matched": ["/a/b", "/a/c"]}


def test_longer_path_wins():
    r = redact(
        {"a": {"x": {"b": 1}}, "b": 2},
        [
            {"path": "/**/b", "action": "remove"},
            {"path": "/a/**/b", "action": "mask"},
        ],
    )
    assert r.status_code == 200
    assert r.json() == {
        "document": {"a": {"x": {"b": "***"}}},
        "matched": ["/a/x/b", "/b"],
    }


def test_declaration_order_breaks_ties():
    r = redact(
        {"a": 1},
        [
            {"path": "/a", "action": "mask"},
            {"path": "/a", "action": "remove"},
        ],
    )
    assert r.status_code == 200
    assert r.json() == {"document": {"a": "***"}, "matched": ["/a"]}


def test_declaration_order_breaks_ties_reverse():
    r = redact(
        {"a": 1},
        [
            {"path": "/a", "action": "remove"},
            {"path": "/a", "action": "mask"},
        ],
    )
    assert r.status_code == 200
    assert r.json() == {"document": {}, "matched": ["/a"]}


def test_same_path_is_reported_once():
    r = redact(
        {"a": {"b": 1}},
        [
            {"path": "/a/*", "action": "mask"},
            {"path": "/a/b", "action": "mask"},
        ],
    )
    assert r.status_code == 200
    assert r.json() == {"document": {"a": {"b": "***"}}, "matched": ["/a/b"]}


# ------------------------------------------------------- combined rules


def test_multiple_disjoint_rules():
    r = redact(
        {"a": 1, "b": 2, "c": 3},
        [
            {"path": "/a", "action": "remove"},
            {"path": "/b", "action": "mask"},
            {"path": "/c", "action": "hash"},
        ],
    )
    assert r.status_code == 200
    assert r.json() == {
        "document": {"b": "***", "c": sha256_of(3)},
        "matched": ["/a", "/b", "/c"],
    }


def test_mask_ancestor_subsumes_remove_descendant():
    r = redact(
        {"a": {"b": 1, "c": 2}},
        [
            {"path": "/a", "action": "mask"},
            {"path": "/a/b", "action": "remove"},
        ],
    )
    assert r.status_code == 200
    # The removal is subsumed by the ancestor mask but still matched.
    assert r.json() == {"document": {"a": "***"}, "matched": ["/a", "/a/b"]}


def test_remove_ancestor_and_descendant():
    r = redact(
        {"a": {"b": 1}, "z": 0},
        [
            {"path": "/a", "action": "remove"},
            {"path": "/a/b", "action": "remove"},
        ],
    )
    assert r.status_code == 200
    assert r.json() == {"document": {"z": 0}, "matched": ["/a", "/a/b"]}


def test_hash_uses_the_original_value():
    # The digest covers the value as submitted, even though a sibling
    # rule removes one of its members.
    r = redact(
        {"a": {"b": 1, "c": 2}},
        [
            {"path": "/a/b", "action": "remove"},
            {"path": "/a", "action": "hash"},
        ],
    )
    assert r.status_code == 200
    assert r.json() == {
        "document": {"a": sha256_of({"b": 1, "c": 2})},
        "matched": ["/a", "/a/b"],
    }


def test_mask_and_remove_in_same_array_address_original_positions():
    r = redact(
        {"l": ["a", "b", "c"]},
        [
            {"path": "/l/1", "action": "mask"},
            {"path": "/l/0", "action": "remove"},
        ],
    )
    assert r.status_code == 200
    assert r.json() == {"document": {"l": ["***", "c"]}, "matched": ["/l/0", "/l/1"]}


def test_matched_paths_sorted_indices_before_names():
    document = {"list": list(range(11)), "name": "x"}
    r = redact(document, [{"path": "/*/*", "action": "mask"}, {"path": "/name", "action": "mask"}])
    assert r.status_code == 200
    # Array indices sort numerically (not lexicographically: 2 before 10)
    # and before member names at the same level.
    expected = [f"/list/{i}" for i in range(11)] + ["/name"]
    assert r.json()["matched"] == expected


def test_no_match_returns_document_unchanged():
    r = redact({"a": 1}, [{"path": "/nope", "action": "mask"}])
    assert r.status_code == 200
    assert r.json() == {"document": {"a": 1}, "matched": []}


def test_empty_rules_return_document_unchanged():
    r = redact({"a": [1, 2]}, [])
    assert r.status_code == 200
    assert r.json() == {"document": {"a": [1, 2]}, "matched": []}


# ------------------------------------------------------------------ root


def test_empty_pattern_matches_root_only():
    r = redact({"a": 1}, [{"path": "", "action": "mask"}])
    assert r.status_code == 200
    assert r.json() == {"document": "***", "matched": [""]}


def test_mask_root_replaces_whole_document():
    r = redact({"a": {"b": 1}}, [{"path": "", "action": "mask"}])
    assert r.status_code == 200
    assert r.json() == {"document": "***", "matched": [""]}


def test_hash_root():
    r = redact({"a": 1}, [{"path": "", "action": "hash"}])
    assert r.status_code == 200
    assert r.json() == {
        "document": "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862",
        "matched": [""],
    }


def test_scalar_document_root_mask():
    r = redact("secret", [{"path": "", "action": "mask"}])
    assert r.status_code == 200
    assert r.json() == {"document": "***", "matched": [""]}


def test_remove_root_is_409():
    r = redact({"a": 1}, [{"path": "", "action": "remove"}])
    assert r.status_code == 409
    assert r.json() == {
        "detail": "redact conflict",
        "failed_index": 0,
        "path": "",
        "reason": "'remove' cannot target the whole document",
    }


def test_remove_root_via_glob_is_409_with_winning_rule_index():
    r = redact(
        {"x": 1},
        [
            {"path": "/x", "action": "mask"},
            {"path": "/**", "action": "remove"},
        ],
    )
    assert r.status_code == 409
    assert r.json()["failed_index"] == 1
    assert r.json()["path"] == ""


# ------------------------------------------------------- invalid requests


def test_rules_must_be_an_array():
    r = client.post("/redact", json={"document": {}, "rules": "x"})
    assert r.status_code == 422


def test_rule_must_be_an_object():
    r = redact({}, [1])
    assert r.status_code == 422
    assert r.json() == {
        "detail": "invalid redact rule",
        "reason": "each rule must be an object",
        "failed_index": 0,
    }


def test_missing_action():
    r = redact({}, [{"path": "/a"}])
    assert r.status_code == 422
    assert r.json() == {
        "detail": "invalid redact rule",
        "reason": "missing 'action' field",
        "failed_index": 0,
        "path": "/a",
    }


def test_unsupported_action():
    r = redact({}, [{"path": "/a", "action": "encrypt"}])
    assert r.status_code == 422
    assert r.json() == {
        "detail": "invalid redact rule",
        "reason": "unsupported action 'encrypt'; supported actions are: "
        "remove, mask, hash",
        "failed_index": 0,
        "path": "/a",
    }


def test_missing_path():
    r = redact({}, [{"action": "mask"}])
    assert r.status_code == 422
    assert r.json() == {
        "detail": "invalid redact rule",
        "reason": "missing or non-string 'path' field",
        "failed_index": 0,
    }


def test_non_string_path():
    r = redact({}, [{"action": "mask", "path": 1}])
    assert r.status_code == 422
    assert r.json()["reason"] == "missing or non-string 'path' field"


def test_pointer_must_start_with_slash():
    r = redact({}, [{"path": "a", "action": "mask"}])
    assert r.status_code == 422
    body = r.json()
    assert body["reason"] == "malformed JSON Pointer: non-empty pointer must start with '/'"
    assert body["failed_index"] == 0
    assert body["path"] == "a"


def test_pointer_bad_tilde_escape():
    r = redact({}, [{"path": "/a~", "action": "mask"}])
    assert r.status_code == 422
    assert r.json()["reason"] == "malformed JSON Pointer: '~' must be followed by '0' or '1'"


def test_all_rules_are_validated_before_any_matching():
    # The second rule is invalid, so nothing is applied even though the
    # first rule would have matched.
    r = redact(
        {"a": 1},
        [
            {"path": "/a", "action": "mask"},
            {"path": "/b", "action": "bogus"},
        ],
    )
    assert r.status_code == 422
    assert r.json()["failed_index"] == 1


def test_missing_document_field_is_422():
    r = client.post("/redact", json={"rules": []})
    assert r.status_code == 422


def test_missing_rules_field_is_422():
    r = client.post("/redact", json={"document": {}})
    assert r.status_code == 422


# ------------------------------------------------------- input immutability


def test_apply_redactions_does_not_modify_the_input_document():
    document = {"a": {"b": [1, 2, 3]}, "c": "secret"}
    snapshot = deepcopy(document)
    result, matched = apply_redactions(
        document,
        [
            {"path": "/a/b/1", "action": "remove"},
            {"path": "/c", "action": "hash"},
            {"path": "/a", "action": "mask"},
        ],
    )
    assert document == snapshot
    assert result == {"a": "***", "c": sha256_of("secret")}
    assert matched == ["/a", "/a/b/1", "/c"]


def test_result_is_independent_of_the_input_document():
    document = {"a": {"b": 1}}
    result, _ = apply_redactions(document, [{"path": "/z", "action": "mask"}])
    result["a"]["b"] = 99
    assert document == {"a": {"b": 1}}
