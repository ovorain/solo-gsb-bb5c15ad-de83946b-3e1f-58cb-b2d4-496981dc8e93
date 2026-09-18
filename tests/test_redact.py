import hashlib
import json

from fastapi.testclient import TestClient

from app.main import app
from app.canonicalize import canonicalize

client = TestClient(app)


def redact(document, rules):
    return client.post("/redact", json={"document": document, "rules": rules})


def jcs_hash(value):
    return hashlib.sha256(canonicalize(value).encode("utf-8")).hexdigest()


# ------------------------------------------------------------ basic actions


def test_remove_object_member():
    r = redact({"a": 1, "b": 2}, [{"path": "/a", "action": "remove"}])
    assert r.status_code == 200
    assert r.json() == {"document": {"b": 2}, "hits": [
        {"path": "/a", "action": "remove", "rule": 0},
    ]}


def test_remove_array_element_shifts_tail():
    r = redact([1, 2, 3], [{"path": "/1", "action": "remove"}])
    assert r.status_code == 200
    assert r.json() == {"document": [1, 3], "hits": [
        {"path": "/1", "action": "remove", "rule": 0},
    ]}


def test_mask_replaces_value_with_triple_stars():
    r = redact({"secret": {"nested": [1, 2]}},
               [{"path": "/secret", "action": "mask"}])
    assert r.status_code == 200
    assert r.json() == {"document": {"secret": "***"}, "hits": [
        {"path": "/secret", "action": "mask", "rule": 0},
    ]}


def test_mask_may_target_arrays_and_scalars():
    r = redact([1, 2, 3], [{"path": "/1", "action": "mask"}])
    assert r.json()["document"] == [1, "***", 3]

    r = redact(42, [{"path": "/**", "action": "mask"}])
    assert r.json()["document"] == "***"


def test_hash_is_sha256_of_jcs_canonical_value():
    value = {"b": 1, "a": [3, 2, 1]}
    r = redact({"secret": value, "keep": True},
               [{"path": "/secret", "action": "hash"}])
    assert r.status_code == 200
    body = r.json()
    assert body["document"] == {"secret": jcs_hash(value), "keep": True}
    assert body["hits"] == [{"path": "/secret", "action": "hash", "rule": 0}]


def test_hash_scalar_values():
    r = redact({"n": 42, "s": "x", "flag": False, "nil": None}, [
        {"path": "/n", "action": "hash"},
        {"path": "/s", "action": "hash"},
        {"path": "/flag", "action": "hash"},
        {"path": "/nil", "action": "hash"},
    ])
    assert r.json()["document"] == {
        "n": jcs_hash(42),
        "s": jcs_hash("x"),
        "flag": jcs_hash(False),
        "nil": jcs_hash(None),
    }


# ------------------------------------------------------------ glob matching


def test_single_star_matches_every_object_member():
    r = redact({"a": {"x": 1}, "b": {"x": 2}},
               [{"path": "/*/x", "action": "remove"}])
    assert r.status_code == 200
    assert r.json()["document"] == {"a": {}, "b": {}}
    assert [h["path"] for h in r.json()["hits"]] == ["/a/x", "/b/x"]


def test_single_star_matches_every_array_index():
    r = redact({"cards": [{"cvv": "1"}, {"cvv": "2"}, {"cvv": "3"}]},
               [{"path": "/cards/*/cvv", "action": "mask"}])
    assert r.status_code == 200
    assert r.json()["document"] == {
        "cards": [{"cvv": "***"}, {"cvv": "***"}, {"cvv": "***"}],
    }
    assert [h["path"] for h in r.json()["hits"]] == [
        "/cards/0/cvv", "/cards/1/cvv", "/cards/2/cvv",
    ]


def test_single_star_does_not_cross_levels():
    # /*/c matches /a/c but not /a/b/c.
    r = redact({"a": {"c": 1, "b": {"c": 2}}},
               [{"path": "/*/c", "action": "mask"}])
    assert r.json()["document"] == {"a": {"c": "***", "b": {"c": 2}}}


def test_double_star_matches_zero_or_more_levels():
    doc = {"a": {"b": 1, "nested": {"b": 2, "deep": {"b": 3}}}}
    r = redact(doc, [{"path": "/a/**/b", "action": "mask"}])
    assert r.status_code == 200
    assert r.json()["document"] == {
        "a": {"b": "***", "nested": {"b": "***", "deep": {"b": "***"}}},
    }
    assert [h["path"] for h in r.json()["hits"]] == [
        "/a/b", "/a/nested/b", "/a/nested/deep/b",
    ]


def test_double_star_alone_matches_root_and_every_node_but_terminal_prunes():
    # The root hit wins for the whole tree, so descendants are not visited.
    r = redact({"a": {"b": 1}}, [{"path": "/**", "action": "mask"}])
    assert r.json() == {"document": "***", "hits": [
        {"path": "", "action": "mask", "rule": 0},
    ]}


def test_double_star_matches_across_arrays():
    r = redact([{"x": [{"secret": "s"}]}],
               [{"path": "/**/secret", "action": "mask"}])
    assert r.json()["document"] == [{"x": [{"secret": "***"}]}]
    assert r.json()["hits"][0]["path"] == "/0/x/0/secret"


def test_literal_asterisk_inside_token_is_not_a_wildcard():
    doc = {"a*b": 1, "axb": 2, "*": 3}
    r = redact(doc, [{"path": "/a*b", "action": "mask"}])
    assert r.json()["document"] == {"a*b": "***", "axb": 2, "*": 3}


def test_literal_array_index_and_out_of_range_index():
    r = redact([1, 2, 3], [
        {"path": "/0", "action": "mask"},
        {"path": "/9", "action": "remove"},
    ])
    assert r.json()["document"] == ["***", 2, 3]
    assert [h["path"] for h in r.json()["hits"]] == ["/0"]


def test_pointer_escaping_in_globs():
    r = redact({"a/b": {"~c": 1}},
               [{"path": "/a~1b/~0c", "action": "mask"}])
    assert r.json()["document"] == {"a/b": {"~c": "***"}}
    assert r.json()["hits"][0]["path"] == "/a~1b/~0c"


def test_empty_pointer_targets_root():
    r = redact({"a": 1}, [{"path": "", "action": "hash"}])
    assert r.status_code == 200
    assert r.json()["document"] == jcs_hash({"a": 1})
    assert r.json()["hits"] == [{"path": "", "action": "hash", "rule": 0}]


def test_non_matching_rules_produce_empty_hits():
    doc = {"a": 1}
    snapshot = json.dumps(doc)
    r = redact(doc, [{"path": "/x/**/y", "action": "remove"}])
    assert r.status_code == 200
    assert r.json() == {"document": {"a": 1}, "hits": []}
    assert json.dumps(doc) == snapshot


def test_empty_rules_list_returns_unchanged_document():
    r = redact({"a": [1, 2]}, [])
    assert r.json() == {"document": {"a": [1, 2]}, "hits": []}


# ------------------------------------------------------------ arbitration


def test_rule_with_fewer_wildcards_wins_on_same_path():
    r = redact({"a": {"b": {"c": 1}}}, [
        {"path": "/**/c", "action": "remove"},
        {"path": "/a/b/c", "action": "mask"},
    ])
    assert r.json()["document"] == {"a": {"b": {"c": "***"}}}
    assert r.json()["hits"] == [
        {"path": "/a/b/c", "action": "mask", "rule": 1},
    ]


def test_single_star_and_double_star_tie_on_count_longer_pattern_wins():
    # Both patterns have one wildcard token; /a/*/x/c is longer (4 tokens)
    # than /**/c (3 tokens) and both hit /a/y/x/c.
    doc = {"a": {"y": {"x": {"c": 1}}}}
    r = redact(doc, [
        {"path": "/**/c", "action": "remove"},
        {"path": "/a/*/x/c", "action": "mask"},
    ])
    assert r.json()["document"] == {"a": {"y": {"x": {"c": "***"}}}}
    assert r.json()["hits"][0]["rule"] == 1


def test_equal_specificity_resolved_by_declaration_order():
    r = redact({"a": {"b": {"c": 1}}}, [
        {"path": "/a/**/c", "action": "remove"},
        {"path": "/a/*/c", "action": "mask"},
    ])
    assert r.json()["document"] == {"a": {"b": {}}}
    assert r.json()["hits"][0]["rule"] == 0

    r = redact({"a": {"b": {"c": 1}}}, [
        {"path": "/a/*/c", "action": "mask"},
        {"path": "/a/**/c", "action": "remove"},
    ])
    assert r.json()["document"] == {"a": {"b": {"c": "***"}}}
    assert r.json()["hits"][0]["rule"] == 0


def test_exact_same_rule_path_declaration_order():
    r = redact({"a": 1}, [
        {"path": "/a", "action": "mask"},
        {"path": "/a", "action": "remove"},
    ])
    assert r.json()["document"] == {"a": "***"}
    assert r.json()["hits"][0]["rule"] == 0


def test_ancestor_match_is_terminal_and_prunes_descendants():
    # /a is removed outright; the mask under it cannot fire and is not a hit.
    r = redact({"a": {"b": 1, "c": 2}, "keep": 3}, [
        {"path": "/a", "action": "remove"},
        {"path": "/a/b", "action": "mask"},
        {"path": "/keep", "action": "mask"},
    ])
    assert r.json()["document"] == {"keep": "***"}
    assert [h["path"] for h in r.json()["hits"]] == ["/a", "/keep"]


def test_winner_is_chosen_independently_per_concrete_path():
    # The exact path outranks the globstar at the shallow secret; the
    # deeper secret is only reachable through the globstar, which then
    # applies there even though it lost higher up.
    doc = {"users": {"secret": 1, "other": {"secret": 2}}}
    r = redact(doc, [
        {"path": "/**/secret", "action": "mask"},
        {"path": "/users/secret", "action": "remove"},
    ])
    assert r.status_code == 200
    assert r.json()["document"] == {
        "users": {"other": {"secret": "***"}},
    }
    assert r.json()["hits"] == [
        {"path": "/users/other/secret", "action": "mask", "rule": 0},
        {"path": "/users/secret", "action": "remove", "rule": 1},
    ]


# ------------------------------------------------------------ conflicts


def test_remove_whole_document_is_409():
    r = redact({"a": 1}, [{"path": "", "action": "remove"}])
    assert r.status_code == 409
    body = r.json()
    assert body == {
        "detail": "redaction conflict",
        "failed_index": 0,
        "path": "",
        "reason": "'remove' cannot target the whole document",
    }


def test_remove_root_via_double_star_is_409():
    r = redact([1, 2], [{"path": "/**", "action": "remove"}])
    assert r.status_code == 409
    body = r.json()
    assert body["failed_index"] == 0 and body["path"] == ""


def test_losing_root_remove_does_not_conflict():
    # The exact-pointer mask wins at the root (fewer wildcards), so the
    # globstar remove never applies.
    r = redact({"a": 1}, [
        {"path": "/**", "action": "remove"},
        {"path": "", "action": "mask"},
    ])
    assert r.status_code == 200
    assert r.json()["document"] == "***"


# ------------------------------------------------------------ validation (422)


def test_rules_must_be_an_array():
    r = client.post("/redact", json={"document": {}, "rules": {"path": "/a"}})
    assert r.status_code == 422


def test_document_field_required():
    r = client.post("/redact", json={"rules": []})
    assert r.status_code == 422


def test_rule_must_be_an_object():
    r = redact({}, [42])
    assert r.status_code == 422
    assert r.json()["failed_index"] == 0


def test_missing_action():
    r = redact({"a": 1}, [{"path": "/a"}])
    assert r.status_code == 422
    body = r.json()
    assert body["detail"] == "invalid redaction rule"
    assert body["failed_index"] == 0
    assert body["path"] == "/a"


def test_unknown_action():
    r = redact({"a": 1}, [{"path": "/a", "action": "encrypt"}])
    assert r.status_code == 422
    assert "encrypt" in r.json()["reason"]
    assert r.json()["failed_index"] == 0


def test_missing_path():
    r = redact({"a": 1}, [{"action": "remove"}])
    assert r.status_code == 422
    assert r.json()["failed_index"] == 0


def test_non_string_path_or_action():
    r = redact({"a": 1}, [{"path": 1, "action": "remove"}])
    assert r.status_code == 422
    r = redact({"a": 1}, [{"path": "/a", "action": 7}])
    assert r.status_code == 422


def test_pointer_must_start_with_slash():
    r = redact({"a": 1}, [{"path": "a", "action": "remove"}])
    assert r.status_code == 422
    assert r.json()["path"] == "a"


def test_pointer_escape_must_be_0_or_1():
    r = redact({"a": 1}, [{"path": "/a~2", "action": "remove"}])
    assert r.status_code == 422
    assert r.json()["path"] == "/a~2"


def test_all_rules_validated_before_anything_runs():
    # Rule 0 is valid and would apply, but rule 1 is malformed: no
    # result and a 422 naming the failing index must come back.
    doc = {"a": 1, "b": 2}
    snapshot = json.dumps(doc)
    r = redact(doc, [
        {"path": "/a", "action": "remove"},
        {"path": "/b", "action": "nuke"},
    ])
    assert r.status_code == 422
    assert r.json()["failed_index"] == 1
    assert json.dumps(doc) == snapshot


def test_extra_rule_fields_are_ignored():
    r = redact({"a": 1}, [{"path": "/a", "action": "mask", "note": "x"}])
    assert r.status_code == 200
    assert r.json()["document"] == {"a": "***"}


# ------------------------------------------------------------ immutability


def test_input_document_is_never_modified():
    doc = {"user": {"ssn": "123", "tags": ["a", "b"]}, "n": 1}
    snapshot = json.dumps(doc)
    r = redact(doc, [
        {"path": "/user/ssn", "action": "mask"},
        {"path": "/user/tags/*", "action": "remove"},
        {"path": "/n", "action": "hash"},
    ])
    assert r.status_code == 200
    assert json.dumps(doc) == snapshot
    assert doc == {"user": {"ssn": "123", "tags": ["a", "b"]}, "n": 1}


def test_result_does_not_alias_input_subtrees():
    doc = {"a": {"b": 1}}
    r = redact(doc, [{"path": "/a", "action": "mask"}])
    assert r.json()["document"] == {"a": "***"}
    # Masking replaced the subtree rather than mutating the original.
    assert doc["a"] == {"b": 1}


# ------------------------------------------------------------ response shape


def test_hits_sorted_as_rfc6901_paths_indices_before_names():
    # At a common parent, array indices sort numerically and before
    # member names; at the top level member names sort lexicographically.
    doc = {"z": [1, 2], "a": {"k": 1}, "b": 1}
    r = redact(doc, [
        {"path": "/b", "action": "mask"},
        {"path": "/a/k", "action": "mask"},
        {"path": "/z/1", "action": "mask"},
        {"path": "/z/0", "action": "mask"},
    ])
    assert r.status_code == 200
    paths = [h["path"] for h in r.json()["hits"]]
    assert paths == ["/a/k", "/b", "/z/0", "/z/1"]


def test_each_hit_records_action_and_rule_index():
    r = redact({"a": 1, "b": 2, "c": 3}, [
        {"path": "/a", "action": "remove"},
        {"path": "/b", "action": "mask"},
        {"path": "/c", "action": "hash"},
    ])
    assert r.json()["hits"] == [
        {"path": "/a", "action": "remove", "rule": 0},
        {"path": "/b", "action": "mask", "rule": 1},
        {"path": "/c", "action": "hash", "rule": 2},
    ]


# ------------------------------------------------------------ misc


def test_deeply_nested_document_beyond_default_recursion_limit():
    # Exercises the engine directly (the stdlib JSON encoder used by
    # the HTTP test client has its own, unrelated, depth limit).
    from app.redact import redact as run_redact

    depth = 3000
    doc = leaf = {}
    for _ in range(depth):
        leaf["child"] = {}
        leaf = leaf["child"]
    leaf["target"] = "secret"

    result, hits = run_redact(doc, [{"path": "/**/**/target", "action": "mask"}])
    assert len(hits) == 1
    assert hits[0]["path"].count("/") == depth + 1
    leaf = result
    for _ in range(depth):
        leaf = leaf["child"]
    assert leaf["target"] == "***"


def test_repeated_double_star_is_idempotent():
    doc = {"a": {"b": {"secret": 1}}, "secret": 2}
    r = redact(doc, [{"path": "/**/**/secret", "action": "mask"}])
    assert r.status_code == 200
    paths = [h["path"] for h in r.json()["hits"]]
    assert paths == ["/a/b/secret", "/secret"]
