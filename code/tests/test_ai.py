import json
import sys
from pathlib import Path
from unittest.mock import patch
import urllib.request

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ghost_audit.ai import LocalSemanticAgent, SemanticError, _NoRedirect, _authorization_decision, _lexical_authorization_fallback


def transport(response):
    def call(payload):
        return {"message": {"content": json.dumps(response)}, "prompt_eval_count": 31, "eval_count": 9}
    return call


def test_intent_uses_model_and_content_cache(tmp_path):
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport({"authorize_deletion": False, "quote": "Do not delete", "reason": "export only"}))
    assert agent.authorize("Do not delete; export my data.") is False
    assert agent.authorize("Do not delete; export my data.") is False
    assert agent.usage["model_calls"] == 1
    assert agent.usage["cache_hits"] == 1
    assert agent.usage["input_tokens"] == 31


def test_korean_explicit_account_deletion_and_negation():
    positive = "이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다."
    negative = "계정 삭제를 요청하지 않습니다. 프로필은 유지해 주세요."
    ambiguous = "계정 삭제 방법을 알려 주세요."
    assert _lexical_authorization_fallback(positive) is True
    assert _authorization_decision(positive, positive, False) is True
    assert _lexical_authorization_fallback(negative) is False
    assert _authorization_decision(negative, negative, True) is False
    assert _lexical_authorization_fallback(ambiguous) is None


def test_rejects_non_boolean_authorization(tmp_path):
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport({"authorize_deletion": "false", "quote": "export", "reason": "export"}))
    with pytest.raises(SemanticError):
        agent.authorize("export my data")


def test_retries_malformed_model_json_with_a_shorter_response(tmp_path):
    output_limits = []

    def transport(payload):
        output_limits.append(payload["options"]["num_predict"])
        content = "{\"authorize_deletion\": true, \"quote\": \"Delete my account\"" if len(output_limits) == 1 else json.dumps({
            "authorize_deletion": True,
            "quote": "Delete my account",
            "reason": "explicit request",
        })
        return {"message": {"content": content}, "prompt_eval_count": 20, "eval_count": 6}

    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport)
    assert agent.authorize("Delete my account.") is True
    assert output_limits == [180, 360]
    assert agent.usage["model_calls"] == 2
    assert agent.usage["input_tokens"] == 40


def test_malformed_model_json_fails_after_one_retry(tmp_path):
    calls = []

    def transport(_payload):
        calls.append(True)
        return {"message": {"content": "not json"}}

    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport)
    with pytest.raises(SemanticError, match="after one retry: JSONDecodeError"):
        agent.authorize("Delete my account.")
    assert len(calls) == 2


def test_non_object_model_json_fails_after_one_retry(tmp_path):
    calls = []

    def transport(_payload):
        calls.append(True)
        return {"message": {"content": "[]"}}

    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport)
    with pytest.raises(SemanticError, match="after one retry: ValueError"):
        agent.authorize("Delete my account.")
    assert len(calls) == 2


def test_malformed_model_elapsed_time_is_counted_once_per_attempt(tmp_path):
    def malformed(_payload):
        return {"message": {"content": "[]"}}

    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=malformed)
    ticks = iter((0.0, 1.0, 2.0, 3.0))
    with patch("ghost_audit.ai.time.perf_counter", side_effect=lambda: next(ticks)):
        with pytest.raises(SemanticError):
            agent._ask("task", {"type": "object"}, {})
    assert agent.usage["elapsed_seconds"] == 2.0


def test_http_transport_disables_proxies_and_redirects(tmp_path):
    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b'{"message": {"content": "{}"}}'

    class Opener:
        def open(self, _request, timeout):
            assert timeout == 45
            return Response()

    agent = LocalSemanticAgent(cache_dir=tmp_path)
    with patch("urllib.request.build_opener", return_value=Opener()) as build_opener:
        agent._http_call({"model": "local"})
    proxy, redirect = build_opener.call_args.args
    assert isinstance(proxy, urllib.request.ProxyHandler)
    assert proxy.proxies == {}
    assert isinstance(redirect, _NoRedirect)
    assert redirect.redirect_request(None, None, 307, "Temporary Redirect", {}, "http://remote.example") is None


@pytest.mark.parametrize("endpoint", [
    "http://localhost.attacker.example:11434",
    "http://127.0.0.1@attacker.example:11434",
    "http://localhost@127.0.0.1:11434",
    "https://127.0.0.1:11434",
    "http://127.0.0.1:11434/path",
    "http://127.0.0.1:11434/?next=evil",
])
def test_rejects_nonlocal_or_noncanonical_model_endpoints(tmp_path, endpoint):
    with pytest.raises(ValueError, match="loopback"):
        LocalSemanticAgent(cache_dir=tmp_path, endpoint=endpoint)


@pytest.mark.parametrize("endpoint", [
    "http://127.0.0.1:11434",
    "http://[::1]:11434",
    "http://localhost:11434",
])
def test_accepts_loopback_model_endpoints(tmp_path, endpoint):
    agent = LocalSemanticAgent(cache_dir=tmp_path, endpoint=endpoint)
    assert agent.endpoint == endpoint


def test_batch_uses_grounded_lexical_fallback_only_after_model_json_failure(tmp_path):
    calls = []

    def transport(_payload):
        calls.append(True)
        return {"message": {"content": "not json"}}

    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport)
    assert agent.authorize_many([
        "Please erase my account.",
        "Please export my data.",
        "Please make my account forgotten.",
    ]) == [True, False, None]
    assert len(calls) == 6
    assert agent.usage["lexical_fallbacks"] == 3


def test_cloud_model_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        LocalSemanticAgent(model="some-model:cloud", cache_dir=tmp_path)


def test_interpretation_requires_source_grounded_quote(tmp_path):
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport({"state": "PRESENT", "resource_id": "object-a", "quote": "invented phrase", "reason": "x"}))
    result = agent.interpret_evidence("object-a is visible", "evidence_x", ["object-a"])
    assert result["state"] == "UNRESOLVED"


def test_interpretation_accepts_grounded_read(tmp_path):
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport({"state": "PRESENT", "resource_id": "object-a", "quote": "object-a is visible", "reason": "listed object"}))
    result = agent.interpret_evidence("object-a is visible", "evidence_x", ["object-a"])
    assert result["source_id"] == "evidence_x"
    assert result["state"] == "PRESENT"


def test_malformed_evidence_response_stays_unresolved_without_aborting(tmp_path):
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=lambda _payload: {"message": {"content": "not json"}})
    result = agent.interpret_evidence("object-a is visible", "evidence_x", ["object-a"])
    assert result["state"] == "UNRESOLVED"
    assert result["resource_id"] == "object-a"
    assert agent.usage["evidence_unresolved"] == 1


def test_batch_authorization_requires_each_exact_quote(tmp_path):
    response = {"results": [
        {"index": 1, "authorize_deletion": True, "quote": "Delete my account", "reason": "explicit"},
        {"index": 0, "authorize_deletion": True, "quote": "made up quote", "reason": "not grounded"},
    ]}
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport(response))
    assert agent.authorize_many(["Please export my data", "Delete my account"], batch_size=2) == [False, True]


def test_batch_authorization_rejects_omitted_input(tmp_path):
    response = {"results": [{"index": 0, "authorize_deletion": True, "quote": "Delete", "reason": "explicit"}]}
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport(response))
    with pytest.raises(SemanticError):
        agent.authorize_many(["Delete account", "Erase profile"], batch_size=2)


def test_export_or_unsubscribe_cannot_become_deletion_from_model_guess(tmp_path):
    for text, quote in [("export my data", "export my data"), ("unsubscribe from marketing", "unsubscribe")]:
        agent = LocalSemanticAgent(cache_dir=tmp_path / str(len(text)), transport=transport({"authorize_deletion": True, "quote": quote, "reason": "incorrect model guess"}))
        assert agent.authorize(text) is False


def test_explicit_negation_vetoes_model_positive(tmp_path):
    text = "Please export my data. Do not delete my account."
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport({"authorize_deletion": True, "quote": "delete my account", "reason": "incorrect model guess"}))
    assert agent.authorize(text) is False


def test_grounded_incidental_quote_can_use_full_request_intent(tmp_path):
    text = "Delete my account. Please confirm when the process is complete."
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport({
        "authorize_deletion": True,
        "quote": "Please confirm when the process is complete.",
        "reason": "the request asks for deletion",
    }))
    assert agent.authorize(text) is True


def test_explicit_negation_vetoes_close_account(tmp_path):
    text = "Do not close my account."
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport({"authorize_deletion": True, "quote": "close my account", "reason": "incorrect model guess"}))
    assert agent.authorize(text) is False


def test_marketing_removal_is_not_account_deletion(tmp_path):
    text = "Please remove me from marketing lists only. I still want receipts for this account."
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport({"authorize_deletion": True, "quote": "remove me from marketing lists only", "reason": "incorrect model guess"}))
    assert agent.authorize(text) is False


def test_inflected_erasure_is_accepted_when_grounded(tmp_path):
    text = "I would like the account associated with this address to be erased."
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport({"authorize_deletion": True, "quote": "the account associated with this address to be erased", "reason": "explicit erasure"}))
    assert agent.authorize(text) is True


def test_reversible_mojibake_quote_can_be_grounded_in_original_text(tmp_path):
    text = "Solicito a exclusão permanente da conta associada a este e-mail."
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport({"authorize_deletion": True, "quote": "exclusÃ£o permanente da conta", "reason": "explicit Portuguese deletion"}))
    assert agent.authorize(text) is True


def test_unsupported_positive_intent_is_unresolved_not_non_applicable(tmp_path):
    text = "Please make my account forgotten."
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport({"authorize_deletion": True, "quote": text, "reason": "possible erasure"}))
    assert agent.authorize(text) is None


def test_unrecognized_positive_quote_cannot_become_not_applicable_in_batch(tmp_path):
    response = {"authorize_deletion": True, "quote": "forgotten", "reason": "possible erasure"}
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport(response))
    assert agent.authorize_many(["Please make my account forgotten."]) == [None]


def test_single_request_batch_uses_compact_authorization_schema(tmp_path):
    response = {"authorize_deletion": True, "quote": "Delete my account", "reason": "direct request"}
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport(response))
    assert agent.authorize_many(["Delete my account. Please confirm when complete."]) == [True]


def test_explicit_user_request_overrides_a_model_false_vote(tmp_path):
    text = "Please delete my account."
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport({"authorize_deletion": False, "quote": "delete my account", "reason": "uncertain"}))
    assert agent.authorize(text) is True


def test_first_person_erasure_search_result_and_japanese_requests(tmp_path):
    examples = [
        "I'm deleting my account.",
        "My account page is gone. Can you remove that search result too?",
        "このメールアドレスに関連するアカウントの完全な削除を依頼します。",
    ]
    for index, text in enumerate(examples):
        agent = LocalSemanticAgent(
            cache_dir=tmp_path / str(index),
            transport=transport({"authorize_deletion": False, "quote": text, "reason": "local lexical request"}),
        )
        assert agent.authorize(text) is True


def test_verification_only_request_is_not_a_new_deletion_request(tmp_path):
    text = "Please check the latest state and confirm the profile is gone."
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport({
        "authorize_deletion": True,
        "quote": text,
        "reason": "incorrectly treated as a deletion request",
    }))
    assert agent.authorize(text) is False


@pytest.mark.parametrize('verb', ['removing', 'deleting', 'erasing'])
def test_correction_without_deletion_vetoes_model_positive(tmp_path, verb):
    text = f'Can you correct my surname without {verb} any of my records?'
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport({
        'authorize_deletion': True, 'quote': text, 'reason': 'incorrect model guess',
    }))
    assert agent.authorize(text) is False


def test_audit_request_explicitly_requires_remaining_records_to_be_unidentifiable(tmp_path):
    text = 'Please check the latest state and confirm the profile is gone and remaining records cannot identify me.'
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport({
        'authorize_deletion': False, 'quote': text, 'reason': 'verification',
    }))
    assert agent.authorize(text) is True


@pytest.mark.parametrize('text', [
    'Please delete my account without removing legally retained order records.',
    'Please delete my account, but do not remove invoices retained for tax purposes.',
])
def test_preserving_required_records_does_not_negate_account_deletion(tmp_path, text):
    agent = LocalSemanticAgent(cache_dir=tmp_path, transport=transport({
        'authorize_deletion': True, 'quote': text, 'reason': 'delete subject to retention',
    }))
    assert agent.authorize(text) is True
