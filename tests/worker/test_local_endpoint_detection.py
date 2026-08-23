# SPDX-FileCopyrightText: 2026 Virantis
# SPDX-License-Identifier: LicenseRef-Vooda-Community-1.0
"""Local-model throttling must follow the endpoint, not the label.

Triage serializes to a single request for local inference servers, which
are CPU-bound and cannot do better. That clamp is right for a model on
localhost and badly wrong for a cloud endpoint: it discards the
operator's configured concurrency and rate limit.

The provider label is a dropdown value, and a cloud model registered
under a local-server label would silently serialize — both kinds speak
the same OpenAI-compatible protocol over the same client, so nothing
errors; the scan just runs far below its configured throughput.

The endpoint is the fact. A loopback or private-network URL cannot be a
shared cloud endpoint; a public host is not local inference.
"""
import inspect

import pytest

from apps.worker.tasks import _is_local_endpoint


@pytest.mark.parametrize("url", [
    "http://localhost:11434",
    "http://127.0.0.1:11434",
    "http://127.0.0.1:1234/v1",
    "http://[::1]:8080/v1",
    "http://192.168.1.50:11434",
    "http://10.0.0.7:8000/v1",
    "http://172.16.4.2:5000",
    "http://ollama:11434",             # docker-compose service name
    "http://inference/v1",             # bare container hostname
    "http://gpu-box.local:8080",
    "http://llm.internal:8000/v1",
    "http://169.254.10.9:11434",       # link-local
])
def test_local_endpoints_are_serialized(url):
    assert _is_local_endpoint(url) is True, f"{url} should be treated as local"


@pytest.mark.parametrize("url", [
    "https://openrouter.ai/api/v1",
    "https://api.openai.com/v1",
    "https://api.anthropic.com",
    "https://generativelanguage.googleapis.com/v1beta",
    "https://my-llm.example.com/v1",
    "https://eu.api.mistral.ai/v1",
])
def test_cloud_endpoints_keep_configured_concurrency(url):
    assert _is_local_endpoint(url) is False, f"{url} must not be throttled as local"


def test_a_public_host_on_an_ollama_port_is_still_remote():
    """Port alone cannot imply locality — the host is what matters."""
    assert _is_local_endpoint("https://openrouter.ai:11434/api/v1") is False


def test_ollama_in_a_public_domain_name_is_not_local():
    """Substring matching on the URL is not host classification."""
    assert _is_local_endpoint("https://ollama-proxy.example.com/v1") is False


@pytest.mark.parametrize("url", ["", "   ", None])
def test_missing_endpoint_is_not_assumed_local(url):
    assert _is_local_endpoint(url) is False


def test_endpoint_wins_over_the_provider_label():
    """The specific failure: an OpenRouter model registered as 'ollama'."""
    src = inspect.getsource(_triage_source_fn())
    assert "_is_local_endpoint(_base)" in src, (
        "locality must be derived from the endpoint"
    )
    # The label may only decide when there is no endpoint to judge.
    before, _, after = src.partition("_is_local_endpoint(_base)")
    assert "_provider_label in _local_provider_names" in after, (
        "the label should remain the fallback for an unset endpoint"
    )
    assert "_provider_label in _local_provider_names" not in before.split("_base = ")[-1], (
        "the label must not decide locality when an endpoint is present"
    )


def test_label_endpoint_disagreement_is_logged():
    """Silent throttling is what made this invisible."""
    assert "local_model_detection_from_endpoint" in inspect.getsource(_triage_source_fn())


def _triage_source_fn():
    from apps.worker import tasks
    return tasks._run_ai_triage
