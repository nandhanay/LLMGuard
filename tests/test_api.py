"""
tests/test_api.py — Integration Tests for FastAPI Gateway
============================================================

Tests the /chat, /health, and /session endpoints using FastAPI's
TestClient with a mocked Ollama HTTP response.

Run with: pytest tests/test_api.py -v
"""

from unittest.mock import AsyncMock, patch, MagicMock

import pytest
import httpx
from fastapi.testclient import TestClient

from gateway.main import app, _session_histories
from gateway.detector import PIIDetector
from gateway.vault import PIIVault
from gateway.transformer import TextTransformer
from gateway.inspector import ResponseInspector
from gateway.audit import AuditLogger
from gateway.policy import PolicyEngine


# ── Fixtures ──────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def setup_app_state():
    """Configure app state with in-memory vault and test client."""
    detector = PIIDetector(score_threshold=0.4)
    vault = PIIVault(":memory:")
    policy = PolicyEngine("policies/default.yaml")
    transformer = TextTransformer(detector, vault, policy=policy)
    inspector = ResponseInspector(detector, vault)
    audit_logger = AuditLogger(":memory:")

    app.state.policy = policy
    app.state.detector = detector
    app.state.vault = vault
    app.state.transformer = transformer
    app.state.inspector = inspector
    app.state.audit_logger = audit_logger
    app.state.http_client = httpx.AsyncClient(base_url="http://mocked-ollama")

    _session_histories.clear()

    yield

    vault.close()


@pytest.fixture
def client():
    return TestClient(app)


def mock_ollama_response(reply_text: str):
    """Helper to mock Ollama chat API response."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "message": {"role": "assistant", "content": reply_text}
    }
    mock_resp.raise_for_status = MagicMock()
    return mock_resp


# ── Health Endpoint ──────────────────────────────────────────

class TestHealthEndpoint:
    """Test the /health endpoint."""

    def test_health_check(self, client: TestClient):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "vault_initialized" in data
        assert data["vault_initialized"] is True
        assert data["detector_ready"] is True


# ── Chat Endpoint ────────────────────────────────────────────

class TestChatEndpoint:
    """Test the POST /chat endpoint."""

    @patch("httpx.AsyncClient.post")
    def test_chat_without_pii(self, mock_post, client: TestClient):
        """Message without PII should pass through to Ollama."""
        mock_post.return_value = mock_ollama_response("Hello! How can I help?")

        response = client.post(
            "/chat",
            json={"session_id": "s1", "message": "How does photosynthesis work?"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["session_id"] == "s1"
        assert data["reply"] == "Hello! How can I help?"
        assert data["pii_detected"] is False
        assert data["entities_found"] == 0
        assert data["processing_time_ms"] > 0

    @patch("httpx.AsyncClient.post")
    def test_chat_sanitizes_pii_before_ollama(self, mock_post, client: TestClient):
        """Ollama should receive ONLY sanitized text, never raw PII."""
        mock_post.return_value = mock_ollama_response("Hello PERSON_1!")

        response = client.post(
            "/chat",
            json={
                "session_id": "s1",
                "message": "My name is Rahul Sharma and my email is rahul@test.com",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["pii_detected"] is True
        assert data["entities_found"] >= 1

        # Check what was sent to Ollama
        call_kwargs = mock_post.call_args
        sent_payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        messages = sent_payload["messages"]
        sent_text = messages[-1]["content"]

        # Crucial check: raw PII must NOT be in the payload to Ollama
        assert "Rahul Sharma" not in sent_text
        assert "rahul@test.com" not in sent_text
        # Instead, placeholders should be present
        assert "PERSON_" in sent_text or "EMAIL_ADDRESS_" in sent_text

    @patch("httpx.AsyncClient.post")
    def test_chat_restores_placeholders_in_reply(self, mock_post, client: TestClient):
        """Placeholders in Ollama's reply should be restored to original values."""
        # Ollama responds using the placeholder it received
        mock_post.return_value = mock_ollama_response(
            "Nice to meet you, PERSON_1! How are you?"
        )

        response = client.post(
            "/chat",
            json={"session_id": "s1", "message": "My name is Rahul Sharma."},
        )
        assert response.status_code == 200
        data = response.json()
        # The reply to the USER should have the original name restored
        assert "Rahul Sharma" in data["reply"]
        assert "PERSON_1" not in data["reply"]

    @patch("httpx.AsyncClient.post")
    def test_chat_multi_turn_history(self, mock_post, client: TestClient):
        """Sanitized conversation history should accumulate across turns."""
        mock_post.return_value = mock_ollama_response("Noted!")

        # Turn 1
        client.post(
            "/chat",
            json={"session_id": "s1", "message": "I'm Rahul Sharma."},
        )
        # Turn 2
        client.post(
            "/chat",
            json={"session_id": "s1", "message": "What is my name?"},
        )

        # Check the history sent on Turn 2
        call_kwargs = mock_post.call_args
        sent_payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        messages = sent_payload["messages"]

        # Should have 3 messages: user1 (sanitized), assistant1, user2
        assert len(messages) == 3
        # No message in history should contain "Rahul Sharma"
        for msg in messages:
            assert "Rahul Sharma" not in msg["content"]


# ── Error Handling ───────────────────────────────────────────

class TestErrorHandling:
    """Test error conditions."""

    def test_missing_session_id(self, client: TestClient):
        response = client.post("/chat", json={"message": "hello"})
        assert response.status_code == 422  # Validation error

    def test_missing_message(self, client: TestClient):
        response = client.post("/chat", json={"session_id": "s1"})
        assert response.status_code == 422

    def test_empty_message(self, client: TestClient):
        response = client.post("/chat", json={"session_id": "s1", "message": ""})
        assert response.status_code == 422

    @patch("httpx.AsyncClient.post", side_effect=httpx.ConnectError("Connection refused"))
    def test_ollama_down_returns_503(self, mock_post, client: TestClient):
        """When Ollama is unreachable, return 503 with clear message."""
        response = client.post(
            "/chat",
            json={"session_id": "s1", "message": "Hello"},
        )
        assert response.status_code == 503
        assert "Cannot connect to Ollama" in response.json()["detail"]

    def test_chat_blocked_on_credit_card(self, client: TestClient):
        """Requests containing payment cards must be blocked by policy with HTTP 403."""
        response = client.post(
            "/chat",
            json={"session_id": "s_block", "message": "Please charge card 4111-1111-1111-1111 now."},
        )
        assert response.status_code == 403
        assert "Request blocked by privacy policy" in response.json()["detail"]


# ── Session Deletion ─────────────────────────────────────────

class TestSessionDeletion:
    """Test the DELETE /session/{session_id} endpoint."""

    @patch("httpx.AsyncClient.post")
    def test_delete_clears_vault_and_history(self, mock_post, client: TestClient):
        mock_post.return_value = mock_ollama_response("OK")

        # Create some data
        client.post(
            "/chat",
            json={"session_id": "s_del", "message": "I'm Rahul Sharma."},
        )

        # Verify history exists
        assert "s_del" in _session_histories

        # Delete session
        response = client.delete("/session/s_del")
        assert response.status_code == 200
        data = response.json()
        assert data["session_id"] == "s_del"
        assert data["mappings_deleted"] >= 1
        assert data["history_cleared"] is True

        # Verify history is gone
        assert "s_del" not in _session_histories

