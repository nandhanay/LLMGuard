const API_BASE = import.meta.env.VITE_API_URL || '/api';

export class GatewayError extends Error {
  constructor(message, status, code = 'ERROR') {
    super(message);
    this.name = 'GatewayError';
    this.status = status;
    this.code = code;
  }
}

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) {
    throw new GatewayError('Gateway health check failed', res.status, 'HEALTH_ERROR');
  }
  return res.json();
}

export async function sendChat(sessionId, message) {
  const res = await fetch(`${API_BASE}/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: sessionId, message }),
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const detail = data.detail || `Request failed with status ${res.status}`;
    const code =
      res.status === 403
        ? 'POLICY_BLOCKED'
        : res.status === 503 || res.status === 504 || res.status === 502
          ? 'OLLAMA_UNAVAILABLE'
          : 'API_ERROR';
    throw new GatewayError(detail, res.status, code);
  }

  return data;
}

export async function deleteSession(sessionId) {
  const res = await fetch(`${API_BASE}/session/${encodeURIComponent(sessionId)}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    throw new GatewayError('Failed to clear session', res.status, 'DELETE_ERROR');
  }
  return res.json();
}
