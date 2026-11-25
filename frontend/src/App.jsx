import { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Plus,
  RefreshCw,
  Send,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import { deleteSession, fetchHealth, GatewayError, sendChat } from './api';
import './App.css';

const PRESET_PROMPTS = [
  {
    title: 'General Question (No PII)',
    text: 'Explain how TLS encryption works in 2 sentences.',
    danger: false,
  },
  {
    title: 'PII Pseudonymization',
    text: 'My name is Rahul Sharma, email rahul@test.com, phone +91 98765 43210.',
    danger: false,
  },
  {
    title: 'Indian PAN + Location',
    text: 'Check tax status for PAN AADPE7873B in Bengaluru.',
    danger: false,
  },
  {
    title: 'Policy Block (403 Credit Card)',
    text: 'Please process my credit card 4111-1111-1111-1111.',
    danger: true,
  },
];

export default function App() {
  const [sessions, setSessions] = useState(['session-1']);
  const [activeSession, setActiveSession] = useState('session-1');
  const [messagesBySession, setMessagesBySession] = useState({ 'session-1': [] });
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);
  const [wiping, setWiping] = useState(false);
  const [health, setHealth] = useState(null);
  const [healthError, setHealthError] = useState(false);
  const [toast, setToast] = useState('');
  const endRef = useRef(null);

  const loadHealth = async () => {
    try {
      const data = await fetchHealth();
      setHealth(data);
      setHealthError(false);
    } catch {
      setHealth(null);
      setHealthError(true);
    }
  };

  useEffect(() => {
    loadHealth();
    const timer = setInterval(loadHealth, 15000);
    return () => clearInterval(timer);
  }, []);

  const activeMessages = messagesBySession[activeSession] || [];

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [activeMessages.length, sending]);

  const appendMessage = (sessionId, msg) => {
    setMessagesBySession((prev) => ({
      ...prev,
      [sessionId]: [...(prev[sessionId] || []), msg],
    }));
  };

  const handleCreateSession = () => {
    const nextId = `session-${sessions.length + 1}`;
    setSessions((prev) => [...prev, nextId]);
    setMessagesBySession((prev) => ({ ...prev, [nextId]: [] }));
    setActiveSession(nextId);
  };

  const handleWipeSession = async () => {
    setWiping(true);
    setToast('');
    try {
      const res = await deleteSession(activeSession);
      setMessagesBySession((prev) => ({ ...prev, [activeSession]: [] }));
      setToast(
        `Cleared ${activeSession}: ${res.mappings_deleted} vault mapping(s) deleted.`
      );
    } catch (err) {
      setToast(err.message || 'Could not clear session.');
    } finally {
      setWiping(false);
    }
  };

  const handleSend = async (e) => {
    e?.preventDefault();
    const trimmed = input.trim();
    if (!trimmed || sending) return;

    const currentSession = activeSession;
    setInput('');
    setToast('');
    appendMessage(currentSession, {
      id: crypto.randomUUID(),
      role: 'user',
      text: trimmed,
    });

    setSending(true);
    try {
      const data = await sendChat(currentSession, trimmed);
      appendMessage(currentSession, {
        id: crypto.randomUUID(),
        role: 'assistant',
        text: data.reply,
        piiDetected: data.pii_detected,
        entitiesFound: data.entities_found,
        processingTimeMs: data.processing_time_ms,
      });
    } catch (err) {
      if (err instanceof GatewayError && err.code === 'POLICY_BLOCKED') {
        appendMessage(currentSession, {
          id: crypto.randomUUID(),
          role: 'blocked',
          text: err.message,
        });
      } else {
        appendMessage(currentSession, {
          id: crypto.randomUUID(),
          role: 'error',
          text: err.message || 'Failed to reach LLMGuard gateway.',
        });
      }
    } finally {
      setSending(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const healthStatus = healthError
    ? 'offline'
    : health?.status === 'ok'
      ? 'ok'
      : 'degraded';

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={20} />
          </div>
          <div>
            <h1>LLMGuard</h1>
            <p>Privacy-Aware LLM Gateway</p>
          </div>
        </div>

        <div>
          <div className="section-header">
            <span>Sessions</span>
            <button className="icon-btn" onClick={handleCreateSession} type="button">
              <Plus size={14} /> New
            </button>
          </div>

          <div className="session-list">
            {sessions.map((id) => (
              <button
                key={id}
                type="button"
                className={`session-item ${id === activeSession ? 'active' : ''}`}
                onClick={() => setActiveSession(id)}
              >
                <span>{id}</span>
                <span style={{ fontSize: '0.72rem', opacity: 0.7 }}>
                  {(messagesBySession[id] || []).length}
                </span>
              </button>
            ))}
          </div>

          <button
            className="wipe-btn"
            type="button"
            onClick={handleWipeSession}
            disabled={wiping}
          >
            <Trash2 size={14} />
            {wiping ? 'Wiping Vault...' : 'Wipe Session Vault'}
          </button>
        </div>

        <div>
          <div className="section-header">
            <span>Quick Test Prompts</span>
          </div>
          <div className="presets">
            {PRESET_PROMPTS.map((preset) => (
              <button
                key={preset.title}
                type="button"
                className="preset-btn"
                onClick={() => setInput(preset.text)}
              >
                <span className={`preset-title ${preset.danger ? 'danger' : ''}`}>
                  {preset.title}
                </span>
                <span className="preset-text">{preset.text}</span>
              </button>
            ))}
          </div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div className="session-pill">
            Active session: <strong>{activeSession}</strong>
          </div>

          <div className="health-group">
            <span className={`health-pill ${healthStatus}`}>
              {healthStatus === 'ok' ? (
                <CheckCircle2 size={14} />
              ) : (
                <AlertTriangle size={14} />
              )}
              {healthError
                ? 'Gateway Offline'
                : `Gateway: ${health?.status || '...'} | ${health?.ollama_model || ''}`}
            </span>
            <button
              className="icon-btn"
              type="button"
              onClick={loadHealth}
              title="Refresh gateway health"
            >
              <RefreshCw size={14} />
            </button>
          </div>
        </header>

        {toast && (
          <div className="toast">
            <span>{toast}</span>
            <button
              className="icon-btn"
              type="button"
              onClick={() => setToast('')}
            >
              Dismiss
            </button>
          </div>
        )}

        <div className="messages">
          {activeMessages.length === 0 && (
            <div className="empty-state">
              <ShieldCheck size={42} color="#38bdf8" />
              <h2>Protected LLM Chat</h2>
              <p>
                Prompts are scanned for PII, evaluated against your privacy policy,
                and sanitized before leaving the gateway. Pick a quick test prompt
                on the left or type a message below.
              </p>
            </div>
          )}

          {activeMessages.map((m) => (
            <div key={m.id} className={`msg-row ${m.role}`}>
              <div className="bubble">{m.text}</div>

              {m.role === 'assistant' && (
                <div className="meta-row">
                  <span
                    className={`meta-badge ${m.piiDetected ? 'protected' : ''}`}
                  >
                    <ShieldCheck size={12} />
                    {m.piiDetected
                      ? `PII Protected (${m.entitiesFound} entities)`
                      : 'No PII Detected'}
                  </span>
                  <span className="meta-badge">
                    <Clock size={12} />
                    {m.processingTimeMs} ms
                  </span>
                </div>
              )}

              {m.role === 'blocked' && (
                <div className="meta-row">
                  <span className="meta-badge blocked">
                    <ShieldAlert size={12} />
                    Blocked by Privacy Policy (403)
                  </span>
                </div>
              )}
            </div>
          ))}

          {sending && (
            <div className="msg-row assistant">
              <div className="bubble" style={{ color: 'var(--muted)' }}>
                Scanning PII &amp; waiting for response...
              </div>
            </div>
          )}

          <div ref={endRef} />
        </div>

        <form className="composer" onSubmit={handleSend}>
          <textarea
            rows={1}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Send a message through LLMGuard..."
          />
          <button
            className="send-btn"
            type="submit"
            disabled={sending || !input.trim()}
          >
            <Send size={15} />
            Send
          </button>
        </form>
      </main>
    </div>
  );
}
