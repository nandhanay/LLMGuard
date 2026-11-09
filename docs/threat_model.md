# Threat Model — LLMGuard Privacy Gateway

## Overview

This document describes the threat model for the LLMGuard Privacy Gateway,
identifying assets, threat actors, attack surfaces, and mitigations.

> **Status:** Draft — to be expanded as the system evolves.

## Assets

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| User prompts | Raw text containing PII | High |
| PII mappings | Original ↔ placeholder associations | Critical |
| LLM responses | May contain leaked or fabricated PII | Medium |
| Audit logs | Security events (no raw PII) | Low |
| Session data | Conversation history (sanitized only) | Medium |

## Threat Actors

1. **Malicious user** — crafts prompts to extract other users' PII or bypass sanitization.
2. **Compromised LLM** — model that hallucinates or leaks memorized training data.
3. **Insider with log access** — attempts to reconstruct PII from audit logs.
4. **Cross-session attacker** — tries to access another session's vault mappings.

## Key Threats

### T1: Prompt injection to bypass sanitization
- **Vector:** User crafts input that evades Presidio detection.
- **Mitigation:** Multi-layer detection, output inspection, adversarial testing.

### T2: Cross-session data leakage
- **Vector:** Session A accesses Session B's PII mappings.
- **Mitigation:** Session-isolated vault with strict access control.

### T3: PII in LLM response
- **Vector:** LLM generates new PII not present in the original prompt.
- **Mitigation:** Response inspection with Presidio before returning to user.

### T4: Mapping reconstruction from logs
- **Vector:** Audit logs contain enough metadata to reconstruct PII.
- **Mitigation:** Logs contain only entity types, counts, and timing — never raw values.

### T5: Placeholder manipulation
- **Vector:** User includes fake placeholders (e.g., "PERSON_1") in their prompt.
- **Mitigation:** Validate placeholder format and cross-reference with vault.

## To Be Expanded

- Cumulative inference attacks across multiple turns
- Alias-based re-identification risks
- Model memorization of placeholder patterns
- Policy bypass through encoding tricks (Base64, Unicode, etc.)

