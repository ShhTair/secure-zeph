"""Layer 1 — Heuristic Rules.

65+ pattern-based rules across 13 categories.
Enriched from garak probes, PyRIT converters, PromptBench attacks, and InjecAgent data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class HeuristicRule:
    id: str
    pattern: str  # regex pattern (case-insensitive)
    label: str
    weight: float
    description: str
    compiled: re.Pattern | None = None

    def match(self, text: str) -> bool:
        if self.compiled:
            return bool(self.compiled.search(text))
        return bool(re.search(self.pattern, text, re.IGNORECASE | re.DOTALL))


def _r(id: str, pattern: str, label: str, weight: float, desc: str) -> HeuristicRule:
    """Helper to build a rule with pre-compiled regex."""
    return HeuristicRule(
        id=id,
        pattern=pattern,
        label=label,
        weight=weight,
        description=desc,
        compiled=re.compile(pattern, re.IGNORECASE | re.DOTALL),
    )


# ============================================================
# Category: OVERRIDE — attempts to replace system instructions
# ============================================================
OVERRIDE_RULES = [
    _r("HR-001", r"ignore\s+(all\s+)?(?:previous|prior|above|earlier)?\s*(?:instructions|rules|guidelines|directives|restrictions|constraints|policies)", "OVERRIDE", 0.8,
       "Ignore previous instructions"),
    _r("HR-002", r"forget\s+(everything|all|your\s+(instructions|rules))", "OVERRIDE", 0.8,
       "Forget everything"),
    _r("HR-003", r"new\s+system\s+prompt", "OVERRIDE", 0.9,
       "New system prompt injection"),
    _r("HR-027", r"override\s+safety|bypass\s+(filter|safety|restriction)", "OVERRIDE", 0.9,
       "Override safety / bypass filter"),
    _r("HR-031", r"nevermind[.,!]?\s+(?:instead|now|actually)", "OVERRIDE", 0.7,
       "Nevermind + redirect (garak promptinject)"),
    _r("HR-032", r"(?:STOP|HALT|IGNORE)[!.]{0,3}\s+(?:do\s+not|don't|never)\s+follow", "OVERRIDE", 0.7,
       "SCREAMING STOP pattern (garak)"),
    _r("HR-070", r"disregard\s+(?:all\s+)?(?:previous|prior|above|earlier|your)?\s*(?:instructions|rules|guidelines|directives|prompts?)", "OVERRIDE", 0.8,
       "Disregard instructions"),
    _r("HR-071", r"do\s+not\s+follow\s+(?:any\s+)?(?:previous|prior|original|your)\s+(?:instructions|rules|guidelines)", "OVERRIDE", 0.8,
       "Do not follow previous instructions"),
    _r("HR-072", r"your\s+(?:new|real|actual|true)\s+(?:task|instructions?|goal|purpose|objective)\s+(?:is|are)", "OVERRIDE", 0.8,
       "Your new task is..."),
]

# ============================================================
# Category: SECRET_EXTRACTION — probing for system internals
# ============================================================
SECRET_EXTRACTION_RULES = [
    _r("HR-007", r"reveal\s+(your\s+)?(system\s+prompt|instructions|config)", "SECRET_EXTRACTION", 0.8,
       "Reveal system prompt"),
    _r("HR-008", r"(show|print|display|output|give|tell)\s+(?:me\s+)?(your\s+)?(?:the\s+)?(api\s*key|config|secret|password|credentials?)", "SECRET_EXTRACTION", 0.9,
       "Show API key / config"),
    _r("HR-066", r"(?:print|output|display|repeat|show)\s+(?:me\s+)?(?:your\s+)?(?:the\s+)?(?:full\s+)?(?:system\s+prompt|system\s+instructions|initial\s+prompt|original\s+instructions)", "SECRET_EXTRACTION", 0.9,
       "Print/show system prompt"),
    _r("HR-067", r"(?:what|tell\s+me)\s+(?:are|were)\s+(?:your|my)\s+(?:initial\s+)?instructions", "SECRET_EXTRACTION", 0.8,
       "What are your instructions"),
    _r("HR-068", r"repeat\s+(?:the\s+)?(?:text|words?|instructions?)\s+above", "SECRET_EXTRACTION", 0.8,
       "Repeat the text above"),
    _r("HR-069", r"output\s+(?:your\s+)?(?:full\s+)?(?:config|configuration|settings)\s+(?:as|in)\s+(?:json|yaml|xml|text)", "SECRET_EXTRACTION", 0.8,
       "Output config as JSON/YAML"),
]

# ============================================================
# Category: ROLE_CONFUSION — persona manipulation
# ============================================================
ROLE_CONFUSION_RULES = [
    _r("HR-004", r"you\s+are\s+now\s+(?:a\s+)?(?!going|about|ready)", "ROLE_CONFUSION", 0.7,
       "You are now [role]"),
    _r("HR-005", r"(?:act|behave)\s+as\s+(?:if\s+you\s+(?:are|were))?|pretend\s+(?:you\s+are|to\s+be)", "ROLE_CONFUSION", 0.6,
       "Act as / pretend to be"),
    _r("HR-021", r"(?:from\s+now\s+on|henceforth)\s+you\s+(?:are|will|shall)", "ROLE_CONFUSION", 0.5,
       "Excessive role switching"),
    _r("HR-073", r"(?:switch|change|enter)\s+(?:to|into)\s+(?:\w+\s+)?mode", "ROLE_CONFUSION", 0.6,
       "Switch to X mode"),
    _r("HR-074", r"disable\s+(?:all\s+)?(?:content\s+)?(?:filters?|restrictions?|safeguards?|safety|limits?|guidelines?)", "ROLE_CONFUSION", 0.9,
       "Disable content filters"),
    _r("HR-075", r"(?:you\s+have|with)\s+(?:no|zero|unlimited)\s+(?:restrictions?|limits?|boundaries|rules|filters?)", "ROLE_CONFUSION", 0.8,
       "You have no restrictions"),
    _r("HR-076", r"(?:print|show|dump|output|display)\s+(?:all\s+)?(?:env|environment)\s+(?:var|variables?)", "ROLE_CONFUSION", 0.9,
       "Print environment variables"),
    _r("HR-101", r"(?:from now on|henceforth|going forward),?\s+you\s+are\s+(?:a|an|the|my)", "ROLE_CONFUSION", 0.8,
       "Role reassignment: from now on you are X"),
    _r("HR-102", r"you\s+are\s+(?:now\s+)?(?:a\s+)?(?:system\s+admin|root\s+user|superuser|hacker|attacker)", "ROLE_CONFUSION", 0.85,
       "Role claim: privileged identity"),
]
# Category: INSTRUCTION_SMUGGLING — jailbreak / DAN attempts
# ============================================================
INSTRUCTION_SMUGGLING_RULES = [
    _r("HR-006", r"developer\s+mode|maintenance\s+mode|debug\s+mode|admin\s+mode", "INSTRUCTION_SMUGGLING", 0.9,
       "Developer mode / DAN activation"),
    _r("HR-023", r"^(?:ADMIN|ROOT|SYSTEM|SUDO)\s*:", "INSTRUCTION_SMUGGLING", 0.8,
       "ADMIN: / ROOT: prefix"),
    _r("HR-026", r"```(?:system|instructions?|prompt)\b", "INSTRUCTION_SMUGGLING", 0.6,
       "Code-fence wrapped instructions"),
    _r("HR-030", r"\n\s*\[(?:SYSTEM|ADMIN|ROOT|INSTRUCTIONS?)\]", "INSTRUCTION_SMUGGLING", 0.8,
       "[SYSTEM] mid-text smuggling"),
    _r("HR-052", r"(?:special|master|admin)\s+override|skeleton\s*key", "INSTRUCTION_SMUGGLING", 0.8,
       "SkeletonKey pattern (PyRIT)"),
    _r("HR-095", r"<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<\|assistant\|>", "INSTRUCTION_SMUGGLING", 0.9,
       "ChatML token smuggling"),
    _r("HR-096", r"<<<\s*(?:INJECT|INJECTION|OVERRIDE|SYSTEM)\s*>>>", "INSTRUCTION_SMUGGLING", 0.9,
       "<<<INJECTION>>> markers"),
    _r("HR-097", r"__system__|__admin__|__override__|__inject__|__hidden__", "INSTRUCTION_SMUGGLING", 0.8,
       "Dunder system/admin fields in JSON/data"),
    _r("HR-098", r"(?:IMPORTANT|CRITICAL|URGENT)\s+SYSTEM\s+MESSAGE", "INSTRUCTION_SMUGGLING", 0.8,
       "IMPORTANT SYSTEM MESSAGE separator injection"),
    _r("HR-099", r"<script>|javascript:|on(?:load|error|click)\s*=", "INSTRUCTION_SMUGGLING", 0.8,
       "XSS-style script injection"),
]

# ============================================================
# Category: TOOL_ABUSE — malicious tool invocation
# ============================================================
TOOL_ABUSE_RULES = [
    _r("HR-009", r"(?:execute|run)\s+(?:this\s+)?(?:command|shell|bash|cmd|terminal)", "TOOL_ABUSE", 0.9,
       "Execute command / run shell"),
    _r("HR-010", r"send\s+(?:an?\s+)?email\s+to\s+(?!me\b|myself\b)", "TOOL_ABUSE", 0.7,
       "Send email to external"),
    _r("HR-011", r"(?:call|invoke|use)\s+(?:the\s+)?(?:tool|function|api)\s", "TOOL_ABUSE", 0.6,
       "Unexpected tool call instruction"),
    _r("HR-022", r"(?:tool_?call|function_?call|api_?call)\s*:", "TOOL_ABUSE", 0.9,
       "toolcall: manual injection"),
    _r("HR-082", r"\beval\s*\(", "TOOL_ABUSE", 0.9,
       "eval() call — code execution"),
    _r("HR-083", r"\bexec\s*\(|os\.system\s*\(|subprocess\.\w+\s*\(", "TOOL_ABUSE", 0.9,
       "exec/os.system/subprocess — code execution"),
    _r("HR-084", r"read\s+(?:the\s+)?(?:/etc/passwd|/etc/shadow|\.env|\.ssh|\.aws)", "TOOL_ABUSE", 0.9,
       "Read sensitive system files"),
    _r("HR-085", r"rm\s+-rf|del\s+/[fqs]|format\s+c:", "TOOL_ABUSE", 0.9,
       "Destructive system commands"),
    _r("HR-086", r"(?:send|email|forward)\s+(?:all\s+|every\s+|the\s+)?(?:contents?|files?|data|results?|everything)\s+to", "TOOL_ABUSE", 0.8,
       "Send all contents/data to external"),
    _r("HR-100", r"(?:read_file|read|open)\s*(?:\\u2192|→|->|=>|\s+then\s+)\s*(?:send|email|post|upload)", "TOOL_ABUSE", 0.85,
       "Tool chaining: read then exfiltrate"),
]

# ============================================================
# Category: INDIRECT_INJECTION — injection via context
# ============================================================
INDIRECT_INJECTION_RULES = [
    _r("HR-012", r"as\s+an?\s+(?:AI|language\s+model|assistant|chatbot)", "INDIRECT_INJECTION", 0.5,
       "As an AI assistant marker"),
    _r("HR-013", r"when\s+you\s+(?:see|read|encounter|process)\s+this", "INDIRECT_INJECTION", 0.6,
       "When you see this trigger"),
    _r("HR-014", r"instructions?\s+for\s+(?:the\s+)?(?:model|AI|assistant|LLM)", "INDIRECT_INJECTION", 0.7,
       "Instructions for the model"),
    _r("HR-015", r"(?:^|\n)\s*#\s*(?:IMPORTANT|SYSTEM|INSTRUCTIONS?|OVERRIDE)\b", "INDIRECT_INJECTION", 0.7,
       "# IMPORTANT headers in retrieved context"),
    _r("HR-019", r"do\s+not\s+tell\s+(?:the\s+)?user|hide\s+this\s+from", "INDIRECT_INJECTION", 0.7,
       "Do not tell the user"),
]

# ============================================================
# Category: EXFILTRATION — data leakage attempts
# ============================================================
EXFILTRATION_RULES = [
    _r("HR-016", r"https?://[^\s]+\?[^\s]*(?:base64|b64|data|q|query|secret|key|token|api_key|password)\s*=", "EXFILTRATION", 0.8,
       "URL with encoded/data exfil param"),
    _r("HR-017", r"data://|data:text/", "EXFILTRATION", 0.8,
       "data:// URI"),
    _r("HR-018", r"!\[.*?\]\(https?://[^\s]+\?[^\s]*=", "EXFILTRATION", 0.7,
       "Markdown image with query param"),
    _r("HR-024", r"(?:confidential|secret|private)\s+.*?(?:share|send|post|transmit)\s+(?:with|to)", "EXFILTRATION", 0.6,
       "Confidential + share with"),
    _r("HR-044", r"!\[.*?\]\(https?://[^\s]+\.(?:png|jpg|gif|webp)\?[a-z]+=", "EXFILTRATION", 0.9,
       "Markdown image exfiltration (garak web_injection)"),
    _r("HR-045", r"concatenate\s+(?:these\s+)?strings.*?replace\s+\[", "EXFILTRATION", 0.7,
       "Concat template exfiltration (garak web_injection)"),
    _r("HR-077", r"(?:send|post|upload|transmit|exfiltrate)\s+(?:the\s+)?(?:api\s*key|secrets?|passwords?|credentials?|data|conversation|history)\s+(?:to|via|using)", "EXFILTRATION", 0.9,
       "Send secrets to external"),
    _r("HR-078", r"(?:curl|wget|fetch|httpx?\.(?:get|post)|requests?\.(?:get|post))\s*\(\s*['\"]?https?://", "EXFILTRATION", 0.8,
       "HTTP request to external URL in code"),
    _r("HR-079", r"(?:webhook|pastebin|ngrok|requestbin|burpcollaborator)\.\w+", "EXFILTRATION", 0.8,
       "Known exfil service domains"),
    _r("HR-080", r"embed\s+(?:the\s+)?(?:system\s+prompt|api\s*key|secret|data)\s+(?:in|into)\s+(?:a\s+)?(?:url|link|image|markdown)", "EXFILTRATION", 0.9,
       "Embed secret in URL/image"),
    _r("HR-081", r"dns\s+(?:query|lookup|request)\s+.*?(?:leak|exfil|steal|send)", "EXFILTRATION", 0.8,
       "DNS exfiltration"),
]

# ============================================================
# Category: PERSONA_MARKERS — known jailbreak personas (📚 garak dan.py)
# ============================================================
PERSONA_MARKER_RULES = [
    _r("HR-033", r"\[DAN\]|DAN\s*:|DAN\s+Mode\s+enabled", "PERSONA_MARKER", 0.9,
       "[DAN] / DAN: / DAN Mode enabled"),
    _r("HR-034", r"ANTI-DAN\s*:|STAN\s*:|DUDE\s*:", "PERSONA_MARKER", 0.9,
       "ANTI-DAN / STAN / DUDE persona"),
    _r("HR-035", r"\[.?JAILBREAK.?\]|successfully\s+jailbr", "PERSONA_MARKER", 0.9,
       "[🔓JAILBREAK] marker"),
    _r("HR-036", r"\(.?Developer\s+Mode\s+Output.?\)", "PERSONA_MARKER", 0.9,
       "(🔓Developer Mode Output)"),
    _r("HR-087", r"(?:do\s+anything\s+now|can\s+do\s+anything|no\s+(?:rules?|limits?|restrictions?|boundaries))", "PERSONA_MARKER", 0.8,
       "DAN Do Anything Now pattern"),
    _r("HR-088", r"(?:jailbr(?:oken|eak)\s+mode|unlocked\s+mode|unfiltered\s+mode|unrestricted\s+mode)", "PERSONA_MARKER", 0.9,
       "Jailbroken/unlocked/unfiltered mode"),
    _r("HR-089", r"(?:all\s+)?safety\s+(?:measures?|protocols?|guidelines?|guardrails?)\s+(?:are\s+)?(?:off|disabled|removed|turned\s+off)", "PERSONA_MARKER", 0.9,
       "Safety measures off/disabled"),
    _r("HR-090", r"(?:strive\s+to\s+avoid\s+norms|generate\s+any\s+(?:kind\s+of\s+)?content\s+without)", "PERSONA_MARKER", 0.8,
       "STAN Strive To Avoid Norms"),
]

# ============================================================
# Category: ENCODING_EVASION — encoding-based bypass (📚 garak encoding.py)
# ============================================================
ENCODING_EVASION_RULES = [
    _r("HR-028", r"(?:decode|interpret)\s+(?:this\s+)?base64|base64\s*:\s*[A-Za-z0-9+/]{10,}", "ENCODING_EVASION", 0.8,
       "Base64 encoded instructions"),
    _r("HR-038", r"(?:decode|convert|translate)\s+(?:the\s+following\s+)?\w+\s+(?:encoded|string|text)", "ENCODING_EVASION", 0.8,
       "Decode the following [encoding] (garak)"),
    _r("HR-039", r"rot13|braille|morse\s+code|atbash", "ENCODING_EVASION", 0.7,
       "ROT13/braille/morse encoding wrapper"),
    _r("HR-051", r"(?:[a-z]+[0-9]+[a-z]+){3,}|(?:3[xX](?:ecute)|1[gG]n[o0]r[3e])", "ENCODING_EVASION", 0.5,
       "Leetspeak substitution pattern (PyRIT)"),
]

# ============================================================
# Category: EXPLOITATION — code/SQL/template injection (📚 garak exploitation.py)
# ============================================================
EXPLOITATION_RULES = [
    _r("HR-040", r"\{\{.*?(?:import|os\.|subprocess|eval|exec|system)\s*\(.*?\}\}", "EXPLOITATION", 0.9,
       "Jinja template injection with code execution"),
    _r("HR-041", r"\b(?:SELECT|DROP|UNION|INSERT|DELETE|EXEC|TRUNCATE|ALTER)\s+(?:TABLE|FROM|INTO|ALL)\b", "EXPLOITATION", 0.8,
       "SQL injection keywords"),
    _r("HR-042", r"(?:--\s*\w|IF\(1=1|/\*.*?\*/|';\s*\w)", "EXPLOITATION", 0.7,
       "SQL injection indicators"),
    _r("HR-043", r"(?:I\s+am\s+an?\s+administrator|admin\s+testing)\s+.*?echo", "EXPLOITATION", 0.8,
       "Echo command admin pattern (garak)"),
]

# ============================================================
# Category: LATENT_INJECTION — hidden instructions in tool output (📚 garak latentinjection + InjecAgent)
# ============================================================
LATENT_INJECTION_RULES = [
    _r("HR-037", r"(?:---|\*\*\*|===)\s*\n\s*(?:IMPORTANT|INSTRUCTIONS?|NOTE|OVERRIDE)\s*:", "LATENT_INJECTION", 0.8,
       "Separator + IMPORTANT/INSTRUCTIONS in tool output (garak)"),
    _r("HR-046", r"\[system\]\s*\(#(?:context|assistant|instructions)\)", "LATENT_INJECTION", 0.9,
       "[system](#context/assistant) injection (garak web_injection)"),
    _r("HR-063", r"(?:please|kindly)\s+(?:grant|send|transfer|execute|delete|remove)\s+.*?(?:access|money|funds|email)", "LATENT_INJECTION", 0.8,
       "Tool response with action verbs + sensitive targets (InjecAgent)"),
    _r("HR-064", r"grant\s+(?:permanent\s+)?(?:guest\s+)?access|transfer\s+funds|send\s+money", "LATENT_INJECTION", 0.9,
       "Grant access / transfer funds (InjecAgent attack patterns)"),
    _r("HR-065", r"(?:on\s+behalf\s+of|acting\s+as)\s+(?:the\s+)?user", "LATENT_INJECTION", 0.7,
       "Acting on behalf of user (InjecAgent)"),
    _r("HR-091", r"\[HIDDEN\]|\[INVISIBLE\]|<invisible>|<hidden>|<!--\s*inject", "LATENT_INJECTION", 0.9,
       "Hidden/invisible HTML comment injection tags"),
    _r("HR-092", r"(?:on\s+(?:the\s+)?next|when\s+(?:the\s+)?next)\s+(?:question|request|message|query|prompt)", "LATENT_INJECTION", 0.7,
       "Delayed trigger: on the next question/request"),
    _r("HR-093", r"append\s+(?:this\s+)?(?:to\s+)?(?:your|every|all|each)\s+(?:response|reply|output|answer)", "LATENT_INJECTION", 0.7,
       "Append to every response"),
    _r("HR-094", r"(?:if|when)\s+anyone\s+asks?\s+about", "LATENT_INJECTION", 0.75,
       "If anyone asks about — conditional trigger"),
    _r("HR-103", r"\bINJECTION\s*:|\bINJECT\s*:|PAYLOAD\s*:", "LATENT_INJECTION", 0.9,
       "Explicit INJECTION/PAYLOAD marker in context"),
    _r("HR-104", r"bypass\s+(?:all\s+)?(?:checks?|filters?|security|safety|restrictions?)\s+and\s+(?:reveal|show|expose|output)", "LATENT_INJECTION", 0.85,
       "Bypass checks and reveal — compound attack"),
    _r("HR-105", r"append\s+(?:this|the)\s+password", "LATENT_INJECTION", 0.85,
       "Append password to response — data exfil via output"),
]

# ============================================================
# Category: SMUGGLING — obfuscation techniques (📚 garak smuggling.py + PyRIT)
# ============================================================
SMUGGLING_RULES = [
    _r("HR-047", r"(?:hypothetical|fictional|imagine)\s+(?:scenario|situation|response)\s+where", "SMUGGLING", 0.7,
       "HypotheticalResponse framing (garak)"),
    _r("HR-048", r"predict_mask|fill_in_the_blank|complete_the_(?:sentence|text)", "SMUGGLING", 0.6,
       "FunctionMasking obfuscation (garak)"),
    _r("HR-049", r"[\u0430\u0435\u043e\u0440\u0441\u0443\u0445]{2,}", "SMUGGLING", 0.6,
       "Cyrillic homoglyph clusters"),
    _r("HR-050", r"[\u200b\ufeff\u200c\u200d]", "SMUGGLING", 0.7,
       "Zero-width character insertion"),
]

# ============================================================
# Category: MULTI_TURN — gradual escalation (📚 PyRIT)
# ============================================================
MULTI_TURN_RULES = [
    _r("HR-053", r"(?:just\s+a\s+)?few\s+(?:more\s+)?examples?\s+of\s+(?:harmful|dangerous|illegal)", "MULTI_TURN", 0.7,
       "ManyShot jailbreak pattern (PyRIT)"),
    _r("HR-054", r"instead\s+of\s+not\s+doing|rather\s+than\s+refusing", "MULTI_TURN", 0.6,
       "FlipAttack inversion (PyRIT)"),
    _r("HR-055", r"(?:let's|let\s+us)\s+(?:start|begin)\s+(?:with|by)\s+(?:something\s+)?(?:simple|harmless|innocent)", "MULTI_TURN", 0.5,
       "Crescendo start (PyRIT)"),
    _r("HR-056", r"(?:don't|do\s+not)\s+refuse|just\s+answer|stop\s+being\s+(?:safe|careful|cautious)", "MULTI_TURN", 0.6,
       "Negation trap (PyRIT)"),
    _r("HR-057", r"for\s+(?:educational|research|academic)\s+purposes?\s+only|hypothetically\s+speaking", "MULTI_TURN", 0.5,
       "Persuasion / educational framing (PyRIT)"),
]

# ============================================================
# Category: NOISE — adversarial noise/perturbation (📚 PromptBench)
# ============================================================
NOISE_RULES = [
    _r("HR-059", r"[A-Za-z0-9]{10,}\s+[A-Za-z0-9]{10,}\s+[A-Za-z0-9]{10,}", "NOISE", 0.4,
       "Random alphanumeric append (PromptBench CheckList)"),
    _r("HR-060", r"and\s+true\s+is\s+true|and\s+false\s+is\s+not\s+true", "NOISE", 0.4,
       "Tautology append (PromptBench StressTest)"),
]

# ============================================================
# Misc remaining
# ============================================================
MISC_RULES = [
    _r("HR-020", r"this\s+is\s+(?:just\s+)?a\s+test|testing\s+(?:your|the)\s+(?:limits|boundaries)", "SOCIAL_ENGINEERING", 0.4,
       "This is a test — social engineering"),
    _r("HR-025", r"(?:first|initial)\s+instructions?\s+(?:said|were|stated).*?(?:but|however|instead)", "CONFLICTING", 0.5,
       "Conflicting instructions"),
    _r("HR-029", r"repeat\s+after\s+me|say\s+(?:exactly|the\s+following)", "SOCIAL_ENGINEERING", 0.5,
       "Repeat after me + suspicious"),
    _r("HR-058", r"(?:obfuscated?|encoded?|encrypted?)\s+(?:code|script|payload|program)", "EXPLOITATION", 0.6,
       "Code obfuscation (PyRIT CodeChameleon)"),
    _r("HR-061", r"(?:traduire|traducir|übersetzen|翻译|翻訳)\s", "ENCODING_EVASION", 0.5,
       "Non-English translate commands in English context (PromptBench)"),
    _r("HR-062", r"[\u0430-\u044f]+[a-z]+[\u0430-\u044f]+|[a-z]+[\u0430-\u044f]+[a-z]+", "SMUGGLING", 0.6,
       "Mixed Cyrillic-Latin character patterns"),
]

# ============================================================
# ALL RULES combined
# ============================================================
ALL_RULES: list[HeuristicRule] = (
    OVERRIDE_RULES
    + SECRET_EXTRACTION_RULES
    + ROLE_CONFUSION_RULES
    + INSTRUCTION_SMUGGLING_RULES
    + TOOL_ABUSE_RULES
    + INDIRECT_INJECTION_RULES
    + EXFILTRATION_RULES
    + PERSONA_MARKER_RULES
    + ENCODING_EVASION_RULES
    + EXPLOITATION_RULES
    + LATENT_INJECTION_RULES
    + SMUGGLING_RULES
    + MULTI_TURN_RULES
    + NOISE_RULES
    + MISC_RULES
)
