"""Layer 0 — Input Normalization.

Canonicalizes text for consistent downstream detection.
Strips obfuscation techniques discovered from garak, PyRIT, and PromptBench research.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field


@dataclass
class NormalizationFlags:
    unicode_normalized: bool = False
    zero_width_stripped: bool = False
    base64_detected: bool = False
    url_encoded_detected: bool = False
    whitespace_collapsed: bool = False
    homoglyph_detected: bool = False
    encoding_wrapper_detected: bool = False
    markdown_system_injection_detected: bool = False
    segments_decoded: list[str] = field(default_factory=list)


# Zero-width characters to strip (📚 garak smuggling.py + PyRIT)
_ZERO_WIDTH_CHARS = frozenset([
    "\u200b",  # Zero Width Space
    "\u200c",  # Zero Width Non-Joiner
    "\u200d",  # Zero Width Joiner
    "\ufeff",  # Zero Width No-Break Space / BOM
    "\u2060",  # Word Joiner
    "\u200e",  # Left-to-Right Mark
    "\u200f",  # Right-to-Left Mark
    "\u00ad",  # Soft Hyphen
])

_ZERO_WIDTH_RE = re.compile("[" + "".join(_ZERO_WIDTH_CHARS) + "]+")

# Base64 detection: looks for standalone blocks of valid base64 (min 20 chars)
_BASE64_RE = re.compile(r"(?<!\w)[A-Za-z0-9+/]{20,}={0,2}(?!\w)")

# URL-encoded sequences (%XX)
_URL_ENCODED_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){3,}")

# Markdown system prompt injection patterns (📚 garak web_injection.py MarkdownImageExfil)
_MD_SYSTEM_RE = re.compile(
    r"\[system\]\s*\(#(?:context|assistant|instructions)\)", re.IGNORECASE
)

# Encoding wrapper patterns (📚 garak encoding.py)
_ENCODING_WRAPPER_RE = re.compile(
    r"(?:decode|convert|translate)\s+(?:the\s+following\s+)?"
    r"(?:base64|rot13|braille|morse|hex|binary|ascii85)",
    re.IGNORECASE,
)

# Common Cyrillic↔Latin homoglyphs (📚 garak smuggling.py, PromptBench TextBugger)
_HOMOGLYPH_MAP: dict[str, str] = {
    "\u0430": "a",  # Cyrillic а → Latin a
    "\u0435": "e",  # Cyrillic е → Latin e
    "\u043e": "o",  # Cyrillic о → Latin o
    "\u0440": "p",  # Cyrillic р → Latin p
    "\u0441": "c",  # Cyrillic с → Latin c
    "\u0443": "y",  # Cyrillic у → Latin y
    "\u0445": "x",  # Cyrillic х → Latin x
    "\u0456": "i",  # Cyrillic і → Latin i
    "\u0458": "j",  # Cyrillic ј → Latin j
    "\u04bb": "h",  # Cyrillic һ → Latin h
    "\u0501": "d",  # Cyrillic ԁ → Latin d
    "\u051b": "q",  # Cyrillic ԛ → Latin q
}

_HOMOGLYPH_RE = re.compile("[" + "".join(_HOMOGLYPH_MAP.keys()) + "]")


def normalize_text(raw: str) -> tuple[str, NormalizationFlags]:
    """Normalize raw text and return (normalized_text, flags)."""
    flags = NormalizationFlags()
    text = raw

    # 1. Unicode NFC normalization
    nfc = unicodedata.normalize("NFC", text)
    if nfc != text:
        flags.unicode_normalized = True
    text = nfc

    # 2. Strip zero-width characters
    stripped = _ZERO_WIDTH_RE.sub("", text)
    if stripped != text:
        flags.zero_width_stripped = True
        # Also produce a space-separated variant for word-boundary detection
        flags.segments_decoded.append(
            "zw_spaced:" + _ZERO_WIDTH_RE.sub(" ", text)
        )
    text = stripped

    # 3. Detect homoglyphs
    if _HOMOGLYPH_RE.search(text):
        flags.homoglyph_detected = True
        # Replace homoglyphs with Latin equivalents for downstream detection
        for cyrillic, latin in _HOMOGLYPH_MAP.items():
            text = text.replace(cyrillic, latin)

    # 4. Detect and inline-replace base64 segments
    b64_matches = list(_BASE64_RE.finditer(text))
    if b64_matches:
        flags.base64_detected = True
        # Replace in reverse order to preserve positions
        for m in reversed(b64_matches):
            try:
                decoded = base64.b64decode(m.group(), validate=True).decode("utf-8", errors="ignore")
                if decoded and len(decoded) >= 4:
                    flags.segments_decoded.append(f"base64:{decoded[:200]}")
                    # Inline replace so L1 can scan decoded content
                    text = text[:m.start()] + decoded + text[m.end():]
            except Exception:
                pass

    # 5. Detect and inline-replace URL-encoded segments
    url_matches = list(_URL_ENCODED_RE.finditer(text))
    if url_matches:
        flags.url_encoded_detected = True
        for m in reversed(url_matches):
            try:
                from urllib.parse import unquote
                decoded = unquote(m.group())
                if decoded != m.group():
                    text = text[:m.start()] + decoded + text[m.end():]
            except Exception:
                pass

    # 6. Collapse excessive whitespace (keep single newlines)
    collapsed = re.sub(r"[ \t]+", " ", text)
    collapsed = re.sub(r"\n{3,}", "\n\n", collapsed)
    if collapsed != text:
        flags.whitespace_collapsed = True
    text = collapsed

    # 7. Detect markdown system prompt injection
    if _MD_SYSTEM_RE.search(text):
        flags.markdown_system_injection_detected = True

    # 8. Detect encoding wrapper patterns
    if _ENCODING_WRAPPER_RE.search(text):
        flags.encoding_wrapper_detected = True

    return text, flags
