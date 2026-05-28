from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

_LOCALE_DIR = Path(__file__).parent / "locales"
_cache: dict[str, dict[str, str]] = {}
_active_lang: str = "en"


def _load(lang: str) -> dict[str, str]:
    if lang in _cache:
        return _cache[lang]
    path = _LOCALE_DIR / f"{lang}.json"
    if not path.exists():
        return _load("en")
    try:
        with open(path, encoding="utf-8") as f:
            data: dict[str, str] = json.load(f)
            _cache[lang] = data
            return data
    except (json.JSONDecodeError, OSError):
        return _load("en") if lang != "en" else {}


def set_language(lang: str) -> None:
    global _active_lang
    if lang in ("en", "tr"):
        _active_lang = lang


def get_language() -> str:
    return _active_lang


def t(key: str, default: Optional[str] = None) -> str:
    data = _load(_active_lang)
    return data.get(key, default if default else key)


def available_languages() -> list[tuple[str, str]]:
    langs = []
    for f in _LOCALE_DIR.glob("*.json"):
        code = f.stem
        name = {"en": "English", "tr": "Türkçe"}.get(code, code)
        langs.append((code, name))
    return langs


# Detect from environment
_init_lang = os.environ.get("LANG", "en_US.UTF-8")
if _init_lang.startswith("tr"):
    _active_lang = "tr"
else:
    _active_lang = "en"
