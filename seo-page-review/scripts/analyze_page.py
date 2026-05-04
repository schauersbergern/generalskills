#!/usr/bin/env python3
"""
SEO & GEO Page Analyzer

Rendert eine URL mit Playwright/Chromium (oder fällt auf reine HTML-Analyse via
requests+BeautifulSoup zurück), extrahiert alle messbaren Signale und gibt
strukturiertes JSON aus, das vom seo-page-review Skill konsumiert wird.

Usage:
    python3 analyze_page.py <url>
    python3 analyze_page.py <url> --no-render
    python3 analyze_page.py <url> --keyword "n8n automatisierung"
    python3 analyze_page.py <url> --timeout 45

Output: JSON auf stdout. Fehler auf stderr.
"""

import argparse
import json
import re
import subprocess
import sys
import time
import unicodedata
from collections import Counter
from typing import Any
from urllib.parse import urljoin, urlparse


# ----------------------------------------------------------------------------
# Dependency-Bootstrap
# ----------------------------------------------------------------------------

def _ensure_pkg(pkg_name: str, import_name: str | None = None) -> bool:
    """Versucht ein Paket zu importieren, installiert es bei Bedarf via pip."""
    name = import_name or pkg_name
    try:
        __import__(name)
        return True
    except ImportError:
        pass
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", "--break-system-packages", pkg_name],
            stderr=subprocess.DEVNULL,
        )
        __import__(name)
        return True
    except Exception:
        return False


_HAS_REQUESTS = _ensure_pkg("requests")
_HAS_BS4 = _ensure_pkg("beautifulsoup4", "bs4")
_HAS_LXML = _ensure_pkg("lxml")

if not (_HAS_REQUESTS and _HAS_BS4):
    print(json.dumps({
        "error": "missing_dependencies",
        "message": "requests und beautifulsoup4 konnten nicht installiert werden.",
    }), file=sys.stderr)
    sys.exit(2)

import requests  # noqa: E402
from bs4 import BeautifulSoup  # noqa: E402


# ----------------------------------------------------------------------------
# Konstanten
# ----------------------------------------------------------------------------

USER_AGENT = "Mozilla/5.0 (compatible; SEO-Page-Review/1.0; +https://anthropic.com)"
DEFAULT_TIMEOUT = 30

AI_CRAWLERS = [
    "GPTBot",
    "OAI-SearchBot",
    "ChatGPT-User",
    "ClaudeBot",
    "Anthropic-AI",
    "PerplexityBot",
    "Google-Extended",
    "CCBot",
    "Bytespider",
    "Applebot-Extended",
    "FacebookBot",
    "ImagesiftBot",
    "Diffbot",
    "Omgilibot",
]

GERMAN_FILLER_PATTERNS = [
    r"\bin der heutigen (digitalen )?welt\b",
    r"\bzweifellos\b",
    r"\bim folgenden (werden wir|wird)\b",
    r"\bnicht zuletzt\b",
    r"\blast but not least\b",
    r"\bes ist wichtig zu erw[äa]hnen\b",
    r"\bin diesem artikel (werden wir|wird)\b",
    r"\bauf der einen seite,? auf der anderen seite\b",
]

W_FRAGEWORTE = [
    "was", "wer", "wie", "wo", "wann", "warum", "wieso", "weshalb",
    "welche", "welcher", "welches", "wofür", "wodurch", "woraus",
]


# ----------------------------------------------------------------------------
# Fetcher: Playwright bevorzugt, Fallback auf requests
# ----------------------------------------------------------------------------

def fetch_with_playwright(url: str, timeout: int) -> dict[str, Any] | None:
    """Rendert die Seite mit Chromium. Liefert dict oder None bei Fehler."""
    if not _ensure_pkg("playwright"):
        return None

    # Versuch, Chromium zu installieren falls fehlt
    try:
        subprocess.run(
            [sys.executable, "-m", "playwright", "install", "chromium"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=180, check=False,
        )
    except Exception:
        pass

    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        return None

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent=USER_AGENT,
                viewport={"width": 1366, "height": 900},
                locale="de-DE",
            )
            page = context.new_page()

            t_start = time.time()
            response = page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)
            ttfb_ms = (time.time() - t_start) * 1000
            # Kurz auf JS-Hydration warten, ohne networkidle (das kann ewig dauern)
            try:
                page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                pass

            if response is None:
                browser.close()
                return None

            status = response.status
            headers = response.headers
            html = page.content()
            final_url = page.url

            # Performance: count requests
            # (Aus sync API limitiert, simple Heuristik aus DOM)
            browser.close()

            return {
                "renderer": "playwright",
                "status_code": status,
                "final_url": final_url,
                "headers": dict(headers),
                "html": html,
                "ttfb_ms": round(ttfb_ms, 1),
            }
    except Exception as e:
        print(f"[warn] playwright failed: {e}", file=sys.stderr)
        return None


def fetch_with_requests(url: str, timeout: int) -> dict[str, Any] | None:
    """Reiner HTTP-GET ohne JS-Rendering."""
    try:
        t_start = time.time()
        resp = requests.get(
            url,
            headers={"User-Agent": USER_AGENT, "Accept-Language": "de-DE,de;q=0.9,en;q=0.8"},
            timeout=timeout,
            allow_redirects=True,
        )
        ttfb_ms = (time.time() - t_start) * 1000
        return {
            "renderer": "requests-fallback",
            "status_code": resp.status_code,
            "final_url": resp.url,
            "headers": dict(resp.headers),
            "html": resp.text,
            "ttfb_ms": round(ttfb_ms, 1),
        }
    except Exception as e:
        print(f"[error] requests failed: {e}", file=sys.stderr)
        return None


# ----------------------------------------------------------------------------
# Robots.txt + llms.txt
# ----------------------------------------------------------------------------

def fetch_robots_txt(base_url: str, timeout: int = 15) -> dict[str, Any]:
    """Holt robots.txt und parst AI-Crawler-Direktiven."""
    parsed = urlparse(base_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    result = {
        "url": robots_url,
        "fetched": False,
        "status_code": None,
        "raw": "",
        "sitemaps": [],
        "ai_crawler_status": {},
        "any_disallow_all": False,
    }
    try:
        resp = requests.get(robots_url, headers={"User-Agent": USER_AGENT}, timeout=timeout)
        result["status_code"] = resp.status_code
        if resp.status_code == 200:
            result["fetched"] = True
            result["raw"] = resp.text
            result.update(parse_robots_txt(resp.text))
    except Exception as e:
        print(f"[warn] robots.txt fetch failed: {e}", file=sys.stderr)

    # AI-Crawler-Status auswerten
    parsed_blocks = result.get("blocks", [])
    for crawler in AI_CRAWLERS:
        result["ai_crawler_status"][crawler] = check_crawler_allowed(
            parsed_blocks, crawler, parsed.path or "/"
        )
    return result


def parse_robots_txt(text: str) -> dict[str, Any]:
    """Parst robots.txt in strukturierte Blöcke."""
    blocks: list[dict[str, Any]] = []
    sitemaps: list[str] = []
    current: dict[str, Any] | None = None

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
            continue
        directive, _, value = line.partition(":")
        directive = directive.strip().lower()
        value = value.strip()

        if directive == "user-agent":
            if current and current.get("agents"):
                # gleiche Gruppe, weiterer Agent
                if not current.get("rules"):
                    current["agents"].append(value)
                    continue
            current = {"agents": [value], "rules": []}
            blocks.append(current)
        elif directive in {"allow", "disallow"} and current is not None:
            current["rules"].append({"type": directive, "path": value})
        elif directive == "sitemap":
            sitemaps.append(value)

    return {"blocks": blocks, "sitemaps": sitemaps}


def check_crawler_allowed(blocks: list[dict[str, Any]], crawler: str, path: str) -> dict[str, Any]:
    """Prüft, ob ein Crawler eine Path explicitly disallowed bekommt."""
    crawler_lower = crawler.lower()
    matching_blocks = []
    wildcard_block = None

    for block in blocks:
        agents_lower = [a.lower() for a in block.get("agents", [])]
        if any(crawler_lower == a or crawler_lower in a for a in agents_lower):
            matching_blocks.append(block)
        if "*" in agents_lower:
            wildcard_block = block

    # Spezifische Blöcke haben Vorrang vor Wildcard
    target_block = matching_blocks[0] if matching_blocks else wildcard_block

    if target_block is None:
        return {"allowed": True, "reason": "no_directive"}

    # Längste Regel gewinnt (Standard-Verhalten)
    matched_rule = None
    matched_len = -1
    for rule in target_block.get("rules", []):
        rule_path = rule["path"]
        if rule_path == "":
            # Disallow: leer = erlauben alles
            if rule["type"] == "disallow" and matched_len < 0:
                matched_rule = {"type": "allow", "path": ""}
                matched_len = 0
            continue
        # Einfache Prefix-Übereinstimmung
        check_path = rule_path.replace("*", "")
        if path.startswith(check_path):
            if len(rule_path) > matched_len:
                matched_rule = rule
                matched_len = len(rule_path)

    if matched_rule is None:
        return {"allowed": True, "reason": "no_matching_rule"}

    if matched_rule["type"] == "disallow":
        return {
            "allowed": False,
            "reason": f"disallow:{matched_rule['path']}",
            "block_specific": target_block in matching_blocks,
        }
    return {"allowed": True, "reason": f"allow:{matched_rule['path']}"}


def check_llms_txt(base_url: str, timeout: int = 10) -> dict[str, Any]:
    """Prüft, ob /llms.txt existiert."""
    parsed = urlparse(base_url)
    llms_url = f"{parsed.scheme}://{parsed.netloc}/llms.txt"
    try:
        resp = requests.head(llms_url, headers={"User-Agent": USER_AGENT}, timeout=timeout, allow_redirects=True)
        if resp.status_code == 200:
            return {"url": llms_url, "exists": True, "status_code": 200}
        return {"url": llms_url, "exists": False, "status_code": resp.status_code}
    except Exception:
        return {"url": llms_url, "exists": False, "status_code": None}


# ----------------------------------------------------------------------------
# HTML-Analyse
# ----------------------------------------------------------------------------

def analyze_html(html: str, base_url: str, response_data: dict[str, Any]) -> dict[str, Any]:
    """Hauptanalyse-Funktion. Extrahiert alle messbaren Signale."""
    parser = "lxml" if _HAS_LXML else "html.parser"
    soup = BeautifulSoup(html, parser)

    result: dict[str, Any] = {
        "url": base_url,
        "final_url": response_data.get("final_url", base_url),
        "renderer": response_data.get("renderer"),
        "status_code": response_data.get("status_code"),
        "ttfb_ms": response_data.get("ttfb_ms"),
        "headers": _extract_relevant_headers(response_data.get("headers", {})),
        "html_size_bytes": len(html.encode("utf-8")),
    }

    # Sprache
    html_tag = soup.find("html")
    result["lang"] = (html_tag.get("lang") if html_tag else None) or None

    # Charset
    charset = None
    meta_charset = soup.find("meta", charset=True)
    if meta_charset:
        charset = meta_charset.get("charset")
    else:
        meta_http = soup.find("meta", attrs={"http-equiv": re.compile("content-type", re.I)})
        if meta_http and meta_http.get("content"):
            m = re.search(r"charset=([\w-]+)", meta_http["content"], re.I)
            if m:
                charset = m.group(1)
    result["charset"] = charset

    # Viewport
    viewport = soup.find("meta", attrs={"name": "viewport"})
    result["viewport"] = viewport.get("content") if viewport else None

    # Title
    title_tag = soup.find("title")
    title_text = (title_tag.text.strip() if title_tag else "") or ""
    result["title"] = {
        "text": title_text,
        "length": len(title_text),
    }

    # Meta description
    meta_desc = soup.find("meta", attrs={"name": "description"})
    desc_text = (meta_desc.get("content", "").strip() if meta_desc else "") or ""
    result["meta_description"] = {
        "text": desc_text,
        "length": len(desc_text),
    }

    # Meta robots
    meta_robots = soup.find("meta", attrs={"name": re.compile("^robots$", re.I)})
    result["meta_robots"] = (meta_robots.get("content", "").lower() if meta_robots else "") or ""

    # Canonical
    canonical = soup.find("link", attrs={"rel": "canonical"})
    result["canonical"] = canonical.get("href") if canonical else None

    # Hreflang
    hreflang_tags = soup.find_all("link", attrs={"rel": "alternate", "hreflang": True})
    result["hreflang"] = [
        {"hreflang": t.get("hreflang"), "href": t.get("href")} for t in hreflang_tags
    ]

    # Open Graph
    og_tags = {}
    for tag in soup.find_all("meta", attrs={"property": re.compile("^og:", re.I)}):
        og_tags[tag["property"].lower()] = tag.get("content", "")
    result["open_graph"] = og_tags

    # Twitter Card
    tw_tags = {}
    for tag in soup.find_all("meta", attrs={"name": re.compile("^twitter:", re.I)}):
        tw_tags[tag["name"].lower()] = tag.get("content", "")
    result["twitter_card"] = tw_tags

    # Headings
    headings: dict[str, list[str]] = {f"h{i}": [] for i in range(1, 7)}
    heading_order: list[tuple[int, str]] = []
    for level in range(1, 7):
        for h in soup.find_all(f"h{level}"):
            text = h.get_text(strip=True)
            if text:
                headings[f"h{level}"].append(text)
                heading_order.append((level, text))
    result["headings"] = headings
    result["heading_hierarchy_jumps"] = _count_heading_jumps(heading_order)
    result["heading_order"] = [{"level": l, "text": t} for l, t in heading_order]

    # Body-Text + Sektions-Analyse
    body_text = _extract_body_text(soup)
    result["text"] = {
        "raw_length": len(body_text),
        "word_count": _count_words(body_text),
    }

    # Lesbarkeit (Flesch DE / Amstad)
    result["readability"] = _calculate_readability(body_text, result.get("lang") or "de")

    # Keyword-Analyse (heuristisch ohne explizites Keyword)
    result["text"]["top_terms"] = _top_terms(body_text, n=10)

    # Sektionen mit H2-Frage-Antwort-Heuristik
    result["sections"] = _analyze_sections(soup)

    # FAQ-Heuristik
    result["faq_heuristic"] = _detect_faq(soup)

    # Listen, Tabellen
    result["lists"] = {
        "ul_count": len(soup.find_all("ul")),
        "ol_count": len(soup.find_all("ol")),
        "li_count": len(soup.find_all("li")),
    }
    result["tables"] = {
        "count": len(soup.find_all("table")),
        "with_thead": len([t for t in soup.find_all("table") if t.find("thead")]),
    }

    # Filler/Boilerplate
    body_lower = body_text.lower()
    filler_hits = []
    for pattern in GERMAN_FILLER_PATTERNS:
        matches = re.findall(pattern, body_lower)
        if matches:
            filler_hits.append({"pattern": pattern, "count": len(matches)})
    result["filler_phrases"] = filler_hits

    # Links
    result["links"] = _analyze_links(soup, base_url)

    # Bilder
    result["images"] = _analyze_images(soup, base_url)

    # Schema (JSON-LD, Microdata, RDFa)
    result["schema"] = _analyze_schema(soup)

    # Performance-Heuristiken
    result["performance"] = _analyze_performance(soup, response_data.get("headers", {}), html)

    # Datum-Hinweise
    result["dates"] = _analyze_dates(soup, body_text)

    # Author-Hinweise
    result["author_signals"] = _analyze_author(soup, body_text)

    # Erfahrungsmarker
    result["experience_markers"] = _detect_experience_markers(body_text)

    # Quellen-Verlinkung im Fließtext
    result["inline_citations"] = _count_inline_citations(soup, base_url)

    # Trust-Indikatoren (Footer, Impressum, Kontakt)
    result["trust_indicators"] = _detect_trust_indicators(soup)

    # Content Capsule Score (heuristisch)
    result["content_capsule_score"] = _capsule_coverage(result["sections"])

    # Citability-Heuristik (Absatz-Längen)
    result["paragraph_lengths"] = _paragraph_length_distribution(soup)

    # Entitäten (heuristisch: kapitalisierte Mehrwortgruppen)
    result["entities"] = _extract_entities_heuristic(body_text)

    # Erkannter Seitentyp (heuristisch)
    result["detected_page_type"] = _detect_page_type(result, base_url)

    return result


# ----------------------------------------------------------------------------
# Helper-Funktionen
# ----------------------------------------------------------------------------

def _extract_relevant_headers(headers: dict[str, str]) -> dict[str, str]:
    relevant = ["content-type", "content-encoding", "server", "x-powered-by", "cache-control",
                "strict-transport-security", "x-content-type-options", "content-security-policy",
                "alt-svc"]
    out = {}
    lower_map = {k.lower(): k for k in headers.keys()}
    for r in relevant:
        if r in lower_map:
            out[r] = headers[lower_map[r]]
    return out


def _count_heading_jumps(heading_order: list[tuple[int, str]]) -> int:
    """Zählt übersprungene Heading-Levels."""
    if not heading_order:
        return 0
    jumps = 0
    prev_level = heading_order[0][0]
    for level, _ in heading_order[1:]:
        if level > prev_level + 1:
            jumps += 1
        prev_level = level
    return jumps


def _extract_body_text(soup: BeautifulSoup) -> str:
    """Extrahiert lesbaren Text, ohne Scripts/Styles/Nav-Boilerplate."""
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.decompose()
    main = soup.find("main") or soup.find("article") or soup.body or soup
    text = main.get_text(separator=" ", strip=True)
    text = re.sub(r"\s+", " ", text)
    return text


def _count_words(text: str) -> int:
    if not text:
        return 0
    return len(re.findall(r"\b[\w'\-äöüÄÖÜß]+\b", text))


def _calculate_readability(text: str, lang: str) -> dict[str, Any]:
    """Berechnet Flesch Reading Ease (DE: Amstad-Anpassung)."""
    if not text or len(text) < 100:
        return {"score": None, "grade": None, "method": "insufficient_text"}

    sentences = re.split(r"[.!?]+", text)
    sentences = [s.strip() for s in sentences if s.strip()]
    n_sentences = len(sentences) or 1

    words = re.findall(r"\b[\w'\-äöüÄÖÜß]+\b", text)
    n_words = len(words) or 1

    syllables = sum(_count_syllables_de(w) for w in words)

    asl = n_words / n_sentences
    asw = syllables / n_words

    is_de = (lang or "").lower().startswith("de")
    if is_de:
        score = 180 - asl - (58.5 * asw)
        method = "flesch_amstad_de"
    else:
        score = 206.835 - 1.015 * asl - 84.6 * asw
        method = "flesch_en"

    score = max(0.0, min(100.0, score))

    return {
        "score": round(score, 1),
        "method": method,
        "avg_sentence_length": round(asl, 1),
        "avg_syllables_per_word": round(asw, 2),
        "n_sentences": n_sentences,
        "n_words": n_words,
    }


def _count_syllables_de(word: str) -> int:
    """Heuristische Silbenzählung (deutschtauglich, vereinfacht)."""
    word = word.lower()
    word = unicodedata.normalize("NFC", word)
    if len(word) <= 1:
        return 1
    vowels = "aeiouyäöü"
    count = 0
    prev_vowel = False
    for ch in word:
        is_vowel = ch in vowels
        if is_vowel and not prev_vowel:
            count += 1
        prev_vowel = is_vowel
    # Diphthonge wieder abziehen wäre nice, aber ohne echtes Lexikon zu fehleranfällig
    return max(1, count)


def _top_terms(text: str, n: int = 10) -> list[dict[str, Any]]:
    """Häufigste Substantiv-ähnliche Begriffe (heuristisch über Capitalization + Stopwords)."""
    stopwords = {
        "der", "die", "das", "und", "oder", "aber", "als", "auch", "auf", "aus", "bei", "bis",
        "durch", "ein", "eine", "einen", "einem", "einer", "eines", "es", "für", "gegen", "ich",
        "im", "in", "ist", "ja", "kann", "können", "mehr", "mit", "nach", "nicht", "noch", "nur",
        "ob", "ohne", "sein", "sich", "sie", "so", "über", "um", "und", "uns", "unser", "von",
        "vor", "war", "wäre", "weil", "wenn", "werden", "wie", "wir", "wird", "zu", "zum", "zur",
        "the", "of", "and", "to", "a", "in", "is", "for", "on", "with",
    }
    tokens = re.findall(r"\b[\wäöüÄÖÜß]{3,}\b", text)
    tokens = [t.lower() for t in tokens if t.lower() not in stopwords]
    counter = Counter(tokens)
    return [{"term": t, "count": c} for t, c in counter.most_common(n)]


def _analyze_sections(soup: BeautifulSoup) -> list[dict[str, Any]]:
    """Analysiert H2-Sektionen heuristisch auf Frage-Antwort-Struktur."""
    sections = []
    h2s = soup.find_all("h2")
    for h2 in h2s:
        title_text = h2.get_text(strip=True)
        if not title_text:
            continue
        # Sammle nachfolgenden Text bis zum nächsten H2 oder H1
        following_text_parts = []
        for sibling in h2.find_all_next():
            if sibling.name in ("h1", "h2"):
                break
            if sibling.name in ("p", "li"):
                txt = sibling.get_text(strip=True)
                if txt:
                    following_text_parts.append(txt)
            if sum(len(p) for p in following_text_parts) > 2000:
                break
        following_text = " ".join(following_text_parts)
        word_count = _count_words(following_text)
        first_80_tokens = " ".join(following_text.split()[:80])

        is_question = title_text.endswith("?")
        starts_with_w = any(title_text.lower().startswith(w + " ") for w in W_FRAGEWORTE)
        # Antwort-Heuristik: in den ersten 60 Wörtern eine Aussage mit Subjekt+Verb
        first_60_words = " ".join(following_text.split()[:60])
        has_concrete_answer = bool(re.search(r"\b(ist|sind|bedeutet|bezeichnet|umfasst|gilt)\b", first_60_words.lower()))

        capsule_match = (is_question or starts_with_w) and 30 <= word_count <= 220 and has_concrete_answer

        sections.append({
            "h2": title_text,
            "is_question_format": is_question or starts_with_w,
            "word_count": word_count,
            "first_80_tokens": first_80_tokens,
            "capsule_match": capsule_match,
        })
    return sections


def _detect_faq(soup: BeautifulSoup) -> dict[str, Any]:
    """Erkennt eine FAQ-Sektion heuristisch."""
    faq_indicators = soup.find_all(string=re.compile(r"(faq|h[äa]ufige fragen|fragen und antworten)", re.I))
    if not faq_indicators:
        return {"detected": False, "questions": 0, "avg_answer_words": None}

    # Suche danach nach Frage-Pattern
    questions = []
    for h in soup.find_all(["h2", "h3", "h4"]):
        txt = h.get_text(strip=True)
        if txt.endswith("?") or any(txt.lower().startswith(w + " ") for w in W_FRAGEWORTE):
            answer_parts = []
            for sib in h.find_all_next():
                if sib.name in ("h1", "h2", "h3", "h4"):
                    break
                if sib.name in ("p", "li"):
                    answer_parts.append(sib.get_text(strip=True))
                if sum(len(p) for p in answer_parts) > 1000:
                    break
            answer = " ".join(answer_parts)
            questions.append({"q": txt, "answer_words": _count_words(answer)})

    if not questions:
        return {"detected": False, "questions": 0, "avg_answer_words": None}

    avg = sum(q["answer_words"] for q in questions) / len(questions)
    return {
        "detected": len(questions) >= 3,
        "questions": len(questions),
        "avg_answer_words": round(avg, 1),
        "in_optimal_length": sum(1 for q in questions if 40 <= q["answer_words"] <= 80),
    }


def _analyze_links(soup: BeautifulSoup, base_url: str) -> dict[str, Any]:
    """Analysiert interne und externe Links."""
    parsed_base = urlparse(base_url)
    base_host = parsed_base.netloc.lower().lstrip("www.")

    internal = []
    external = []
    generic_anchors = ["hier", "klick", "klicken sie hier", "mehr", "lesen", "weiter", "click here", "read more"]
    generic_count = 0

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        full = urljoin(base_url, href)
        parsed = urlparse(full)
        if not parsed.netloc:
            continue
        host = parsed.netloc.lower().lstrip("www.")
        anchor = a.get_text(strip=True)
        rel = a.get("rel", [])
        if isinstance(rel, str):
            rel = [rel]

        link_data = {"href": full, "anchor": anchor, "rel": rel}
        if host == base_host or host.endswith("." + base_host):
            internal.append(link_data)
        else:
            external.append(link_data)

        if anchor.lower() in generic_anchors:
            generic_count += 1

    total = len(internal) + len(external)
    return {
        "internal_count": len(internal),
        "external_count": len(external),
        "total": total,
        "generic_anchors_count": generic_count,
        "generic_anchors_ratio": round(generic_count / total, 3) if total > 0 else 0,
        "internal_sample": internal[:10],
        "external_sample": external[:10],
        "external_with_nofollow": sum(1 for e in external if "nofollow" in e["rel"]),
    }


def _analyze_images(soup: BeautifulSoup, base_url: str) -> dict[str, Any]:
    """Analysiert Bilder."""
    imgs = soup.find_all("img")
    n = len(imgs)
    if n == 0:
        return {"count": 0, "with_alt": 0, "alt_coverage": 0,
                "with_dimensions": 0, "lazy_loaded": 0, "modern_format": 0,
                "examples": []}

    with_alt = 0
    descriptive_alt = 0
    with_dims = 0
    lazy = 0
    modern = 0
    examples = []

    for img in imgs:
        alt = img.get("alt")
        has_alt = alt is not None
        if has_alt:
            with_alt += 1
            if len(alt.strip()) >= 8 and not re.match(r"^(image|bild|img|foto|picture)\d*\.?\w*$", alt.strip().lower()):
                descriptive_alt += 1
        if img.get("width") and img.get("height"):
            with_dims += 1
        if img.get("loading", "").lower() == "lazy":
            lazy += 1
        src = img.get("src", "") or img.get("data-src", "")
        if re.search(r"\.(webp|avif)(\?|$)", src, re.I):
            modern += 1
        if len(examples) < 5:
            examples.append({
                "src": urljoin(base_url, src) if src else "",
                "alt": alt,
                "has_dims": bool(img.get("width") and img.get("height")),
                "loading": img.get("loading"),
            })

    return {
        "count": n,
        "with_alt": with_alt,
        "alt_coverage": round(with_alt / n, 3),
        "descriptive_alt": descriptive_alt,
        "descriptive_alt_ratio": round(descriptive_alt / n, 3),
        "with_dimensions": with_dims,
        "with_dimensions_ratio": round(with_dims / n, 3),
        "lazy_loaded": lazy,
        "lazy_loaded_ratio": round(lazy / n, 3),
        "modern_format": modern,
        "modern_format_ratio": round(modern / n, 3),
        "examples": examples,
    }


def _analyze_schema(soup: BeautifulSoup) -> dict[str, Any]:
    """Findet alle JSON-LD-Blöcke und extrahiert Schema-Typen."""
    json_ld_blocks = []
    json_ld_errors = []

    for script in soup.find_all("script", attrs={"type": "application/ld+json"}):
        raw = script.string or script.text or ""
        if not raw.strip():
            continue
        try:
            data = json.loads(raw)
            json_ld_blocks.append(data)
        except json.JSONDecodeError as e:
            json_ld_errors.append({"error": str(e), "snippet": raw[:200]})

    types_found = []
    for block in json_ld_blocks:
        types_found.extend(_extract_schema_types(block))

    # Microdata / RDFa Erkennung (rudimentär)
    microdata = bool(soup.find(attrs={"itemtype": True}))
    rdfa = bool(soup.find(attrs={"typeof": True}))

    return {
        "json_ld_count": len(json_ld_blocks),
        "json_ld_types": types_found,
        "json_ld_errors": json_ld_errors,
        "microdata_present": microdata,
        "rdfa_present": rdfa,
        "blocks": json_ld_blocks,
    }


def _extract_schema_types(data: Any) -> list[str]:
    """Rekursiv alle @type-Werte sammeln."""
    types = []
    if isinstance(data, dict):
        t = data.get("@type")
        if isinstance(t, str):
            types.append(t)
        elif isinstance(t, list):
            types.extend([x for x in t if isinstance(x, str)])
        if "@graph" in data and isinstance(data["@graph"], list):
            for item in data["@graph"]:
                types.extend(_extract_schema_types(item))
        for v in data.values():
            if isinstance(v, (dict, list)):
                types.extend(_extract_schema_types(v))
    elif isinstance(data, list):
        for item in data:
            types.extend(_extract_schema_types(item))
    return types


def _analyze_performance(soup: BeautifulSoup, headers: dict, html: str) -> dict[str, Any]:
    """Performance-Heuristiken aus dem HTML."""
    head = soup.find("head") or soup
    scripts_in_head = head.find_all("script", src=True)
    render_blocking = sum(1 for s in scripts_in_head if not s.get("async") and not s.get("defer"))

    css_files = soup.find_all("link", attrs={"rel": "stylesheet"})
    fonts = []
    for link in soup.find_all("link"):
        rel = link.get("rel", [])
        if isinstance(rel, str):
            rel = [rel]
        if "preload" in rel and link.get("as") == "font":
            fonts.append(link.get("href"))
        if link.get("href", "").lower().endswith((".woff", ".woff2", ".ttf", ".otf")):
            fonts.append(link.get("href"))

    iframes = soup.find_all("iframe")
    iframes_lazy = sum(1 for i in iframes if i.get("loading") == "lazy")

    preloads = sum(1 for l in soup.find_all("link") if "preload" in (l.get("rel") or []))

    # Total resources (rough estimate)
    total_resources = (
        len(soup.find_all("script", src=True)) +
        len(soup.find_all("link", rel="stylesheet")) +
        len(soup.find_all("img")) +
        len(soup.find_all("iframe")) +
        len(soup.find_all("video")) +
        len(soup.find_all("audio"))
    )

    server = headers.get("server", headers.get("Server", ""))
    alt_svc = headers.get("alt-svc", headers.get("Alt-Svc", ""))
    http_version = "unknown"
    if "h3" in alt_svc.lower() or "quic" in alt_svc.lower():
        http_version = "h3-supported"
    elif "h2" in alt_svc.lower():
        http_version = "h2-supported"

    return {
        "html_size_kb": round(len(html.encode("utf-8")) / 1024, 1),
        "scripts_total": len(soup.find_all("script")),
        "scripts_with_src": len(soup.find_all("script", src=True)),
        "render_blocking_scripts_in_head": render_blocking,
        "css_files": len(css_files),
        "fonts_referenced": len(fonts),
        "iframes": len(iframes),
        "iframes_lazy": iframes_lazy,
        "preloads": preloads,
        "total_resources_estimate": total_resources,
        "server": server,
        "http_version_hint": http_version,
    }


def _analyze_dates(soup: BeautifulSoup, body_text: str) -> dict[str, Any]:
    """Findet sichtbare und Markup-Daten."""
    visible_dates = []
    # Heuristik: typisch deutsche/englische Datumsmuster im Text
    date_patterns = [
        r"\b\d{1,2}\.\s?\d{1,2}\.\s?(20\d{2})\b",
        r"\b(20\d{2})-\d{2}-\d{2}\b",
        r"\b(januar|februar|m[äa]rz|april|mai|juni|juli|august|september|oktober|november|dezember)\s+(20\d{2})\b",
    ]
    for pat in date_patterns:
        for m in re.finditer(pat, body_text, re.I):
            visible_dates.append(m.group(0))

    # Time-Tags
    time_tags = []
    for t in soup.find_all("time"):
        time_tags.append({
            "text": t.get_text(strip=True),
            "datetime": t.get("datetime"),
        })

    # Update-Marker
    update_markers = []
    for pat in [r"zuletzt aktualisiert", r"letzte aktualisierung", r"updated:?", r"stand:?\s*\d", r"aktualisiert am"]:
        if re.search(pat, body_text, re.I):
            update_markers.append(pat)

    return {
        "visible_date_strings": visible_dates[:8],
        "time_tags": time_tags[:8],
        "update_markers_found": update_markers,
        "has_update_marker": len(update_markers) > 0,
    }


def _analyze_author(soup: BeautifulSoup, body_text: str) -> dict[str, Any]:
    """Erkennt Autor-Hinweise heuristisch."""
    meta_author = soup.find("meta", attrs={"name": "author"})
    rel_author = soup.find("a", attrs={"rel": "author"})
    by_pattern = re.findall(r"\b(?:von|by|geschrieben von|autor:?|author:?)\s+([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+)+)", body_text)

    return {
        "meta_author": meta_author.get("content") if meta_author else None,
        "rel_author_link": rel_author.get("href") if rel_author else None,
        "byline_matches": list(set(by_pattern[:5])),
        "has_author_signal": bool(meta_author or rel_author or by_pattern),
    }


def _detect_experience_markers(text: str) -> dict[str, Any]:
    """Sucht Erfahrungsmarker, die E-E-A-T-Experience signalisieren."""
    patterns = [
        r"\b(in den letzten|seit über|seit mehr als)\s+\d+\s+(jahren|monaten)\b",
        r"\b(wir haben|ich habe|unsere kunden|in unserer praxis)\b",
        r"\bfallstudie\b",
        r"\baus eigener erfahrung\b",
        r"\bgetestet\b",
        r"\b(ich|wir)\s+(empfehle|empfehlen|nutze|nutzen)\b",
    ]
    hits = []
    for p in patterns:
        for m in re.finditer(p, text, re.I):
            hits.append(m.group(0))
    return {
        "marker_count": len(hits),
        "examples": list(set(hits[:8])),
        "has_markers": len(hits) > 0,
    }


def _count_inline_citations(soup: BeautifulSoup, base_url: str) -> dict[str, Any]:
    """Zählt externe Links, die im Fließtext stehen (nicht in Footer/Nav)."""
    main = soup.find("main") or soup.find("article") or soup.body or soup
    parsed_base = urlparse(base_url)
    base_host = parsed_base.netloc.lower().lstrip("www.")

    citations = 0
    domains: set[str] = set()
    for a in main.find_all("a", href=True):
        href = urljoin(base_url, a["href"])
        host = urlparse(href).netloc.lower().lstrip("www.")
        if host and host != base_host and not host.endswith("." + base_host):
            citations += 1
            domains.add(host)

    word_count = _count_words(main.get_text(separator=" ", strip=True))
    citations_per_1000 = round((citations / word_count) * 1000, 1) if word_count > 0 else 0

    return {
        "external_links_in_main": citations,
        "unique_domains": len(domains),
        "citations_per_1000_words": citations_per_1000,
        "word_count_main": word_count,
    }


def _detect_trust_indicators(soup: BeautifulSoup) -> dict[str, Any]:
    """Sucht Footer-Links zu Impressum, Datenschutz, Kontakt, Über-uns."""
    indicators = {
        "imprint": False,
        "privacy": False,
        "contact": False,
        "about": False,
        "logo": False,
    }

    text_link_patterns = {
        "imprint": r"\b(impressum|legal notice)\b",
        "privacy": r"\b(datenschutz|privacy)\b",
        "contact": r"\b(kontakt|contact)\b",
        "about": r"\b(über uns|about us|über mich)\b",
    }

    for a in soup.find_all("a", href=True):
        text = a.get_text(strip=True).lower()
        for key, pat in text_link_patterns.items():
            if re.search(pat, text, re.I):
                indicators[key] = True

    # Logo-Heuristik
    for img in soup.find_all("img"):
        alt = (img.get("alt") or "").lower()
        src = (img.get("src") or "").lower()
        if "logo" in alt or "logo" in src:
            indicators["logo"] = True
            break

    return indicators


def _capsule_coverage(sections: list[dict[str, Any]]) -> dict[str, Any]:
    """Berechnet Anteil der Sektionen mit Content-Capsule-Format."""
    if not sections:
        return {"sections_total": 0, "capsule_matches": 0, "ratio": 0}
    matches = sum(1 for s in sections if s.get("capsule_match"))
    return {
        "sections_total": len(sections),
        "capsule_matches": matches,
        "ratio": round(matches / len(sections), 3),
    }


def _paragraph_length_distribution(soup: BeautifulSoup) -> dict[str, Any]:
    """Verteilung der Absatzlängen für Citability-Bewertung."""
    main = soup.find("main") or soup.find("article") or soup.body or soup
    paragraphs = [_count_words(p.get_text()) for p in main.find_all("p")]
    paragraphs = [p for p in paragraphs if p > 0]

    if not paragraphs:
        return {"count": 0, "avg": 0, "in_optimal_range": 0, "ratio_optimal": 0}

    optimal = sum(1 for p in paragraphs if 80 <= p <= 180)
    return {
        "count": len(paragraphs),
        "avg": round(sum(paragraphs) / len(paragraphs), 1),
        "min": min(paragraphs),
        "max": max(paragraphs),
        "in_optimal_range_80_180": optimal,
        "ratio_optimal": round(optimal / len(paragraphs), 3),
        "in_citation_sweet_spot_120_180": sum(1 for p in paragraphs if 120 <= p <= 180),
    }


def _extract_entities_heuristic(text: str) -> dict[str, Any]:
    """Heuristische Entitätenerkennung (kapitalisierte Mehrwortgruppen)."""
    candidates = re.findall(
        r"\b(?:[A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß0-9.]+){0,3})\b",
        text,
    )
    # Filter sehr kurze und sehr häufige (Satzanfänge)
    # Counting unique multi-word entities (>=2 words)
    multi = [c for c in candidates if " " in c]
    counter = Counter(multi)
    top = counter.most_common(20)

    word_count = _count_words(text)
    entity_count = len(set(multi))
    density_per_1000 = round((entity_count / word_count) * 1000, 1) if word_count > 0 else 0

    return {
        "unique_multi_word_candidates": entity_count,
        "density_per_1000_words": density_per_1000,
        "top_candidates": [{"entity": e, "count": c} for e, c in top if c >= 1],
        "word_count": word_count,
        "note": "Heuristische Erkennung. Manuelle Plausibilitätsprüfung empfohlen.",
    }


def _detect_page_type(result: dict[str, Any], url: str) -> dict[str, Any]:
    """Erkennt heuristisch den Seitentyp."""
    schema_types = result.get("schema", {}).get("json_ld_types", [])
    schema_lower = [t.lower() for t in schema_types]

    indicators = []
    detected = "unknown"

    if any(t in schema_lower for t in ["article", "blogposting", "newsarticle"]):
        detected = "article"
        indicators.append("schema:Article-Family")
    elif "product" in schema_lower:
        detected = "product"
        indicators.append("schema:Product")
    elif any(t in schema_lower for t in ["service", "professionalservice"]):
        detected = "service"
        indicators.append("schema:Service")
    elif any(t in schema_lower for t in ["organization", "localbusiness", "corporation"]):
        # Ohne Article wahrscheinlich Homepage oder About
        detected = "organization_or_home"
        indicators.append("schema:Organization-Family")
    elif any(t in schema_lower for t in ["webpage", "collectionpage", "itempage"]):
        detected = "generic_page"
        indicators.append("schema:WebPage-Family")

    parsed = urlparse(url)
    path = parsed.path.lower()
    if path in ("", "/"):
        if detected == "unknown":
            detected = "homepage"
        indicators.append("path:root")
    elif "/blog/" in path or "/news/" in path or "/artikel/" in path:
        if detected == "unknown":
            detected = "article"
        indicators.append("path:blog-ish")

    word_count = result.get("text", {}).get("word_count", 0)
    if word_count > 1500 and detected == "unknown":
        detected = "article"
        indicators.append("text-heavy>1500w")

    return {
        "detected_type": detected,
        "indicators": indicators,
        "schema_types_seen": schema_types,
    }


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="SEO & GEO Page Analyzer")
    parser.add_argument("url", help="URL to analyze")
    parser.add_argument("--no-render", action="store_true", help="Force HTML-only fallback (no JS rendering)")
    parser.add_argument("--keyword", default=None, help="Optional target keyword for on-page evaluation")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout per fetch in seconds")
    args = parser.parse_args()

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    response_data = None
    if not args.no_render:
        response_data = fetch_with_playwright(url, args.timeout)

    if response_data is None:
        response_data = fetch_with_requests(url, args.timeout)

    if response_data is None:
        print(json.dumps({
            "error": "fetch_failed",
            "message": "Konnte URL weder per Playwright noch per HTTP-Get laden.",
            "url": url,
        }, ensure_ascii=False, indent=2))
        return 3

    if response_data["status_code"] >= 400:
        print(json.dumps({
            "error": "http_error",
            "status_code": response_data["status_code"],
            "url": url,
            "renderer": response_data["renderer"],
            "headers": _extract_relevant_headers(response_data.get("headers", {})),
        }, ensure_ascii=False, indent=2))
        return 4

    parsed = analyze_html(response_data["html"], url, response_data)

    # robots.txt + llms.txt zusätzlich
    parsed["robots_txt"] = fetch_robots_txt(url, args.timeout)
    parsed["llms_txt"] = check_llms_txt(url)

    # Optional: Keyword-Match
    if args.keyword:
        kw = args.keyword.lower()
        body = response_data["html"].lower()
        title = parsed["title"]["text"].lower()
        h1s = [h.lower() for h in parsed["headings"]["h1"]]
        meta_desc = parsed["meta_description"]["text"].lower()
        parsed["keyword"] = {
            "term": args.keyword,
            "in_title": kw in title,
            "in_title_first_30": kw in title[:30] if title else False,
            "in_h1": any(kw in h for h in h1s),
            "in_meta_description": kw in meta_desc,
            "occurrences_in_body": body.count(kw),
        }

    print(json.dumps(parsed, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
