#!/usr/bin/env python3
"""
PDP Analyzer (Product Detail Page)

Analysiert E-Commerce-Produktseiten auf SEO- und GEO-Signale. Rendert mit
Playwright/Chromium (Fallback auf reine HTML-Analyse), extrahiert Product-Schema,
Preise, Verfügbarkeit, Reviews, Variants, Trust-Signale, Versand- und Rückgabe-Hinweise,
und erkennt die Shop-Plattform.

Usage:
    python3 analyze_pdp.py <url>
    python3 analyze_pdp.py <url> --no-render
    python3 analyze_pdp.py <url> --keyword "Brompton P-Line"
    python3 analyze_pdp.py <url> --timeout 60

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

USER_AGENT = "Mozilla/5.0 (compatible; SEO-PDP-Analyzer/1.0; +https://anthropic.com)"
DEFAULT_TIMEOUT = 30

AI_CRAWLERS = [
    "GPTBot", "OAI-SearchBot", "ChatGPT-User",
    "ClaudeBot", "Anthropic-AI",
    "PerplexityBot",
    "Google-Extended", "CCBot", "Bytespider",
    "Applebot-Extended",
]

# Plattform-Footprints (Order = Priorität)
PLATFORM_SIGNATURES = [
    ("shopify", [
        r"cdn\.shopify\.com",
        r"Shopify\.theme",
        r"shopify-section",
        r"\.myshopify\.com",
        r"shopify-payment-button",
    ]),
    ("woocommerce", [
        r"woocommerce",
        r"wc-block",
        r"/wp-content/plugins/woocommerce",
        r"WooCommerce",
    ]),
    ("shopware", [
        r"shopware",
        r"/bundles/storefront/",
        r"sw-cms-element",
        r"sw-product-detail",
    ]),
    ("magento", [
        r"Mage\.",
        r"/static/version\d+/",
        r"data-mage-init",
        r"magento",
    ]),
    ("bigcommerce", [
        r"bigcommerce",
        r"cdn\.bcapp\.dev",
    ]),
    ("prestashop", [
        r"prestashop",
        r"PrestaShop",
    ]),
    ("squarespace", [
        r"squarespace",
        r"Static\.SQUARESPACE_CONTEXT",
    ]),
    ("wix", [
        r"wix\.com",
        r"static\.wixstatic\.com",
    ]),
    ("jtl", [
        r"jtl-shop",
        r"JTL-Shop",
    ]),
    ("oxid", [
        r"oxid",
        r"OXID",
    ]),
]

PRICE_PATTERNS_DE = [
    r"(\d{1,3}(?:[\.\s]\d{3})*(?:,\d{2})?)\s*€",
    r"€\s*(\d{1,3}(?:[\.\s]\d{3})*(?:,\d{2})?)",
    r"EUR\s*(\d{1,3}(?:[\.\s]\d{3})*(?:,\d{2})?)",
]
PRICE_PATTERNS_EN = [
    r"\$\s*(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)",
    r"USD\s*(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)",
    r"£\s*(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)",
]

AVAILABILITY_KEYWORDS_DE = {
    "InStock": [r"auf lager", r"sofort lieferbar", r"verfügbar", r"lagernd", r"versandfertig"],
    "OutOfStock": [r"ausverkauft", r"nicht verfügbar", r"nicht lieferbar", r"vergriffen"],
    "PreOrder": [r"vorbestellbar", r"vorbestellung", r"pre[\s\-]?order"],
    "BackOrder": [r"lieferbar in", r"nachbestellung", r"vorrätig in"],
}

ADD_TO_CART_PATTERNS = [
    r"in den warenkorb",
    r"add to cart",
    r"zum warenkorb hinzufügen",
    r"jetzt kaufen",
    r"buy now",
    r"in den korb",
]

GERMAN_FILLER_PATTERNS = [
    r"\bhochwertige verarbeitung\b",
    r"\bhöchste qualität\b",
    r"\binnovative technologie\b",
    r"\beinzigartige(s|r|m|n)? \w+\b",
    r"\bgarantiert\b",
    r"\brevolutionär\b",
    r"\bin der heutigen\b",
    r"\bzweifellos\b",
]

W_FRAGEWORTE = ["was", "wer", "wie", "wo", "wann", "warum", "welche", "welcher", "welches", "wofür"]


# ----------------------------------------------------------------------------
# Fetcher
# ----------------------------------------------------------------------------

def fetch_with_playwright(url: str, timeout: int) -> dict[str, Any] | None:
    if not _ensure_pkg("playwright"):
        return None
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
            try:
                page.wait_for_load_state("networkidle", timeout=10000)
            except Exception:
                pass
            if response is None:
                browser.close()
                return None
            data = {
                "renderer": "playwright",
                "status_code": response.status,
                "final_url": page.url,
                "headers": dict(response.headers),
                "html": page.content(),
                "ttfb_ms": round(ttfb_ms, 1),
            }
            browser.close()
            return data
    except Exception as e:
        print(f"[warn] playwright failed: {e}", file=sys.stderr)
        return None


def fetch_with_requests(url: str, timeout: int) -> dict[str, Any] | None:
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
# robots.txt + Domain-level Daten
# ----------------------------------------------------------------------------

def fetch_robots_txt(base_url: str, timeout: int = 15) -> dict[str, Any]:
    parsed = urlparse(base_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    result = {
        "url": robots_url, "fetched": False, "status_code": None, "raw": "",
        "sitemaps": [], "ai_crawler_status": {}, "blocks": [],
    }
    try:
        resp = requests.get(robots_url, headers={"User-Agent": USER_AGENT}, timeout=timeout)
        result["status_code"] = resp.status_code
        if resp.status_code == 200:
            result["fetched"] = True
            result["raw"] = resp.text
            parsed_robots = parse_robots_txt(resp.text)
            result.update(parsed_robots)
    except Exception as e:
        print(f"[warn] robots.txt fetch failed: {e}", file=sys.stderr)

    for crawler in AI_CRAWLERS:
        result["ai_crawler_status"][crawler] = check_crawler_allowed(
            result.get("blocks", []), crawler, parsed.path or "/"
        )
    return result


def parse_robots_txt(text: str) -> dict[str, Any]:
    blocks: list[dict[str, Any]] = []
    sitemaps: list[str] = []
    current: dict[str, Any] | None = None
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        directive, _, value = line.partition(":")
        directive = directive.strip().lower()
        value = value.strip()
        if directive == "user-agent":
            if current and current.get("agents") and not current.get("rules"):
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
    crawler_lower = crawler.lower()
    matching, wildcard = [], None
    for block in blocks:
        agents_lower = [a.lower() for a in block.get("agents", [])]
        if any(crawler_lower == a or crawler_lower in a for a in agents_lower):
            matching.append(block)
        if "*" in agents_lower:
            wildcard = block
    target = matching[0] if matching else wildcard
    if target is None:
        return {"allowed": True, "reason": "no_directive"}
    matched_rule, matched_len = None, -1
    for rule in target.get("rules", []):
        rp = rule["path"]
        if rp == "":
            if rule["type"] == "disallow" and matched_len < 0:
                matched_rule = {"type": "allow", "path": ""}
                matched_len = 0
            continue
        check_path = rp.replace("*", "")
        if path.startswith(check_path):
            if len(rp) > matched_len:
                matched_rule = rule
                matched_len = len(rp)
    if matched_rule is None:
        return {"allowed": True, "reason": "no_matching_rule"}
    if matched_rule["type"] == "disallow":
        return {"allowed": False, "reason": f"disallow:{matched_rule['path']}",
                "block_specific": target in matching}
    return {"allowed": True, "reason": f"allow:{matched_rule['path']}"}


def check_llms_txt(base_url: str, timeout: int = 10) -> dict[str, Any]:
    parsed = urlparse(base_url)
    llms_url = f"{parsed.scheme}://{parsed.netloc}/llms.txt"
    try:
        resp = requests.head(llms_url, headers={"User-Agent": USER_AGENT}, timeout=timeout, allow_redirects=True)
        return {"url": llms_url, "exists": resp.status_code == 200, "status_code": resp.status_code}
    except Exception:
        return {"url": llms_url, "exists": False, "status_code": None}


# ----------------------------------------------------------------------------
# Plattform-Erkennung
# ----------------------------------------------------------------------------

def detect_platform(html: str, headers: dict[str, str]) -> dict[str, Any]:
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # Header-basierte Erkennung
    powered_by = headers_lower.get("x-powered-by", "").lower()
    server = headers_lower.get("server", "").lower()
    shopid = headers_lower.get("x-shopid")

    if shopid or "shopify" in headers_lower.get("x-shardid", "").lower():
        return {"name": "shopify", "confidence": "high", "indicators": ["header:x-shopid"]}

    indicators_per_platform: dict[str, list[str]] = {}
    for platform, patterns in PLATFORM_SIGNATURES:
        hits = []
        for pattern in patterns:
            if re.search(pattern, html, re.IGNORECASE):
                hits.append(pattern)
        if hits:
            indicators_per_platform[platform] = hits

    if powered_by:
        for platform, _ in PLATFORM_SIGNATURES:
            if platform in powered_by:
                indicators_per_platform.setdefault(platform, []).append(f"header:x-powered-by={powered_by}")

    if not indicators_per_platform:
        return {"name": "unknown", "confidence": "none", "indicators": []}

    sorted_platforms = sorted(indicators_per_platform.items(), key=lambda x: len(x[1]), reverse=True)
    top_name, top_indicators = sorted_platforms[0]
    confidence = "high" if len(top_indicators) >= 3 else "medium" if len(top_indicators) >= 2 else "low"
    return {
        "name": top_name,
        "confidence": confidence,
        "indicators": top_indicators[:5],
        "alternatives": [p for p, _ in sorted_platforms[1:3]],
    }


# ----------------------------------------------------------------------------
# Schema-Extraktion (JSON-LD + Microdata)
# ----------------------------------------------------------------------------

def extract_schema(soup: BeautifulSoup) -> dict[str, Any]:
    json_ld_blocks, json_ld_errors = [], []
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

    # Product-Schema isolieren (häufigster Fall: Product oder ProductGroup)
    product_schema = _find_first_product_schema(json_ld_blocks)

    microdata_product = _extract_microdata_product(soup)

    return {
        "json_ld_count": len(json_ld_blocks),
        "json_ld_types": types_found,
        "json_ld_errors": json_ld_errors,
        "blocks": json_ld_blocks,
        "product_schema": product_schema,
        "microdata_product_present": microdata_product["present"],
        "microdata_product_data": microdata_product["data"],
    }


def _extract_schema_types(data: Any) -> list[str]:
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


def _find_first_product_schema(blocks: list[Any]) -> dict[str, Any] | None:
    """Findet das erste Product- oder ProductGroup-Schema und extrahiert Kernfelder."""
    for block in blocks:
        result = _search_product_in_block(block)
        if result:
            return _parse_product_schema(result)
    return None


def _search_product_in_block(block: Any) -> dict[str, Any] | None:
    if isinstance(block, dict):
        t = block.get("@type")
        types = [t] if isinstance(t, str) else (t if isinstance(t, list) else [])
        for ty in types:
            if isinstance(ty, str) and ty.lower() in ("product", "productgroup"):
                return block
        if "@graph" in block and isinstance(block["@graph"], list):
            for item in block["@graph"]:
                found = _search_product_in_block(item)
                if found:
                    return found
        for v in block.values():
            if isinstance(v, (dict, list)):
                found = _search_product_in_block(v)
                if found:
                    return found
    elif isinstance(block, list):
        for item in block:
            found = _search_product_in_block(item)
            if found:
                return found
    return None


def _parse_product_schema(p: dict[str, Any]) -> dict[str, Any]:
    """Extrahiert die wichtigen Felder aus einem Product-Schema."""
    parsed = {
        "raw": p,
        "type": p.get("@type"),
        "name": p.get("name"),
        "description": p.get("description"),
        "sku": p.get("sku"),
        "mpn": p.get("mpn"),
        "gtin": p.get("gtin13") or p.get("gtin12") or p.get("gtin8") or p.get("gtin14") or p.get("gtin"),
        "image": p.get("image"),
        "url": p.get("url"),
        "category": p.get("category"),
        "brand": _extract_brand(p.get("brand")),
        "offers": _extract_offers(p.get("offers")),
        "aggregateRating": _extract_aggregate_rating(p.get("aggregateRating")),
        "review_count_inline": _count_reviews(p.get("review")),
        "has_variants": isinstance(p.get("hasVariant"), list) and len(p.get("hasVariant", [])) > 0,
        "variant_count": len(p.get("hasVariant", [])) if isinstance(p.get("hasVariant"), list) else 0,
        "color": p.get("color"),
        "material": p.get("material"),
        "weight": p.get("weight"),
    }
    images = parsed["image"]
    if isinstance(images, str):
        parsed["image_count"] = 1
    elif isinstance(images, list):
        parsed["image_count"] = len(images)
    else:
        parsed["image_count"] = 0

    return parsed


def _extract_brand(brand_data: Any) -> dict[str, Any]:
    if brand_data is None:
        return {"present": False}
    if isinstance(brand_data, str):
        return {"present": True, "type": "string", "name": brand_data}
    if isinstance(brand_data, dict):
        return {
            "present": True,
            "type": "object",
            "schema_type": brand_data.get("@type"),
            "name": brand_data.get("name"),
            "sameAs": brand_data.get("sameAs"),
            "url": brand_data.get("url"),
        }
    return {"present": True, "type": "unknown"}


def _extract_offers(offers_data: Any) -> dict[str, Any]:
    if offers_data is None:
        return {"present": False}
    offer = offers_data[0] if isinstance(offers_data, list) and offers_data else offers_data
    if not isinstance(offer, dict):
        return {"present": False}
    return {
        "present": True,
        "schema_type": offer.get("@type"),
        "price": offer.get("price") or offer.get("lowPrice"),
        "priceCurrency": offer.get("priceCurrency"),
        "priceValidUntil": offer.get("priceValidUntil"),
        "availability": offer.get("availability"),
        "itemCondition": offer.get("itemCondition"),
        "has_merchantReturnPolicy": "hasMerchantReturnPolicy" in offer,
        "has_shippingDetails": "shippingDetails" in offer,
        "url": offer.get("url"),
        "seller_present": "seller" in offer,
    }


def _extract_aggregate_rating(rating: Any) -> dict[str, Any]:
    if not isinstance(rating, dict):
        return {"present": False}
    return {
        "present": True,
        "ratingValue": rating.get("ratingValue"),
        "reviewCount": rating.get("reviewCount") or rating.get("ratingCount"),
        "bestRating": rating.get("bestRating"),
        "worstRating": rating.get("worstRating"),
    }


def _count_reviews(review_data: Any) -> int:
    if isinstance(review_data, list):
        return len(review_data)
    if isinstance(review_data, dict):
        return 1
    return 0


def _extract_microdata_product(soup: BeautifulSoup) -> dict[str, Any]:
    elem = soup.find(attrs={"itemtype": re.compile(r"schema\.org/Product", re.I)})
    if not elem:
        return {"present": False, "data": {}}
    data = {}
    for prop in elem.find_all(attrs={"itemprop": True}):
        key = prop["itemprop"]
        if prop.name == "meta":
            data[key] = prop.get("content")
        elif prop.name in ("img", "source"):
            data[key] = prop.get("src") or prop.get("content")
        elif prop.name == "link":
            data[key] = prop.get("href")
        else:
            data[key] = prop.get("content") or prop.get_text(strip=True)
    return {"present": True, "data": data}


# ----------------------------------------------------------------------------
# PDP-spezifische DOM-Analyse
# ----------------------------------------------------------------------------

def analyze_pdp_dom(soup: BeautifulSoup, html: str) -> dict[str, Any]:
    """E-Commerce-spezifische Signale aus dem DOM."""
    pdp = {}

    # Add-to-Cart Button
    body_lower = soup.get_text(separator=" ").lower()
    pdp["add_to_cart_visible"] = any(re.search(p, body_lower) for p in ADD_TO_CART_PATTERNS)
    pdp["add_to_cart_buttons"] = _count_buttons_with_text(soup, ADD_TO_CART_PATTERNS)

    # Preis im DOM (heuristisch für DE)
    pdp["price_signals"] = _extract_price_signals(soup, html)

    # Verfügbarkeit
    pdp["availability_signals"] = _extract_availability_signals(body_lower)

    # Reviews/Sterne
    pdp["review_signals"] = _extract_review_signals(soup, body_lower)

    # Variants
    pdp["variant_signals"] = _extract_variant_signals(soup, body_lower)

    # Trust-Signale
    pdp["trust_signals"] = _extract_trust_signals(soup, body_lower)

    # Versand-/Rückgabe-Hinweise im Text
    pdp["shipping_visible"] = bool(re.search(r"versand|lieferzeit|lieferung|shipping|delivery", body_lower))
    pdp["returns_visible"] = bool(re.search(r"rückgabe|widerruf|return policy|rücksendung|umtausch", body_lower))

    # Spec-Tabelle
    pdp["spec_table"] = _detect_spec_table(soup)

    # Breadcrumb
    pdp["breadcrumb_visible"] = _detect_breadcrumb(soup)

    return pdp


def _count_buttons_with_text(soup: BeautifulSoup, patterns: list[str]) -> int:
    count = 0
    for btn in soup.find_all(["button", "a", "input"]):
        if btn.name == "input" and btn.get("type") not in ("submit", "button"):
            continue
        text = (btn.get_text(strip=True) or btn.get("value", "")).lower()
        if any(re.search(p, text) for p in patterns):
            count += 1
    return count


def _extract_price_signals(soup: BeautifulSoup, html: str) -> dict[str, Any]:
    # Versuch 1: Microdata/itemprop
    price_elem = soup.find(attrs={"itemprop": "price"})
    microdata_price = price_elem.get("content") or price_elem.get_text(strip=True) if price_elem else None

    # Versuch 2: Meta og:price oder product:price
    og_price = None
    for meta in soup.find_all("meta"):
        prop = (meta.get("property") or meta.get("name") or "").lower()
        if prop in ("og:price:amount", "product:price:amount", "twitter:data1"):
            og_price = meta.get("content")
            break

    # Versuch 3: Regex im sichtbaren Text
    text_prices = []
    body_text = soup.get_text(separator=" ")
    for pat in PRICE_PATTERNS_DE + PRICE_PATTERNS_EN:
        for m in re.finditer(pat, body_text):
            text_prices.append(m.group(0).strip())
            if len(text_prices) >= 5:
                break

    return {
        "microdata_price": microdata_price,
        "og_price_amount": og_price,
        "text_price_examples": text_prices[:5],
        "any_price_visible": bool(microdata_price or og_price or text_prices),
    }


def _extract_availability_signals(body_lower: str) -> dict[str, Any]:
    detected = []
    for status, patterns in AVAILABILITY_KEYWORDS_DE.items():
        if any(re.search(p, body_lower) for p in patterns):
            detected.append(status)
    return {
        "detected": detected,
        "primary": detected[0] if detected else None,
    }


def _extract_review_signals(soup: BeautifulSoup, body_lower: str) -> dict[str, Any]:
    # Star ratings im DOM
    star_elements = soup.find_all(class_=re.compile(r"(rating|star|sterne)", re.I))
    review_count_match = re.search(r"(\d+)\s*(bewertungen|reviews|kundenbewertungen)", body_lower)
    aggregate_inline = soup.find(attrs={"itemprop": "aggregateRating"})

    return {
        "rating_dom_elements": len(star_elements),
        "review_count_text_match": review_count_match.group(1) if review_count_match else None,
        "review_count_text_full": review_count_match.group(0) if review_count_match else None,
        "microdata_aggregateRating_present": aggregate_inline is not None,
        "review_text_indicators": bool(re.search(r"\b(rezension|bewertung|review|kundenmeinung)\b", body_lower)),
    }


def _extract_variant_signals(soup: BeautifulSoup, body_lower: str) -> dict[str, Any]:
    # Variant-Selektoren
    selects = soup.find_all("select")
    variant_selects = [s for s in selects if re.search(r"(color|farbe|size|größe|variant)", str(s.get("name", "")) + str(s.get("id", "")), re.I)]

    # Radio Buttons
    radio_groups = set()
    for r in soup.find_all("input", type="radio"):
        name = r.get("name", "")
        if re.search(r"(color|farbe|size|größe|variant)", name, re.I):
            radio_groups.add(name)

    return {
        "variant_select_count": len(variant_selects),
        "variant_radio_groups": len(radio_groups),
        "has_variant_ui": len(variant_selects) + len(radio_groups) > 0,
    }


def _extract_trust_signals(soup: BeautifulSoup, body_lower: str) -> dict[str, Any]:
    indicators = {
        "trusted_shops": bool(re.search(r"trusted\s*shops", body_lower)),
        "kaeuferschutz": bool(re.search(r"käuferschutz|buyer protection", body_lower)),
        "sicheres_einkaufen": bool(re.search(r"sicheres? einkaufen|secure shopping|ssl|https", body_lower)),
        "ekomi": bool(re.search(r"ekomi", body_lower)),
        "tüv_süd": bool(re.search(r"tüv süd|tüv süd s@fer", body_lower)),
        "money_back": bool(re.search(r"geld[\s\-]?zurück|money[\s\-]?back", body_lower)),
    }

    # Zahlungsmethoden im Footer (Heuristik)
    payment_methods = []
    for method in ["paypal", "klarna", "visa", "mastercard", "american express", "amex", "sofort", "apple pay", "google pay", "kreditkarte", "rechnung", "vorkasse", "lastschrift", "sepa"]:
        if re.search(rf"\b{re.escape(method)}\b", body_lower):
            payment_methods.append(method)

    # Footer-Indikatoren
    footer = soup.find("footer")
    footer_text = footer.get_text(separator=" ").lower() if footer else ""
    indicators["impressum_link"] = bool(re.search(r"\bimpressum\b", footer_text)) or bool(soup.find("a", string=re.compile("impressum", re.I)))
    indicators["agb_link"] = bool(re.search(r"\bagb\b", footer_text)) or bool(soup.find("a", string=re.compile("agb|allgemeine geschäftsbedingungen", re.I)))
    indicators["datenschutz_link"] = bool(re.search(r"\bdatenschutz\b", footer_text)) or bool(soup.find("a", string=re.compile("datenschutz", re.I)))

    indicators["payment_methods_visible"] = payment_methods
    indicators["payment_methods_count"] = len(payment_methods)

    return indicators


def _detect_spec_table(soup: BeautifulSoup) -> dict[str, Any]:
    tables = soup.find_all("table")
    spec_tables = []
    for t in tables:
        rows = t.find_all("tr")
        if len(rows) < 3:
            continue
        # Heuristik: Tabelle mit zwei Spalten und Wörter wie "Material", "Gewicht", "Maße"
        text = t.get_text(" ").lower()
        spec_score = sum(1 for w in ["material", "gewicht", "maße", "größe", "farbe", "marke", "modell", "garantie", "lieferumfang", "weight", "size", "dimensions", "warranty"] if w in text)
        if spec_score >= 2:
            spec_tables.append({"row_count": len(rows), "spec_score": spec_score})
    return {
        "spec_tables_found": len(spec_tables),
        "best_spec_table": spec_tables[0] if spec_tables else None,
        "any_table": len(tables) > 0,
        "table_count": len(tables),
    }


def _detect_breadcrumb(soup: BeautifulSoup) -> bool:
    if soup.find(attrs={"itemtype": re.compile(r"BreadcrumbList", re.I)}):
        return True
    breadcrumb_classes = soup.find_all(class_=re.compile(r"breadcrumb", re.I))
    if breadcrumb_classes:
        return True
    if soup.find("nav", attrs={"aria-label": re.compile(r"breadcrumb", re.I)}):
        return True
    return False


# ----------------------------------------------------------------------------
# Allgemeine HTML-Analyse (Title, Meta, Headings, Bilder, Links)
# ----------------------------------------------------------------------------

def analyze_general(soup: BeautifulSoup, html: str, base_url: str) -> dict[str, Any]:
    result: dict[str, Any] = {}

    html_tag = soup.find("html")
    result["lang"] = (html_tag.get("lang") if html_tag else None) or None

    title_tag = soup.find("title")
    title_text = (title_tag.text.strip() if title_tag else "") or ""
    result["title"] = {"text": title_text, "length": len(title_text)}

    meta_desc = soup.find("meta", attrs={"name": "description"})
    desc_text = (meta_desc.get("content", "").strip() if meta_desc else "") or ""
    result["meta_description"] = {"text": desc_text, "length": len(desc_text)}

    canonical = soup.find("link", attrs={"rel": "canonical"})
    result["canonical"] = canonical.get("href") if canonical else None

    meta_robots = soup.find("meta", attrs={"name": re.compile("^robots$", re.I)})
    result["meta_robots"] = (meta_robots.get("content", "").lower() if meta_robots else "")

    viewport = soup.find("meta", attrs={"name": "viewport"})
    result["viewport"] = viewport.get("content") if viewport else None

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

    hreflang_tags = soup.find_all("link", attrs={"rel": "alternate", "hreflang": True})
    result["hreflang"] = [{"hreflang": t.get("hreflang"), "href": t.get("href")} for t in hreflang_tags]

    og_tags = {}
    for tag in soup.find_all("meta", attrs={"property": re.compile("^og:", re.I)}):
        og_tags[tag["property"].lower()] = tag.get("content", "")
    result["open_graph"] = og_tags

    tw_tags = {}
    for tag in soup.find_all("meta", attrs={"name": re.compile("^twitter:", re.I)}):
        tw_tags[tag["name"].lower()] = tag.get("content", "")
    result["twitter_card"] = tw_tags

    headings = {f"h{i}": [] for i in range(1, 7)}
    heading_order = []
    for level in range(1, 7):
        for h in soup.find_all(f"h{level}"):
            text = h.get_text(strip=True)
            if text:
                headings[f"h{level}"].append(text)
                heading_order.append((level, text))
    result["headings"] = headings
    result["heading_jumps"] = _count_heading_jumps(heading_order)

    body_text = _extract_body_text(soup)
    result["text"] = {"raw_length": len(body_text), "word_count": _count_words(body_text)}
    result["readability"] = _calc_readability(body_text, result["lang"] or "de")

    # Filler-Phrasen
    body_lower = body_text.lower()
    fillers = []
    for pat in GERMAN_FILLER_PATTERNS:
        hits = re.findall(pat, body_lower)
        if hits:
            fillers.append({"pattern": pat, "count": len(hits)})
    result["filler_phrases"] = fillers

    # Bilder
    result["images"] = _analyze_images(soup, base_url)

    # Links
    result["links"] = _analyze_links(soup, base_url)

    # Absatz-Verteilung für Citability
    result["paragraph_lengths"] = _paragraph_distribution(soup)

    # FAQ-Heuristik
    result["faq_heuristic"] = _detect_faq(soup)

    # Sektionen mit H3 für PDP-Subsektionen
    result["h3_sections"] = _analyze_h3_sections(soup)

    return result


def _count_heading_jumps(order: list[tuple[int, str]]) -> int:
    if not order:
        return 0
    jumps = 0
    prev = order[0][0]
    for level, _ in order[1:]:
        if level > prev + 1:
            jumps += 1
        prev = level
    return jumps


def _extract_body_text(soup: BeautifulSoup) -> str:
    # Wichtig: nicht den Original-DOM mutieren (.decompose() würde script-Tags zerstören
    # und damit JSON-LD-Schemas entfernen, falls extract_schema später läuft).
    # Stattdessen Soup neu parsen und auf der Kopie arbeiten.
    parser_kind = "lxml" if _HAS_LXML else "html.parser"
    soup_copy = BeautifulSoup(str(soup), parser_kind)
    for tag in soup_copy(["script", "style", "noscript", "template"]):
        tag.decompose()
    main = soup_copy.find("main") or soup_copy.find("article") or soup_copy.body or soup_copy
    return re.sub(r"\s+", " ", main.get_text(separator=" ", strip=True))


def _count_words(text: str) -> int:
    return len(re.findall(r"\b[\w'\-äöüÄÖÜß]+\b", text)) if text else 0


def _calc_readability(text: str, lang: str) -> dict[str, Any]:
    if not text or len(text) < 100:
        return {"score": None, "method": "insufficient_text"}
    sentences = [s.strip() for s in re.split(r"[.!?]+", text) if s.strip()]
    n_sent = len(sentences) or 1
    words = re.findall(r"\b[\w'\-äöüÄÖÜß]+\b", text)
    n_words = len(words) or 1
    syllables = sum(_syllables_de(w) for w in words)
    asl = n_words / n_sent
    asw = syllables / n_words
    is_de = (lang or "").lower().startswith("de")
    if is_de:
        score = 180 - asl - (58.5 * asw)
        method = "flesch_amstad_de"
    else:
        score = 206.835 - 1.015 * asl - 84.6 * asw
        method = "flesch_en"
    score = max(0.0, min(100.0, score))
    return {"score": round(score, 1), "method": method, "n_sentences": n_sent, "n_words": n_words}


def _syllables_de(word: str) -> int:
    word = unicodedata.normalize("NFC", word.lower())
    if len(word) <= 1:
        return 1
    vowels = "aeiouyäöü"
    count, prev = 0, False
    for ch in word:
        is_vowel = ch in vowels
        if is_vowel and not prev:
            count += 1
        prev = is_vowel
    return max(1, count)


def _analyze_images(soup: BeautifulSoup, base_url: str) -> dict[str, Any]:
    imgs = soup.find_all("img")
    n = len(imgs)
    if n == 0:
        return {"count": 0, "with_alt": 0, "alt_coverage": 0, "with_dims": 0,
                "lazy": 0, "modern": 0, "examples": []}
    with_alt = descriptive = with_dims = lazy = modern = 0
    examples = []
    aspect_ratios = []
    for img in imgs:
        alt = img.get("alt")
        if alt is not None:
            with_alt += 1
            if len(alt.strip()) >= 8 and not re.match(r"^(image|bild|img|foto)\d*\.?\w*$", alt.strip().lower()):
                descriptive += 1
        w = img.get("width")
        h = img.get("height")
        if w and h:
            with_dims += 1
            try:
                wn, hn = int(w), int(h)
                if hn > 0:
                    ratio = wn / hn
                    if 0.95 <= ratio <= 1.05:
                        aspect_ratios.append("1:1")
                    elif 1.25 <= ratio <= 1.4:
                        aspect_ratios.append("4:3")
                    elif 1.7 <= ratio <= 1.85:
                        aspect_ratios.append("16:9")
                    else:
                        aspect_ratios.append("other")
            except ValueError:
                pass
        if img.get("loading", "").lower() == "lazy":
            lazy += 1
        src = img.get("src", "") or img.get("data-src", "") or img.get("srcset", "")
        if re.search(r"\.(webp|avif)(\?|\s|$)", src, re.I):
            modern += 1
        if len(examples) < 5:
            examples.append({"src": urljoin(base_url, img.get("src", "")), "alt": alt})
    aspect_set = set(aspect_ratios)
    return {
        "count": n,
        "with_alt": with_alt,
        "alt_coverage": round(with_alt / n, 3),
        "descriptive_alt": descriptive,
        "descriptive_alt_ratio": round(descriptive / n, 3),
        "with_dims": with_dims,
        "with_dims_ratio": round(with_dims / n, 3),
        "lazy": lazy,
        "lazy_ratio": round(lazy / n, 3),
        "modern": modern,
        "modern_ratio": round(modern / n, 3),
        "aspect_ratios_present": list(aspect_set),
        "multiple_aspect_ratios": len(aspect_set & {"1:1", "4:3", "16:9"}) >= 2,
        "examples": examples,
    }


def _analyze_links(soup: BeautifulSoup, base_url: str) -> dict[str, Any]:
    parsed = urlparse(base_url)
    base_host = parsed.netloc.lower().lstrip("www.")
    internal, external = [], []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        full = urljoin(base_url, href)
        host = urlparse(full).netloc.lower().lstrip("www.")
        if not host:
            continue
        anchor = a.get_text(strip=True)
        if host == base_host or host.endswith("." + base_host):
            internal.append({"href": full, "anchor": anchor})
        else:
            external.append({"href": full, "anchor": anchor})
    return {
        "internal_count": len(internal),
        "external_count": len(external),
        "internal_sample": internal[:8],
        "external_sample": external[:8],
    }


def _paragraph_distribution(soup: BeautifulSoup) -> dict[str, Any]:
    main = soup.find("main") or soup.find("article") or soup.body or soup
    paragraphs = [_count_words(p.get_text()) for p in main.find_all("p")]
    paragraphs = [p for p in paragraphs if p > 0]
    if not paragraphs:
        return {"count": 0, "avg": 0, "in_optimal_80_180": 0, "ratio_optimal": 0}
    optimal = sum(1 for p in paragraphs if 80 <= p <= 180)
    return {
        "count": len(paragraphs),
        "avg": round(sum(paragraphs) / len(paragraphs), 1),
        "in_optimal_80_180": optimal,
        "ratio_optimal": round(optimal / len(paragraphs), 3),
    }


def _detect_faq(soup: BeautifulSoup) -> dict[str, Any]:
    faq_indicators = soup.find_all(string=re.compile(r"(faq|h[äa]ufige fragen|fragen und antworten)", re.I))
    if not faq_indicators:
        return {"detected": False, "questions": 0, "avg_answer_words": None}
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
        "in_optimal_40_80": sum(1 for q in questions if 40 <= q["answer_words"] <= 80),
    }


def _analyze_h3_sections(soup: BeautifulSoup) -> dict[str, Any]:
    h3s = soup.find_all("h3")
    sections_with_content = 0
    for h in h3s:
        following_text_parts = []
        for sib in h.find_all_next():
            if sib.name in ("h1", "h2", "h3"):
                break
            if sib.name in ("p", "li"):
                following_text_parts.append(sib.get_text(strip=True))
            if sum(len(p) for p in following_text_parts) > 1500:
                break
        words = _count_words(" ".join(following_text_parts))
        if words >= 50:
            sections_with_content += 1
    return {
        "h3_total": len(h3s),
        "sections_with_content_ge_50w": sections_with_content,
    }


# ----------------------------------------------------------------------------
# PDP-Confidence: Ist das wirklich eine Produktseite?
# ----------------------------------------------------------------------------

def is_pdp(general: dict[str, Any], schema: dict[str, Any], pdp_dom: dict[str, Any], url: str) -> dict[str, Any]:
    """Heuristische Prüfung, ob die URL eine PDP ist."""
    indicators = []
    score = 0

    if schema.get("product_schema"):
        score += 50
        indicators.append("schema:Product/ProductGroup")
    if schema.get("microdata_product_present"):
        score += 30
        indicators.append("microdata:Product")

    if pdp_dom.get("add_to_cart_visible"):
        score += 20
        indicators.append("dom:add-to-cart-button")
    if pdp_dom.get("price_signals", {}).get("any_price_visible"):
        score += 15
        indicators.append("dom:price-visible")
    if pdp_dom.get("variant_signals", {}).get("has_variant_ui"):
        score += 5
        indicators.append("dom:variant-ui")
    if pdp_dom.get("breadcrumb_visible"):
        score += 5
        indicators.append("dom:breadcrumb")

    path = urlparse(url).path.lower()
    if any(seg in path for seg in ["/product/", "/produkt/", "/products/", "/p/", "/artikel/", "/item/"]):
        score += 10
        indicators.append("path:product-segment")

    return {
        "is_pdp_score": score,
        "is_pdp_likely": score >= 50,
        "is_pdp_certain": score >= 80,
        "indicators": indicators,
    }


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="PDP SEO & GEO Analyzer")
    parser.add_argument("url")
    parser.add_argument("--no-render", action="store_true")
    parser.add_argument("--keyword", default=None)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
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
        print(json.dumps({"error": "fetch_failed", "url": url,
                         "message": "Konnte URL nicht laden."}, ensure_ascii=False, indent=2))
        return 3

    if response_data["status_code"] >= 400:
        print(json.dumps({
            "error": "http_error",
            "status_code": response_data["status_code"],
            "url": url,
            "renderer": response_data["renderer"],
        }, ensure_ascii=False, indent=2))
        return 4

    parser_kind = "lxml" if _HAS_LXML else "html.parser"
    soup = BeautifulSoup(response_data["html"], parser_kind)
    html = response_data["html"]

    output: dict[str, Any] = {
        "url": url,
        "final_url": response_data["final_url"],
        "renderer": response_data["renderer"],
        "status_code": response_data["status_code"],
        "ttfb_ms": response_data["ttfb_ms"],
        "html_size_bytes": len(html.encode("utf-8")),
        "headers": {k.lower(): v for k, v in response_data["headers"].items()
                    if k.lower() in ["content-type", "server", "x-powered-by", "x-shopid", "alt-svc",
                                     "strict-transport-security", "cache-control"]},
    }

    output["platform"] = detect_platform(html, response_data["headers"])
    # WICHTIG: extract_schema und analyze_pdp_dom VOR analyze_general aufrufen,
    # weil _extract_body_text in analyze_general script/style-Tags decomposed (mutiert den DOM).
    output["schema"] = extract_schema(soup)
    output["pdp_dom"] = analyze_pdp_dom(soup, html)
    output["general"] = analyze_general(soup, html, url)
    output["pdp_detection"] = is_pdp(output["general"], output["schema"], output["pdp_dom"], url)
    output["robots_txt"] = fetch_robots_txt(url, args.timeout)
    output["llms_txt"] = check_llms_txt(url)

    if args.keyword:
        kw = args.keyword.lower()
        body = html.lower()
        title = output["general"]["title"]["text"].lower()
        h1s = [h.lower() for h in output["general"]["headings"]["h1"]]
        meta = output["general"]["meta_description"]["text"].lower()
        output["keyword"] = {
            "term": args.keyword,
            "in_title": kw in title,
            "in_title_first_30": kw in title[:30] if title else False,
            "in_h1": any(kw in h for h in h1s),
            "in_meta": kw in meta,
            "occurrences_in_body": body.count(kw),
        }

    print(json.dumps(output, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
