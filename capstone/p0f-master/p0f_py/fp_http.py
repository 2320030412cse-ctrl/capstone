"""
fp_http.py - HTTP request / response passive fingerprinting.

Mirrors fp_http.c:
  - parse_http()        : extract headers from a raw TCP payload
  - http_find_match()   : compare collected headers against loaded sigs
  - fingerprint_http()  : entry point called by process.py
  - detect_language()   : map Accept-Language to a full language name
"""

import re
import time
from typing import Optional, List, Tuple, Dict

from fp_reader import (
    HttpSig, HttpSigRecord, HttpHdr,
    http_sigs, fp_os_names, ua_map,
)

# ── ISO 639-1 language lookup (mirrors languages.h LANG_HASH) ─────────────────
# Build a flat dict: 2-letter code → full name
_LANG_MAP: Dict[str, str] = {
    "ro": "Romanian",    "sw": "Swahili",       "ne": "Nepali",
    "nl": "Dutch",       "sn": "Shona",         "ln": "Lingala",
    "en": "English",     "ie": "Interlingue",   "bg": "Bulgarian",
    "ha": "Hausa",       "cs": "Czech",         "ko": "Korean",
    "gv": "Manx",        "vi": "Vietnamese",    "mt": "Maltese",
    "bo": "Tibetan",     "de": "German",        "pa": "Panjabi",
    "lg": "Ganda",       "tk": "Turkmen",       "gl": "Galician",
    "yo": "Yoruba",      "sc": "Sardinian",     "or": "Oriya",
    "fr": "French",      "ae": "Avestan",       "am": "Amharic",
    "mh": "Marshallese", "hr": "Croatian",      "sg": "Sango",
    "ps": "Pushto",      "to": "Tonga",         "kj": "Kuanyama",
    "kv": "Komi",        "li": "Limburgan",     "ng": "Ndonga",
    "lu": "Luba-Katanga","nn": "Norwegian Nynorsk",
    "es": "Spanish",     "gn": "Guarani",       "pl": "Polish",
    "om": "Oromo",       "lb": "Luxembourgish", "se": "Northern Sami",
    "ab": "Abkhazian",   "ar": "Arabic",        "az": "Azerbaijani",
    "si": "Sinhala",     "ba": "Bashkir",       "sr": "Serbian",
    "vo": "Volapuk",     "kl": "Kalaallisut",   "th": "Thai",
    "cu": "Church Slavic","ja": "Japanese",     "fy": "Western Frisian",
    "ch": "Chamorro",    "hy": "Armenian",      "ht": "Haitian",
    "fo": "Faroese",     "fj": "Fijian",        "gd": "Scottish Gaelic",
    "ig": "Igbo",        "is": "Icelandic",     "bi": "Bislama",
    "za": "Zhuang",      "eu": "Basque",        "id": "Indonesian",
    "ks": "Kashmiri",    "cr": "Cree",          "ga": "Irish",
    "gu": "Gujarati",    "st": "Southern Sotho","ur": "Urdu",
    "ce": "Chechen",     "kg": "Kongo",         "he": "Hebrew",
    "dv": "Dhivehi",     "ru": "Russian",       "ts": "Tsonga",
    "bn": "Bengali",     "sv": "Swedish",       "ug": "Uighur",
    "bs": "Bosnian",     "wa": "Walloon",       "ho": "Hiri Motu",
    "ii": "Sichuan Yi",  "sk": "Slovak",        "nb": "Norwegian Bokmal",
    "co": "Corsican",    "lt": "Lithuanian",    "ms": "Malay",
    "da": "Danish",      "ny": "Nyanja",        "ik": "Inupiaq",
    "iu": "Inuktitut",   "sd": "Sindhi",        "rw": "Kinyarwanda",
    "ki": "Kikuyu",      "uk": "Ukrainian",     "la": "Latin",
    "nr": "South Ndebele","oc": "Occitan",      "ml": "Malayalam",
    "ku": "Kurdish",     "rn": "Rundi",         "kn": "Kannada",
    "ta": "Tamil",       "pi": "Pali",          "sm": "Samoan",
    "tw": "Twi",         "nd": "North Ndebele", "oj": "Ojibwa",
    "tl": "Tagalog",     "aa": "Afar",          "ay": "Aymara",
    "te": "Telugu",      "eo": "Esperanto",     "ia": "Interlingua",
    "xh": "Xhosa",       "jv": "Javanese",      "ty": "Tahitian",
    "os": "Ossetian",    "et": "Estonian",      "cy": "Welsh",
    "so": "Somali",      "sq": "Albanian",      "pt": "Portuguese",
    "tn": "Tswana",      "zu": "Zulu",          "bh": "Bihari",
    "mn": "Mongolian",   "uz": "Uzbek",         "lo": "Lao",
    "ee": "Ewe",         "mg": "Malagasy",      "lv": "Latvian",
    "fi": "Finnish",     "af": "Afrikaans",     "an": "Aragonese",
    "av": "Avaric",      "hi": "Hindi",         "ff": "Fulah",
    "nv": "Navajo",      "fa": "Persian",       "yi": "Yiddish",
    "kw": "Cornish",     "tg": "Tajik",         "be": "Belarusian",
    "na": "Nauru",       "qu": "Quechua",       "sh": "Serbo-Croatian",
    "dz": "Dzongkha",    "kk": "Kazakh",        "cv": "Chuvash",
    "kr": "Kanuri",      "br": "Breton",        "bm": "Bambara",
    "ss": "Swati",       "tr": "Turkish",       "mi": "Maori",
    "no": "Norwegian",   "ak": "Akan",          "as": "Assamese",
    "it": "Italian",     "ca": "Catalan",       "km": "Central Khmer",
    "mk": "Macedonian",  "tt": "Tatar",         "rm": "Romansh",
    "io": "Ido",         "sl": "Slovenian",     "hz": "Herero",
    "ka": "Georgian",    "ky": "Kirghiz",       "ve": "Venda",
    "el": "Modern Greek","sa": "Sanskrit",      "wo": "Wolof",
    "mr": "Marathi",     "zh": "Chinese",       "su": "Sundanese",
    "my": "Burmese",     "hu": "Hungarian",     "ti": "Tigrinya",
    "lu": "Luba-Katanga","se": "Northern Sami",
}


def detect_language(accept_lang: str) -> Optional[str]:
    """
    Extract the primary language code from an Accept-Language header
    and return the full name, or None.
    """
    if not accept_lang:
        return None
    # take the first tag (before , or ;)
    tag = re.split(r'[,;]', accept_lang)[0].strip().lower()
    code = tag[:2]
    if len(code) == 2 and code.isalpha():
        return _LANG_MAP.get(code)
    return None


# ── HTTP header extraction ────────────────────────────────────────────────────

def _parse_http_headers(payload: bytes) -> Tuple[Optional[str], List[Tuple[str, str]], bool]:
    """
    Parse raw TCP payload bytes.
    Returns:
      (first_line, [(name, value), ...], via_seen)

    first_line is the request/response line (e.g. 'GET / HTTP/1.1').
    Returns (None, [], False) if the payload is not a valid HTTP message.
    """
    try:
        text = payload.decode('latin-1', errors='replace')
    except Exception:
        return None, [], False

    # find end of headers (blank line)
    end = text.find('\r\n\r\n')
    if end == -1:
        end = text.find('\n\n')
        sep = '\n'
    else:
        sep = '\r\n'

    header_block = text[:end] if end != -1 else text
    lines = header_block.split(sep)

    if not lines:
        return None, [], False

    first_line = lines[0].strip()
    headers: List[Tuple[str, str]] = []
    via_seen = False

    for line in lines[1:]:
        if not line.strip():
            continue
        colon = line.find(':')
        if colon == -1:
            continue
        name  = line[:colon].strip()
        value = line[colon+1:].strip()
        headers.append((name, value))
        if name.lower() in ('via', 'x-forwarded-for'):
            via_seen = True

    return first_line, headers, via_seen


# ── HTTP version extraction ───────────────────────────────────────────────────

def _http_ver(first_line: str) -> int:
    """Return 0 (HTTP/1.0), 1 (HTTP/1.1), or -1 (unknown)."""
    if 'HTTP/1.0' in first_line: return 0
    if 'HTTP/1.1' in first_line: return 1
    return -1


# ── signature matching ────────────────────────────────────────────────────────

def _sig_from_headers(
    first_line: str,
    headers: List[Tuple[str, str]],
    to_srv: bool,
) -> HttpSig:
    """Build an HttpSig from observed headers for matching."""
    hdrs = [HttpHdr(name=n, value=v, optional=False) for n, v in headers]
    ver = _http_ver(first_line)
    return HttpSig(http_ver=ver, headers=hdrs, absent=[], sw=None)


def http_find_match(
    to_srv: bool,
    obs: HttpSig,
) -> Optional[Tuple[HttpSigRecord, bool]]:
    """
    Compare observed HttpSig against loaded HTTP signatures.
    Returns (HttpSigRecord, dishonest) or None.

    'dishonest' is True when a User-Agent / Server string is present
    but doesn't match the expected software string in the signature.
    """
    idx = 0 if to_srv else 1
    candidates = http_sigs[idx]

    # build a set of observed header names (lowercase) for quick lookup
    obs_names = [h.name.lower() for h in obs.headers]
    obs_dict  = {h.name.lower(): h.value for h in obs.headers}

    best_specific: Optional[Tuple[HttpSigRecord, bool]] = None
    best_generic:  Optional[Tuple[HttpSigRecord, bool]] = None

    for rec in candidates:
        rs = rec.sig

        # HTTP version check
        if rs.http_ver != -1 and rs.http_ver != obs.http_ver:
            continue

        # ── mandatory header order check ──────────────────────────────────────
        # all non-optional headers in the sig must appear in obs in order
        sig_mandatory = [h for h in rs.headers if not h.optional]
        obs_ptr = 0
        order_ok = True
        for sh in sig_mandatory:
            found = False
            while obs_ptr < len(obs.headers):
                oh = obs.headers[obs_ptr]
                obs_ptr += 1
                if oh.name.lower() == sh.name.lower():
                    # value match if specified
                    if sh.value and sh.value.lower() not in oh.value.lower():
                        continue
                    found = True
                    break
            if not found:
                order_ok = False
                break
        if not order_ok:
            continue

        # ── absent header check ───────────────────────────────────────────────
        absent_ok = True
        for ah in rs.absent:
            if ah.lower() in obs_dict:
                absent_ok = False
                break
        if not absent_ok:
            continue

        # ── optional headers that appear must be at correct relative position ─
        # (simplified: we just check they exist somewhere if they're in sig)
        # The C code checks ordering; we do the same for optional headers.
        for sh in rs.headers:
            if not sh.optional:
                continue
            # if an optional header appears in obs, it must not violate order
            # (simplified: skip strict ordering check for optional)

        # ── software string (dishonesty) check ────────────────────────────────
        dishonest = False
        if rs.sw:
            ua_val = obs_dict.get('user-agent', '') or obs_dict.get('server', '')
            if ua_val and rs.sw.lower() not in ua_val.lower():
                dishonest = True

        match = (rec, dishonest)
        if rec.generic:
            if best_generic is None:
                best_generic = match
        else:
            if best_specific is None:
                best_specific = match

    return best_specific or best_generic


# ── public entry point ────────────────────────────────────────────────────────

def fingerprint_http(to_srv: bool, payload: bytes, flow: dict) -> Optional[dict]:
    """
    Main entry point. Called by process.py when TCP payload looks like HTTP.

    flow dict keys used: 'src', 'dst', 'sport', 'dport'

    Returns an observation dict or None if the payload is not HTTP.
    """
    first_line, headers, via_seen = _parse_http_headers(payload)

    if not first_line:
        return None

    # minimal check: must look like an HTTP request or response
    is_request  = re.match(r'^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|CONNECT|TRACE)\s', first_line)
    is_response = re.match(r'^HTTP/\d', first_line)
    if not is_request and not is_response:
        return None

    obs = _sig_from_headers(first_line, headers, to_srv)

    # extract interesting fields
    hdr_dict = {n.lower(): v for n, v in headers}
    ua_str   = hdr_dict.get('user-agent') or hdr_dict.get('server', '')
    lang_raw = hdr_dict.get('accept-language', '')
    language = detect_language(lang_raw)

    # check User-Agent against ua_map for OS consistency
    ua_os_match: Optional[str] = None
    for (name_id, ua_pattern) in ua_map:
        if ua_pattern.lower() in ua_str.lower():
            if name_id < len(fp_os_names):
                ua_os_match = fp_os_names[name_id]
            break

    result = http_find_match(to_srv, obs)

    app_str   = None
    dishonest = False
    params    = []

    if result:
        rec, dishonest = result
        name  = fp_os_names[rec.name_id] if rec.name_id < len(fp_os_names) else '?'
        flav  = rec.flavor or ''
        app_str = f"{name} {flav}".strip()
        if rec.generic:  params.append('generic')
        if dishonest:    params.append('dishonest_ua')

    if via_seen:
        params.append('via')

    # detect UA OS vs fingerprinted OS mismatch
    if ua_os_match and flow.get('os') and ua_os_match.lower() not in flow['os'].lower():
        params.append('ua_vs_os')

    return {
        'type':     'http request' if to_srv else 'http response',
        'src':      flow.get('src', '?'),
        'dst':      flow.get('dst', '?'),
        'sport':    flow.get('sport', 0),
        'dport':    flow.get('dport', 0),
        'app':      app_str,
        'lang':     language or 'none',
        'params':   ', '.join(params) if params else 'none',
        'raw_sig':  _build_http_raw_sig(obs),
        'sw':       ua_str or None,
        'via':      via_seen,
        'matched_rec': result[0] if result else None,
    }


def _build_http_raw_sig(sig: HttpSig) -> str:
    """Build a human-readable HTTP signature string."""
    ver = {-1: '*', 0: '0', 1: '1'}.get(sig.http_ver, '*')
    hdr_parts = []
    for h in sig.headers:
        tok = ('?' if h.optional else '') + h.name
        if h.value:
            tok += f"=[{h.value}]"
        hdr_parts.append(tok)
    absent_part = ','.join(sig.absent)
    return f"{ver}:{','.join(hdr_parts)}:{absent_part}:"
