#!/data/data/com.termux/files/usr/bin/python
"""
OSINT-Shinei v2.0 — Professional Open Source Intelligence Framework

Fontes 100% públicas e legais:
  Pilar 1: Username enumeration com validação anti-falso-positivo
  Pilar 2: Profile scraping (GitHub API, Reddit, Telegram, Chess)
  Pilar 3: Email intelligence (Gravatar, leaks, correlação, dorks)
  Consolidação: dossiê HTML profissional

Cases persistentes. Async total. Zero ruído.

Uso ético: informação PÚBLICA apenas. Sem acesso a sistemas,
sem dados privados, sem nada que exija autorização.
"""

import asyncio
import aiohttp
import json
import re
import html as html_mod
import hashlib
import os
import sys
import time
import argparse
import urllib.parse
from datetime import datetime
from pathlib import Path

# ═══════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════

VERSION = "2.0"
BASE = Path(__file__).resolve().parent
CASES = BASE / "cases"
CASES.mkdir(exist_ok=True)

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8',
}

TIMEOUT = aiohttp.ClientTimeout(total=12)

GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[1;33m'
CYAN = '\033[0;36m'
MAGENTA = '\033[0;35m'
GRAY = '\033[0;90m'
BOLD = '\033[1m'
NC = '\033[0m'

def log(sym, color, msg):
    print(f"  {color}{sym}{NC} {msg}")

# ═══════════════════════════════════════════
#  PLATAFORMAS — com validação dupla
# ═══════════════════════════════════════════
# validate = assinatura que SÓ existe em perfil real
# absent   = assinatura que SÓ existe em perfil inexistente
# weight   = 3 confiável, 2 bom, 1 parcial (marcar como "possível")

PLATFORMS = {
    "GitHub": {
        "url": "https://api.github.com/users/{u}",
        "validate": lambda s, t: s == 200 and '"login"' in t,
        "absent": lambda s, t: s == 404,
        "weight": 3,
    },
    "Steam": {
        "url": "https://steamcommunity.com/id/{u}",
        "validate": lambda s, t: s == 200 and 'profile_header' in t,
        "absent": lambda s, t: s == 200 and 'could not be found' in t,
        "weight": 3,
    },
    "Chess.com": {
        "url": "https://api.chess.com/pub/player/{u}",
        "validate": lambda s, t: s == 200 and '"player_id"' in t,
        "absent": lambda s, t: s == 404,
        "weight": 3,
    },
    "HackerNews": {
        "url": "https://hacker-news.firebaseio.com/v0/user/{u}.json",
        "validate": lambda s, t: s == 200 and '"created"' in t,
        "absent": lambda s, t: s == 404 or 'not found' in t.lower(),
        "weight": 3,
    },
    "GitLab": {
        "url": "https://gitlab.com/api/v4/users?username={u}",
        "validate": lambda s, t: s == 200 and '"username"' in t and t.strip() != '[]',
        "absent": lambda s, t: s == 200 and t.strip() == '[]',
        "weight": 3,
    },
    "Reddit": {
        "url": "https://www.reddit.com/user/{u}/about.json",
        "validate": lambda s, t: s == 200 and '"total_karma"' in t,
        "absent": lambda s, t: s == 404 or 'blocked' in t.lower(),
        "weight": 3,
    },
    "Telegram": {
        "url": "https://t.me/{u}",
        "validate": lambda s, t: s == 200 and 'tgme_page_title' in t and 'tgme_page_extra' in t,
        "absent": lambda s, t: s == 200 and 'If you have Telegram' in t,
        "weight": 2,
    },
    "Keybase": {
        "url": "https://keybase.io/{u}",
        "validate": lambda s, t: s == 200 and 'profile' in t.lower() and 'sorry' not in t.lower(),
        "absent": lambda s, t: s == 404 or 'sorry' in t.lower(),
        "weight": 2,
    },
    "ProtonMail verify": {
        "url": "https:// protonmail.com/does-not-exist-then-remove",  # placeholder removido
        "validate": lambda s, t: False,
        "absent": lambda s, t: True,
        "weight": 0,
    },
}

# Remove placeholder
PLATFORMS.pop("ProtonMail verify", None)

# ═══════════════════════════════════════════
#  CASE — estado persistente
# ═══════════════════════════════════════════

class Case:
    def __init__(self, name):
        self.name = name
        self.created = datetime.now().isoformat()
        self.targets = []
        self.usernames = {}   # username -> {site: {"url":..., "weight":...}}
        self.profiles = {}    # username -> {site: {dados}}
        self.emails = {}      # email -> {gravatar, leaked, breaches, dorks}
        self.notes = []
        self.runs = []

    @property
    def path(self):
        return CASES / self.name

    def save(self):
        self.path.mkdir(parents=True, exist_ok=True)
        data = {
            'name': self.name,
            'created': self.created,
            'updated': datetime.now().isoformat(),
            'targets': self.targets,
            'usernames': self.usernames,
            'profiles': self.profiles,
            'emails': self.emails,
            'notes': self.notes,
            'runs': self.runs,
        }
        (self.path / 'case.json').write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')

    @classmethod
    def load(cls, name):
        p = CASES / name / 'case.json'
        if not p.exists():
            return None
        data = json.loads(p.read_text(encoding='utf-8'))
        c = cls(data['name'])
        c.created = data['created']
        c.targets = data.get('targets', [])
        c.usernames = data.get('usernames', {})
        c.profiles = data.get('profiles', {})
        c.emails = data.get('emails', {})
        c.notes = data.get('notes', [])
        c.runs = data.get('runs', [])
        return c

    def add_note(self, text):
        self.notes.append({'time': datetime.now().isoformat(), 'text': text})

    def classify_target(self, t):
        if t.startswith('email:'):
            return ('email', t[6:])
        if '@' in t and '.' in t:
            return ('email', t)
        return ('username', t)

    # ─── Sumário consolidado ───

    def summary(self):
        L = []
        L.append(f"{BOLD}CASE: {self.name}{NC}")
        L.append(f"Criado: {self.created[:10]} | Targets: {len(self.targets)}")
        total = sum(len(v) for v in self.usernames.values())
        confirmed = sum(1 for u in self.usernames.values()
                        for d in u.values() if d.get('weight', 0) >= 2)
        L.append(f"\n{CYAN}[USERNAMES]{NC} {total} achados, {confirmed} confirmados")
        for user, sites in self.usernames.items():
            L.append(f"  {BOLD}{user}{NC}")
            for site, info in sorted(sites.items(),
                                     key=lambda x: -x[1].get('weight', 0)):
                w = info.get('weight', 0)
                sym = {3: "✓", 2: "≈"}.get(w, "?")
                color = {3: GREEN, 2: YELLOW}.get(w, GRAY)
                L.append(f"    {color}{sym}{NC} {site:14s} [{info.get('weight',0)}] {info.get('url','')}")

        L.append(f"\n{CYAN}[EMAILS]{NC}")
        for email, info in self.emails.items():
            leaked = info.get('leaked')
            badge = f"{RED}LEAKED{NC}" if leaked else f"{GREEN}clean{NC}"
            L.append(f"  {email} [{badge}]")
            if info.get('gravatar_name'):
                L.append(f"    Gravatar: {info['gravatar_name']}")
            if info.get('breaches'):
                L.append(f"    Breaches: {', '.join(info['breaches'])}")

        if self.notes:
            L.append(f"\n{CYAN}[NOTAS]{NC}")
            for n in self.notes:
                L.append(f"  {GRAY}{n['time'][:10]}{NC} {n['text']}")

        return "\n".join(L)


# ═══════════════════════════════════════════
#  FASE 1 — USERNAME ENUMERATION (ASYNC)
# ═══════════════════════════════════════════

async def check_platform(session, name, plat, username):
    url = plat['url'].format(u=username)
    try:
        async with session.get(url, timeout=TIMEOUT,
                              allow_redirects=plat.get('follow', True)) as r:
            text = await r.text()
            if plat['validate'](r.status, text):
                return name, {"url": url.split('?')[0],
                             "weight": plat['weight'],
                             "found": True}
            elif plat['absent'](r.status, text):
                return name, {"found": False, "weight": 0}
            else:
                return name, {"found": False, "weight": 0, "ambiguous": True}
    except (asyncio.TimeoutError, aiohttp.ClientError):
        return name, {"found": False, "weight": 0, "error": True}


async def phase_username_async(username):
    """Testa todas as plataformas EM PARALELO"""
    conn = aiohttp.TCPConnector(limit=10)
    async with aiohttp.ClientSession(connector=conn, headers=HEADERS) as session:
        tasks = [check_platform(session, name, plat, username)
                 for name, plat in PLATFORMS.items()]
        results = await asyncio.gather(*tasks)

    found = {}
    for name, info in results:
        if info.get('found'):
            found[name] = {
                "url": info['url'],
                "weight": info['weight'],
            }
            w = info['weight']
            sym = {3: "✓", 2: "≈"}.get(w, "?")
            color = {3: GREEN, 2: YELLOW}.get(w, GRAY)
            log(sym, color, f"{name:14s} [{w}] {info['url']}")
        elif info.get('ambiguous'):
            log("?", GRAY, f"{name:14s} resposta ambígua (verificar manual)")
        elif info.get('error'):
            log("!", RED, f"{name:14s} erro de rede")
        else:
            log("✗", GRAY, f"{name:14s}")
    return found


# ═══════════════════════════════════════════
#  FASE 2 — PROFILE SCRAPING (só fontes confiáveis)
# ═══════════════════════════════════════════

def scrape_github(username):
    r = requests_sync(f"https://api.github.com/users/{username}")
    if not r: return None
    d = r
    email = d.get("email")
    return {
        "name": d.get("name"), "bio": d.get("bio"),
        "followers": d.get("followers"),
        "repos": d.get("public_repos"),
        "location": d.get("location"),
        "email": email,
        "created": (d.get("created_at") or "")[:10],
        "blog": d.get("blog") or None,
        "twitter": d.get("twitter_username"),
    }

def scrape_reddit(username):
    r = requests_sync(f"https://www.reddit.com/user/{username}/about.json")
    if not r: return None
    d = r.get("data", {})
    return {
        "karma": d.get("total_karma"),
        "created": datetime.fromtimestamp(d.get("created_utc", 0)).isoformat()[:10],
        "verified": d.get("verified"),
        "icon": d.get("icon_img") or None,
    }

def scrape_telegram(username):
    r = requests_sync(f"https://t.me/{username}", raw=True)
    if not r: return None
    info = {}
    m = re.search(r'tgme_page_extra">([^<]+)<', r)
    if m: info["handle_extra"] = m.group(1)
    m = re.search(r'tgme_page_description">(.*?)</div>', r, re.DOTALL)
    if m:
        clean = html_mod.unescape(re.sub(r'<[^>]+>', '', m.group(1)))
        info["description"] = clean[:300]
    m = re.search(r'tgme_page_title[^>]*>(?:<[^>]+>)*([^<]+)', r)
    if m: info["title"] = m.group(1).strip()
    return info if info else None

def scrape_chess(username):
    r = requests_sync(f"https://api.chess.com/pub/player/{username}")
    if not r: return None
    return {
        "name": r.get("name"), "country": (r.get("country") or "").split("/")[-1],
        "joined": datetime.fromtimestamp(r.get("joined", 0)).isoformat()[:10]
                  if r.get("joined") else None,
        "followers": r.get("followers"),
        "status": r.get("status"),
    }

def scrape_hn(username):
    r = requests_sync(f"https://hacker-news.firebaseio.com/v0/user/{username}.json")
    if not r: return None
    return {
        "karma": r.get("karma"),
        "created": datetime.fromtimestamp(r.get("created", 0)).isoformat()[:10],
        "about": (r.get("about") or "")[:200] or None,
    }

def requests_sync(url, raw=False):
    """Sync wrapper pra scrapers simples (roda em thread do async)"""
    import requests as rq
    try:
        r = rq.get(url, headers=HEADERS, timeout=10)
        if r.status_code != 200:
            return None
        return r.text if raw else r.json()
    except rq.exceptions.RequestException:
        return None


async def phase_profiles_async(case, username):
    print(f"\n{MAGENTA}═══ FASE 2 — PROFILE SCRAPING: {username} ═══{NC}")
    sites = case.usernames.get(username, {})
    profiles = {}

    loop = asyncio.get_event_loop()

    scrapers = {
        "GitHub": scrape_github,
        "Reddit": scrape_reddit,
        "Telegram": scrape_telegram,
        "Chess.com": scrape_chess,
        "HackerNews": scrape_hn,
    }

    for site, fn in scrapers.items():
        if site not in sites:
            continue
        log("*", CYAN, f"{site}...")
        try:
            data = await loop.run_in_executor(None, fn, username)
            if data:
                profiles[site] = data
                log("+", GREEN, f"{site}: dados extraídos")
                # Emails do GitHub alimentam fase 3
                if site == "GitHub" and data.get("email"):
                    em = data["email"]
                    if em not in case.emails:
                        case.emails[em] = {"source": "GitHub público"}
                        log("!", YELLOW, f"Email público achado: {em}")
            else:
                log("-", GRAY, f"{site}: sem dados")
        except Exception as ex:
            log("!", RED, f"{site}: {ex}")

    case.profiles[username] = profiles
    return profiles



# ═══════════════════════════════════════════
#  FASE 3 — EMAIL INTELLIGENCE
# ═══════════════════════════════════════════

def gravatar_check_sync(email):
    """Gravatar: se perfil existe, retorna nome/about públicos"""
    md5 = hashlib.md5(email.encode()).hexdigest()
    r = requests_sync(f"https://www.gravatar.com/{md5}.json")
    if not r:
        return {"exists": False}
    entry = r.get("entry", [])
    if entry:
        e = entry[0]
        return {
            "exists": True,
            "name": e.get("displayName"),
            "about": (e.get("aboutMe") or "")[:200] or None,
            "hash": md5,
            "avatar_url": f"https://www.gravatar.com/avatar/{md5}",
        }
    return {"exists": False}


def leak_check_sync(email):
    """XposedOrNot: vazou em breach público? Quais?"""
    try:
        r = requests_sync(f"https://api.xposedornot.com/v1/check-email/{email}")
        if not r:
            return {"leaked": False}
        # XposedOrNot retorna {"exposed": "Yes"} ou similar
        if "exposed" in str(r).lower():
            # Busca detalhes dos breaches
            details = requests_sync(
                f"https://api.xposedornot.com/v1/breach-analytics/{email}")
            breaches = []
            if details:
                # Estrutura varia; tenta extrair nomes de breaches
                raw = json.dumps(details)
                breaches = list(set(re.findall(r'"([A-Za-z0-9_.-]{3,30})"', raw)))[:10]
            return {"leaked": True, "breaches": breaches}
        return {"leaked": False}
    except Exception:
        return {"leaked": None}  # None = desconhecido (API fora)


def dorks_for(email, username=None):
    """Dorks de Google indexados — todos legais, só busca pública"""
    user = username or email.split('@')[0]
    domain = email.split('@')[1] if '@' in email else ''
    return {
        "Email exato": f'"{email}"',
        "Pastebin": f'"{email}" (site:pastebin.com OR site:paste.ee OR site:ghostbin.com)',
        "GitHub commits": f'"{email}" site:github.com',
        "Gists": f'"{email}" site:gist.github.com',
        "LinkedIn": f'"{user}" OR "{email}" site:linkedin.com',
        "Docs": f'"{user}" (filetype:pdf OR filetype:doc OR filetype:xls)',
        "Fóruns BR": f'"{user}" (site:reddit.com OR site:brasil.com.br)',
        "Username geral": f'"{user}" -site:google.com -site:youtube.com',
        "Email + senha": f'"{email}" (password OR senha) -site:haveibeenpwned.com',
        "Curiosidades": f'intext:"{email}" intitle:index.of',
    }


def hibp_hint(email):
    """Gera link direto pra verificação manual (HIBP é fonte canônica)"""
    return f"https://haveibeenpwned.com/account/{urllib.parse.quote(email)}"


async def phase_email_async(case, email, username=None):
    print(f"\n{MAGENTA}═══ FASE 3 — EMAIL INTELLIGENCE: {email} ═══{NC}")
    info = case.emails.get(email, {})
    loop = asyncio.get_event_loop()

    log("*", CYAN, "Gravatar...")
    g = await loop.run_in_executor(None, gravatar_check_sync, email)
    info.update(g)
    if g.get("name"):
        log("+", GREEN, f"Gravatar: {g['name']}")

    log("*", CYAN, "Leak check (XposedOrNot)...")
    l = await loop.run_in_executor(None, leak_check_sync, email)
    info.update(l)
    if l.get("leaked"):
        log("!", RED, f"LEAKED em: {', '.join(l.get('breaches', [])[:5])}")
    elif l.get("leaked") is False:
        log("✓", GREEN, "sem vazamento conhecido")
    else:
        log("?", YELLOW, "API indisponível")

    info["dorks"] = dorks_for(email, username)
    info["hibp"] = hibp_hint(email)
    log("*", GRAY, f"{len(info['dorks'])} dorks gerados + link HIBP")

    case.emails[email] = info

    # Correlação automática: local-part do email vira candidato a username
    guess = email.split('@')[0]
    if len(guess) >= 4 and guess not in case.usernames and guess not in case.targets:
        log("!", YELLOW, f"Correlação: investigar também username '{guess}'")
        case.targets.append(f"username:{guess}")

    return info



# ═══════════════════════════════════════════
#  FASE 4 — RELATÓRIO HTML PROFISSIONAL
# ═══════════════════════════════════════════

def phase_report(case):
    print(f"\n{MAGENTA}═══ FASE 4 — RELATÓRIO HTML ═══{NC}")

    total_profiles = sum(len(v) for v in case.usernames.values())
    confirmed = sum(1 for u in case.usernames.values()
                    for d in u.values() if d.get('weight', 0) >= 2)
    total_emails = len(case.emails)
    leaked_emails = sum(1 for e in case.emails.values() if e.get('leaked'))

    sections = []

    # ── Cards de username
    for user, sites in case.usernames.items():
        if not sites:
            continue
        items = ""
        for site, info in sorted(sites.items(), key=lambda x: -x[1].get('weight', 0)):
            w = info.get('weight', 0)
            cls = "ok" if w >= 3 else "maybe"
            sym = "✓" if w >= 3 else "≈"
            items += (f'<li><span class="{cls}">{sym}</span> '
                      f'<a href="{html_mod.escape(info.get("url",""))}" target="_blank">{site}</a> '
                      f'<span class="w">confiança {w}/3</span></li>')
        sections.append(
            f'<div class="card"><h3>👤 Username: {html_mod.escape(user)}</h3>'
            f'<ul>{items}</ul></div>')

    # ── Cards de profiles
    for user, profs in case.profiles.items():
        for site, data in profs.items():
            if not data:
                continue
            fields = "".join(
                f"<li><b>{html_mod.escape(str(k))}:</b> {html_mod.escape(str(v))}</li>"
                for k, v in data.items() if v)
            if fields:
                sections.append(
                    f'<div class="card"><h3>📋 {html_mod.escape(user)} — {site}</h3>'
                    f'<ul>{fields}</ul></div>')

    # ── Cards de emails
    for email, info in case.emails.items():
        if info.get('leaked'):
            badge = '<span class="leak">LEAKED</span>'
        elif info.get('leaked') is False:
            badge = '<span class="clean">clean</span>'
        else:
            badge = '<span class="unknown">unknown</span>'

        fields = f"<li>Status de vazamento: {badge}</li>"
        if info.get('name'):
            fields += f"<li><b>Gravatar:</b> {html_mod.escape(str(info['name']))}</li>"
        if info.get('about'):
            fields += f"<li><b>About:</b> {html_mod.escape(str(info['about']))}</li>"
        if info.get('breaches'):
            fields += f"<li><b>Breaches:</b> {html_mod.escape(', '.join(info['breaches']))}</li>"
        if info.get('hibp'):
            fields += (f'<li>Verificação canônica: <a href="{info["hibp"]}" '
                       f'target="_blank">HaveIBeenPwned</a></li>')

        if info.get('dorks'):
            dorks = "".join(
                f'<li><code>{html_mod.escape(d)}</code> '
                f'<a href="https://www.google.com/search?q={urllib.parse.quote(d)}" '
                f'target="_blank">[executar]</a></li>'
                for d in info['dorks'].values())
            fields += f'<li><b>Dorks:</b><ul class="dorks">{dorks}</ul></li>'

        sections.append(
            f'<div class="card"><h3>📧 {html_mod.escape(email)} {badge}</h3>'
            f'<ul>{fields}</ul></div>')

    # ── Notas
    if case.notes:
        notes = "".join(
            f"<li><i>{n['time'][:10]}</i> — {html_mod.escape(n['text'])}</li>"
            for n in case.notes)
        sections.append(
            f'<div class="card"><h3>📝 Notas do investigador</h3><ul>{notes}</ul></div>')

    html_content = f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OSINT-Shinei — {html_mod.escape(case.name)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0a0e14;color:#d8d8d8;font-family:'JetBrains Mono','Courier New',monospace;padding:20px;line-height:1.6}}
.container{{max-width:1100px;margin:0 auto}}
header{{border:2px solid #ff006e;padding:25px;margin-bottom:25px;background:linear-gradient(135deg,#1a0e14,#0a0e14)}}
h1{{color:#ff006e;font-size:1.7em}} .meta{{color:#888;font-size:.9em}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:20px 0}}
.stat{{background:#14181f;padding:15px;text-align:center;border-left:3px solid #ff006e}}
.stat .n{{font-size:2em;color:#ff006e;font-weight:bold}}
.stat .l{{font-size:.72em;color:#888;letter-spacing:1px}}
.card{{background:#14181f;border-left:3px solid #ff006e;padding:15px;margin-bottom:12px;page-break-inside:avoid}}
.card h3{{color:#ff006e;margin-bottom:10px;font-size:1em;word-break:break-all}}
ul{{list-style:none;padding-left:0}}
li{{padding:4px 0;border-bottom:1px solid #1e1e1e;font-size:.88em;word-break:break-word}}
a{{color:#00ccff;text-decoration:none}} a:hover{{text-decoration:underline}}
.ok{{color:#00ff88;font-weight:bold}} .maybe{{color:#ffaa00;font-weight:bold}}
.w{{color:#555;font-size:.75em}}
.leak{{background:#331a00;color:#ff4444;padding:2px 10px;border-radius:10px;font-size:.75em;font-weight:bold}}
.clean{{background:#00331f;color:#00ff88;padding:2px 10px;border-radius:10px;font-size:.75em}}
.unknown{{background:#1a1a2e;color:#88aacc;padding:2px 10px;border-radius:10px;font-size:.75em}}
code{{background:#1a2332;color:#4a9eff;padding:2px 6px;border-radius:3px;font-size:.8em;display:inline-block;margin:2px 0}}
.dorks{{margin-top:5px}} .dorks li{{font-size:.78em;border-bottom:none}}
@media print{{body{{background:#fff;color:#111}} .card{{border-color:#333}}}}
</style></head><body><div class="container">
<header>
<h1>🔍 OSINT-Shinei v{VERSION}</h1>
<div class="meta">Case: <strong>{html_mod.escape(case.name)}</strong></div>
<div class="meta">Gerado: {datetime.now().strftime('%d/%m/%Y %H:%M')}</div>
<div class="meta">Fontes: 100% públicas (enumeração, APIs abertas, dorks indexados)</div>
</header>
<div class="stats">
<div class="stat"><div class="n">{len(case.targets)}</div><div class="l">TARGETS</div></div>
<div class="stat"><div class="n">{total_profiles}</div><div class="l">ACHADOS</div></div>
<div class="stat"><div class="n">{confirmed}</div><div class="l">CONFIRMADOS</div></div>
<div class="stat"><div class="n">{total_emails}</div><div class="l">EMAILS</div></div>
<div class="stat"><div class="n">{leaked_emails}</div><div class="l">LEAKED</div></div>
</div>
{''.join(sections)}
<footer style="text-align:center;color:#666;margin-top:40px;border-top:1px solid #222;padding-top:20px;font-size:.8em">
OSINT-Shinei v{VERSION} | shinei | Informação pública verificada — uso responsável
</footer></div></body></html>"""

    fname = case.path / 'report.html'
    fname.write_text(html_content, encoding='utf-8')
    print(f"{GREEN}[✓] Relatório: {fname}{NC}")

    os.system(f"cp {fname} ~/storage/shared/Download/ 2>/dev/null")
    os.system(f"termux-open ~/storage/shared/Download/report.html 2>/dev/null")
    return fname



# ═══════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════

def banner():
    print(f"{MAGENTA}")
    print("  ╔══════════════════════════════════════════╗")
    print("  ║   🔍 OSINT-SHINEI v2.0                   ║")
    print("  ║   validated · async · consolidated       ║")
    print("  ╚══════════════════════════════════════════╝")
    print(f"{NC}")


def cmd_new(args):
    case = Case(args.name)
    for t in args.targets:
        kind, val = case.classify_target(t)
        if kind == 'email':
            case.targets.append(f"email:{val}")
        else:
            case.targets.append(f"username:{val}")
    case.save()
    print(f"{GREEN}[✓] Case criado: {case.path}{NC}")
    print(f"    Targets: {', '.join(case.targets)}")
    print(f"\n{CYAN}Executa com:{NC} osint run {args.name}")


async def cmd_run_async(case, no_report):
    start = time.time()
    print(f"{BOLD}Case: {case.name} | Targets: {len(case.targets)}{NC}\n")

    # FASE 1 — usernames (async, paralelo por plataforma)
    phase1_targets = [t for t in case.targets if t.startswith('username:')]
    for t in phase1_targets:
        username = t.replace('username:', '')
        print(f"\n{MAGENTA}═══ FASE 1 — USERNAME: {username} ═══{NC}")
        found = await phase_username_async(username)
        case.usernames[username] = found
        case.save()

    # FASE 2 — profiles (só onde FASE 1 confirmou)
    for username in list(case.usernames.keys()):
        if case.usernames[username]:
            await phase_profiles_async(case, username)
            case.save()

    # FASE 3 — emails
    email_targets = [t for t in case.targets if t.startswith('email:')]
    for t in email_targets:
        await phase_email_async(case, t.replace('email:', ''))
        case.save()

    # Emails descobertos nas fases 1-2 (auto)
    for email in list(case.emails.keys()):
        if 'leaked' not in case.emails[email]:
            guess_user = case.emails[email].get('source') == 'GitHub público'
            await phase_email_async(case, email,
                                    guess_user and email.split('@')[0])
            case.save()

    elapsed = time.time() - start
    case.runs.append({'date': datetime.now().isoformat(), 'seconds': round(elapsed, 1)})
    case.save()

    print(f"\n{GREEN}{'═'*55}{NC}")
    print(f"{GREEN}[✓] Completo em {elapsed:.1f}s{NC}\n")
    print(case.summary())

    if not no_report:
        phase_report(case)


def cmd_run(args):
    case = Case.load(args.case)
    if not case:
        print(f"{RED}[!] Case '{args.case}' não existe. Cria com: osint new -n {args.case} -t alvo{NC}")
        sys.exit(1)
    banner()
    asyncio.run(cmd_run_async(case, args.no_report))


def cmd_new_sync(args):
    banner()
    cmd_new(args)


def cmd_show(args):
    case = Case.load(args.case)
    if not case:
        print(f"{RED}[!] Case não encontrado{NC}")
        sys.exit(1)
    banner()
    print(case.summary())


def cmd_note(args):
    case = Case.load(args.case)
    if not case:
        print(f"{RED}[!] Case não encontrado{NC}")
        sys.exit(1)
    case.add_note(' '.join(args.text))
    case.save()
    print(f"{GREEN}[✓] Nota adicionada{NC}")


def cmd_list(args):
    banner()
    cases = sorted([d.name for d in CASES.iterdir() if d.is_dir()])
    if not cases:
        print(f"{GRAY}Nenhum case. Cria com: osint new -n nome -t alvo1 email:alvo@x.com{NC}")
        return
    print(f"{BOLD}Cases ({len(cases)}):{NC}")
    for c in cases:
        case = Case.load(c)
        n = sum(len(v) for v in case.usernames.values()) if case else 0
        e = len(case.emails) if case else 0
        print(f"  {c} {GRAY}[{n} perfis | {e} emails]{NC}")


def cmd_report(args):
    case = Case.load(args.case)
    if not case:
        print(f"{RED}[!] Case não encontrado{NC}")
        sys.exit(1)
    banner()
    phase_report(case)


def main():
    import argparse
    ap = argparse.ArgumentParser(
        prog='osint',
        description=f'OSINT-Shinei v{VERSION} — framework de investigação pública',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Exemplos:
  osint new -n caso1 -t _Lucas_z7x email:alvo@gmail.com
  osint run caso1
  osint show caso1
  osint note caso1 "confirmado manualmente que a conta TikTok é dele"
  osint report caso1
  osint list

Uso ético: informação PÚBLICA apenas.
        ''')
    sub = ap.add_subparsers(dest='cmd')

    p = sub.add_parser('new', help='Cria novo case')
    p.add_argument('-n', '--name', required=True)
    p.add_argument('-t', '--targets', nargs='+', required=True,
                   help='usernames e/ou email:email@x.com')
    p.set_defaults(func=cmd_new_sync)

    p = sub.add_parser('run', help='Executa investigação completa (async)')
    p.add_argument('case')
    p.add_argument('--no-report', action='store_true')
    p.set_defaults(func=cmd_run)

    p = sub.add_parser('show', help='Resumo do case')
    p.add_argument('case')
    p.set_defaults(func=cmd_show)

    p = sub.add_parser('note', help='Adiciona nota')
    p.add_argument('case')
    p.add_argument('text', nargs='+')
    p.set_defaults(func=cmd_note)

    p = sub.add_parser('list', help='Lista cases')
    p.set_defaults(func=cmd_list)

    p = sub.add_parser('report', help='Gera relatório HTML')
    p.add_argument('case')
    p.set_defaults(func=cmd_report)

    args = ap.parse_args()
    if not args.cmd:
        ap.print_help()
        return
    args.func(args)


if __name__ == '__main__':
    main()
