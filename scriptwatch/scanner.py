"""Escáner defensivo de scripts de terceros.

Hace lo mismo que un navegador al cargar una página: un GET a la URL y un GET a cada <script src>.
No ejecuta JavaScript ni explota nada. Úsalo sobre sitios propios o en forma puntual sobre páginas públicas.
"""
import hashlib
import re
import urllib.request
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

UA = "script-watch/0.1 (auditoria defensiva)"
MAX_BYTES = 2_000_000
MAX_SCRIPTS = 40
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# Heurísticas: tres familias de señales. Una sola familia es normal; dos o más merecen revisión manual.
HEURISTICS = {
    "ofuscación": re.compile(r"\beval\s*\(|\batob\s*\(|String\.fromCharCode"),
    "captura de datos": re.compile(r"cvv|card[-_ ]?number|cardnumber|document\.cookie", re.I),
    "cripto": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
}


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str
    mitre: str
    target: str
    detail: str


class _Collector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            a = dict(attrs)
            self.scripts.append({"src": a.get("src"), "integrity": a.get("integrity"),
                                 "crossorigin": a.get("crossorigin")})


def _validate(url):
    if urlparse(url).scheme not in ("http", "https"):
        raise ValueError("Solo se permiten URLs http/https")


def default_fetch(url, timeout=10):
    _validate(url)
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310 - esquema validado arriba
        body = r.read(MAX_BYTES)
        return r.status, {k.lower(): v for k, v in r.headers.items()}, body


def _registrable(host):
    """Aproximación: últimas dos etiquetas del host. No cubre sufijos como .co.uk (limitación conocida)."""
    parts = (host or "").lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "").lower()


def _check_csp(csp, url):
    if not csp:
        return [Alert("SW-006", "Sin Content-Security-Policy", "low", "T1195", url,
                      "La página no envía CSP: no hay una lista que restrinja qué scripts pueden ejecutarse.")]
    directives = {d.split()[0].lower(): d.split()[1:] for d in csp.split(";") if d.strip()}
    values = directives.get("script-src", directives.get("default-src", []))
    weak = [v for v in values if v in ("*", "'unsafe-inline'", "https:", "http:")]
    if weak:
        return [Alert("SW-006", "CSP permisiva para scripts", "medium", "T1195", url,
                      f"script-src incluye valores amplios: {', '.join(weak)}")]
    return []


def _heuristic_hits(text):
    return [name for name, rx in HEURISTICS.items() if rx.search(text)]


def scan(url, fetch=default_fetch, baseline=None, watchlist=()):
    _validate(url)
    baseline = baseline or {}
    status, headers, body = fetch(url)
    parser = _Collector()
    parser.feed(body.decode("utf-8", errors="replace"))
    page_host = urlparse(url).hostname or ""

    findings = _check_csp(headers.get("content-security-policy"), url)
    scripts, hashes = [], {}
    for s in parser.scripts[:MAX_SCRIPTS]:
        if not s["src"]:
            continue
        src = urljoin(url, s["src"])
        host = urlparse(src).hostname or ""
        third = _registrable(host) != _registrable(page_host)
        scripts.append({"src": src, "third_party": third, "sri": bool(s["integrity"])})
        if not third:
            continue
        if urlparse(src).scheme == "http":
            findings.append(Alert("SW-002", "Script de terceros sin TLS", "high", "T1195", src,
                                  "Se carga por http: cualquiera en el camino puede modificarlo."))
        if not s["integrity"]:
            findings.append(Alert("SW-001", "Script de terceros sin SRI", "medium", "T1195", src,
                                  "Sin atributo integrity el navegador ejecuta lo que el proveedor sirva hoy."))
        for w in watchlist:
            if w.lower() in src.lower():
                findings.append(Alert("SW-004", f"Proveedor en watchlist: {w}", "medium", "T1195.002", src,
                                      "Proveedor marcado por el usuario (p. ej. por un incidente reportado). Revisar."))
        try:
            _, _, content = fetch(src)
        except Exception as e:  # noqa: BLE001 - un script caído no debe frenar el resto del análisis
            findings.append(Alert("SW-000", "No se pudo descargar el script", "info", "-", src, str(e)))
            continue
        digest = hashlib.sha256(content).hexdigest()
        hashes[src] = digest
        if src in baseline and baseline[src] != digest:
            findings.append(Alert("SW-003", "El contenido del script cambió desde el baseline", "high", "T1195.002", src,
                                  "Puede ser una actualización legítima o una manipulación: comparar versiones."))
        hits = _heuristic_hits(content.decode("utf-8", errors="replace"))
        if len(hits) >= 2:
            findings.append(Alert("SW-005", "Patrones sospechosos (heurística)", "medium", "T1059.007", src,
                                  f"Coinciden {len(hits)} familias: {', '.join(hits)}. Puede ser un falso positivo."))
    findings.sort(key=lambda a: (SEV_ORDER[a.severity], a.rule_id))
    return {"url": url, "scripts": scripts, "hashes": hashes, "findings": [asdict(a) for a in findings]}
