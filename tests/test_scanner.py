import functools
import http.server
import threading

from scriptwatch.scanner import scan

PAGE = "https://shop.example.com/"
HTML = """<html><head>
<script src="/static/app.js"></script>
<script src="https://cdn.vendor.net/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script>
</head></html>"""


def make_fetch(pages, headers=None):
    def fetch(url):
        if url not in pages:
            raise OSError("404")
        return 200, headers or {}, pages[url].encode() if isinstance(pages[url], str) else pages[url]
    return fetch


def ids(report):
    return [f["rule_id"] for f in report["findings"]]


def test_first_party_and_sri_third_party_only_csp_info():
    fetch = make_fetch({PAGE: HTML, PAGE + "static/app.js": "x", "https://cdn.vendor.net/lib.js": "y"})
    assert ids(scan(PAGE, fetch=fetch)) == ["SW-006"]  # solo falta CSP


def test_missing_sri_flagged():
    html = '<script src="https://cdn.vendor.net/lib.js"></script>'
    r = scan(PAGE, fetch=make_fetch({PAGE: html, "https://cdn.vendor.net/lib.js": "y"}))
    assert "SW-001" in ids(r)


def test_http_third_party_is_high():
    html = '<script src="http://cdn.vendor.net/lib.js" integrity="sha384-x"></script>'
    r = scan(PAGE, fetch=make_fetch({PAGE: html, "http://cdn.vendor.net/lib.js": "y"}))
    assert r["findings"][0]["rule_id"] == "SW-002" and r["findings"][0]["severity"] == "high"


def test_baseline_change_detected():
    pages = {PAGE: HTML, PAGE + "static/app.js": "x", "https://cdn.vendor.net/lib.js": "v1"}
    first = scan(PAGE, fetch=make_fetch(pages))
    pages["https://cdn.vendor.net/lib.js"] = "v2 modificado"
    second = scan(PAGE, fetch=make_fetch(pages), baseline=first["hashes"])
    assert "SW-003" in ids(second)
    assert "SW-003" not in ids(scan(PAGE, fetch=make_fetch(pages), baseline=second["hashes"]))


def test_watchlist_match():
    r = scan(PAGE, fetch=make_fetch({PAGE: HTML, PAGE + "static/app.js": "x", "https://cdn.vendor.net/lib.js": "y"}),
             watchlist=["vendor"])
    assert "SW-004" in ids(r)


def test_heuristics_need_two_families():
    html = '<script src="https://cdn.vendor.net/lib.js" integrity="sha384-x"></script>'
    one = scan(PAGE, fetch=make_fetch({PAGE: html, "https://cdn.vendor.net/lib.js": "eval(x)"}))
    two = scan(PAGE, fetch=make_fetch({PAGE: html, "https://cdn.vendor.net/lib.js":
                                       "eval(atob(s)); var cvv=1; "}))
    assert "SW-005" not in ids(one) and "SW-005" in ids(two)


def test_csp_unsafe_inline():
    r = scan(PAGE, fetch=make_fetch({PAGE: "<html></html>"},
                                    {"content-security-policy": "script-src 'self' 'unsafe-inline'"}))
    assert ids(r) == ["SW-006"] and r["findings"][0]["severity"] == "medium"


def test_unreachable_script_does_not_crash():
    html = '<script src="https://cdn.vendor.net/lib.js" integrity="sha384-x"></script>'
    r = scan(PAGE, fetch=make_fetch({PAGE: html}))
    assert "SW-000" in ids(r)


def test_rejects_non_http_scheme():
    try:
        scan("file:///etc/passwd")
    except ValueError:
        return
    raise AssertionError("debió rechazar file://")


def test_end_to_end_with_real_local_server(tmp_path):
    (tmp_path / "index.html").write_text('<script src="http://localhost:{p}/x.js"></script>')
    (tmp_path / "x.js").write_text("console.log(1)")
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(tmp_path))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = srv.server_address[1]
    (tmp_path / "index.html").write_text(f'<script src="http://localhost:{port}/x.js"></script>')
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        r = scan(f"http://127.0.0.1:{port}/index.html")
    finally:
        srv.shutdown()
    assert "SW-002" in ids(r) and len(r["hashes"]) == 1
