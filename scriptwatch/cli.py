import argparse
import json
import sys

from .scanner import scan


def main(argv=None):
    p = argparse.ArgumentParser(prog="scriptwatch", description="Audita scripts de terceros de una página.")
    p.add_argument("url")
    p.add_argument("--baseline", help="JSON con hashes previos para detectar cambios")
    p.add_argument("--save-baseline", action="store_true", help="Guardar los hashes actuales en --baseline")
    p.add_argument("--watch", action="append", default=[], help="Proveedor a marcar (repetible), ej. --watch optimizely")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)

    baseline = {}
    if a.baseline:
        try:
            with open(a.baseline, encoding="utf-8") as fh:
                baseline = json.load(fh)
        except FileNotFoundError:
            pass
    report = scan(a.url, baseline=baseline, watchlist=a.watch)
    if a.save_baseline and a.baseline:
        with open(a.baseline, "w", encoding="utf-8") as fh:
            json.dump(report["hashes"], fh, indent=2)
    if a.json:
        json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
        print()
    else:
        third = [s for s in report["scripts"] if s["third_party"]]
        print(f"{report['url']}: {len(report['scripts'])} scripts externos, {len(third)} de terceros")
        for f in report["findings"]:
            print(f"[{f['severity'].upper():6}] {f['rule_id']} {f['mitre']:10} {f['title']} | {f['target']}")
            print(f"           {f['detail']}")
        if not report["findings"]:
            print("Sin hallazgos.")
    return 1 if any(f["severity"] == "high" for f in report["findings"]) else 0
