"""Validate our matcher against `npm audit` (reference scanner) on the npm part of each app.

Usage (after running `npm audit --package-lock-only --json > results/npm_audit/<app>.json`
inside a folder that contains the app's package.json and package-lock.json):
    python validate_npm_audit.py results/findings_raw.csv results/npm_audit results/table_validation.csv
"""
import json
import sys

import pandas as pd


def main(findings_csv, audit_dir, out_csv):
    f = pd.read_csv(findings_csv)
    rows = []
    for app in ["ghostfolio", "firefly-iii", "akaunting", "invoiceninja"]:
        audit = json.load(open(f"{audit_dir}/{app}.json"))
        a = {(v["name"].lower(), v["url"].rsplit("/", 1)[-1])
             for pkg in audit["vulnerabilities"].values() for v in pkg["via"] if isinstance(v, dict)}
        m = {(r.package.lower(), r.ghsa_id) for r in f[(f.project == app) & (f.ecosystem == "npm")].itertuples()}
        rows.append({"Application": app, "npm audit (package, advisory) pairs": len(a), "Our matcher": len(m),
                     "Both": len(a & m), "Only npm audit": len(a - m), "Only our matcher": len(m - a),
                     "Jaccard agreement": round(len(a & m) / len(a | m), 2)})
    t = pd.DataFrame(rows)
    t.to_csv(out_csv, index=False)
    print(t.to_string(index=False))


if __name__ == "__main__":
    main(*sys.argv[1:4])
