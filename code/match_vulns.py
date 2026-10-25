"""Match SBOM components against the GitHub Advisory Database (reviewed advisories).

Usage:
    python match_vulns.py <sbom_dir> <advisory_dir> <out_csv>

For every CycloneDX SBOM in <sbom_dir>, each npm / Composer component (name + version
from its package URL) is checked against the affected version ranges of all
GitHub-reviewed advisories. One output row = one (project, component, advisory) finding.
"""
import csv
import glob
import json
import os
import sys
from collections import defaultdict
from urllib.parse import unquote

from univers.versions import ComposerVersion, SemverVersion

ECOSYSTEMS = {"npm": ("npm", SemverVersion), "composer": ("Packagist", ComposerVersion)}


def parse_version(cls, v):
    v = v.strip().lstrip("vV")
    try:
        return cls(v)
    except Exception:
        return None


def load_advisories(adv_dir):
    """index[(ecosystem, package_name)] -> list of (advisory, affected_entry)."""
    index = defaultdict(list)
    for f in glob.glob(os.path.join(adv_dir, "**", "*.json"), recursive=True):
        with open(f, encoding="utf-8") as fh:
            adv = json.load(fh)
        if adv.get("withdrawn"):
            continue
        for aff in adv.get("affected", []):
            pkg = aff.get("package", {})
            if pkg.get("ecosystem") in ("npm", "Packagist"):
                index[(pkg["ecosystem"], pkg["name"].lower())].append((adv, aff))
    return index


def is_affected(version, aff, cls):
    """True if `version` falls in one of the advisory's affected ranges or listed versions."""
    raw = version.strip().lstrip("vV")
    if raw in [x.lstrip("vV") for x in aff.get("versions", [])]:
        return True
    v = parse_version(cls, version)
    if v is None:
        return False
    for rng in aff.get("ranges", []):
        if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        intro, hit = None, False
        for ev in rng.get("events", []):
            if "introduced" in ev:
                intro = ev["introduced"]
                hit = True
                lower = None if intro == "0" else parse_version(cls, intro)
                if intro != "0" and lower is None:
                    hit = False
                    continue
                if lower is not None and v < lower:
                    hit = False
            elif "fixed" in ev and intro is not None:
                upper = parse_version(cls, ev["fixed"])
                if hit and upper is not None and v < upper:
                    return True
                intro, hit = None, False
            elif "last_affected" in ev and intro is not None:
                upper = parse_version(cls, ev["last_affected"])
                if hit and upper is not None and v <= upper:
                    return True
                intro, hit = None, False
        if intro is not None and hit:  # open-ended range: no fix yet
            return True
    return False


def purl_parts(purl):
    """pkg:npm/%40scope/name@1.0.0 -> ('npm', '@scope/name', '1.0.0')."""
    body = purl.split("?")[0].split("#")[0]
    typ, rest = body[4:].split("/", 1)
    name, _, version = unquote(rest).rpartition("@")
    return typ, name, version


def main(sbom_dir, adv_dir, out_csv):
    index = load_advisories(adv_dir)
    print(f"Loaded advisories for {len(index)} npm/Packagist packages")
    rows, stats = [], []
    for sbom_file in sorted(glob.glob(os.path.join(sbom_dir, "*.cdx.json"))):
        project = os.path.basename(sbom_file).replace(".cdx.json", "")
        comps = json.load(open(sbom_file, encoding="utf-8")).get("components", [])
        vulnerable = set()
        for c in comps:
            purl = c.get("purl", "")
            if not purl.startswith("pkg:"):
                continue
            typ, name, version = purl_parts(purl)
            if typ not in ECOSYSTEMS or not version:
                continue
            eco, cls = ECOSYSTEMS[typ]
            for adv, aff in index.get((eco, name.lower()), []):
                if not is_affected(version, aff, cls):
                    continue
                cves = [a for a in adv.get("aliases", []) if a.startswith("CVE-")]
                vector = next((s["score"] for s in adv.get("severity", []) if s["type"] == "CVSS_V3"), "")
                rows.append({
                    "project": project, "ecosystem": typ, "package": name, "version": version,
                    "scope": c.get("scope", "unknown") or "unknown",
                    "ghsa_id": adv["id"], "cve": cves[0] if cves else "",
                    "ghsa_severity": adv.get("database_specific", {}).get("severity", ""),
                    "ghsa_cvss3_vector": vector, "summary": adv.get("summary", "")[:120],
                })
                vulnerable.add(purl)
        stats.append((project, len(comps), len(vulnerable)))
    # de-duplicate (same component + advisory listed twice in one SBOM)
    seen, unique = set(), []
    for r in rows:
        key = (r["project"], r["package"], r["version"], r["ghsa_id"])
        if key not in seen:
            seen.add(key)
            unique.append(r)
    with open(out_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(unique[0].keys()))
        w.writeheader()
        w.writerows(unique)
    for p, n, v in stats:
        print(f"{p:14s} components={n:5d} vulnerable_components={v:4d} findings={sum(r['project'] == p for r in unique)}")


if __name__ == "__main__":
    main(*sys.argv[1:4])
