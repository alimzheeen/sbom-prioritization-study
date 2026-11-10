"""Additional analyses for the final research paper (Assignment 6).

Uses ONLY results/findings_final.csv produced by analyze.py (no new data sources).

Usage:
    python extended_analysis.py <findings_final.csv> <out_dir>

E1  remediation policies: coverage and efficiency of threshold rules (cf. Jacobs et al. 2021)
E2  effort: list positions needed to reach exploited findings (k = 10, 20, 50; full coverage)
E3  dependency scope of exploited and High/Critical findings
E4  de-duplicated analysis: one row per unique CVE (pooled over applications)
E5  coarseness of CVSS ranking: ties
E6  weight sensitivity of the combined score (current-data positions and temporal AUC)
E7  statistical power of the temporal test (5 positives vs 105 negatives)
E8  agreement between CVSS and EPSS
"""
import os
import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import stats

PROJECTS = ["ghostfolio", "actual", "firefly-iii", "akaunting", "invoiceninja"]
LABEL = {"ghostfolio": "Ghostfolio", "actual": "Actual Budget", "firefly-iii": "Firefly III",
         "akaunting": "Akaunting", "invoiceninja": "Invoice Ninja"}


def comb(cvss, epss_pct, kev, w):
    wc, we, wk = w
    return wc * cvss / 10 + we * epss_pct + wk * kev.astype(float)


def auc_p(score, y):
    pos, neg = score[y], score[~y]
    u = stats.mannwhitneyu(pos, neg, alternative="greater")
    return u.statistic / (len(pos) * len(neg)), u.pvalue


def main(csv, out):
    os.makedirs(out, exist_ok=True)
    f = pd.read_csv(csv)
    f["cvss_now"] = f["cvss_now"].fillna(0)
    f["epss_now"] = f["epss_now"].fillna(0)
    f["dev"] = f["dev_only"].map({True: True, False: False, "True": True, "False": False})
    n_exp = int(f.exploited_now.sum())
    log = []

    def p(*a):
        s = " ".join(str(x) for x in a)
        print(s)
        log.append(s)

    # ---------------- E1: remediation policies (pooled findings) ----------------
    policies = {
        "CVSS >= 9.0 (Critical)": f.cvss_now >= 9.0,
        "CVSS >= 7.0 (High+Critical)": f.cvss_now >= 7.0,
        "CVSS >= 4.0 (Medium and above)": f.cvss_now >= 4.0,
        "EPSS >= 0.10": f.epss_now >= 0.10,
        "CISA KEV listed": f.kev_now.astype(bool),
        "CVSS >= 7.0 OR EPSS >= 0.10 OR KEV": (f.cvss_now >= 7) | (f.epss_now >= 0.10) | f.kev_now.astype(bool),
    }
    rows = []
    for name, sel in policies.items():
        tp = int((sel & f.exploited_now).sum())
        rows.append({"Policy": name, "Findings selected": int(sel.sum()),
                     "Share of all findings": round(sel.mean(), 3),
                     "Exploited covered": f"{tp}/{n_exp}",
                     "Coverage": round(tp / n_exp, 3),
                     "Efficiency": round(tp / sel.sum(), 3) if sel.sum() else np.nan})
    E1 = pd.DataFrame(rows)
    E1.to_csv(f"{out}/table_E1_policies.csv", index=False)
    p("E1 remediation policies (pooled, n =", len(f), "findings,", n_exp, "exploited)")
    p(E1.to_string(index=False))

    # ---------------- E2: effort per application ----------------
    rows = []
    for pr in PROJECTS:
        d = f[f.project == pr]
        e = d[d.exploited_now]
        row = {"Application": LABEL[pr], "Findings": len(d), "Exploited": len(e)}
        for k in (10, 20, 50):
            row[f"Recall@{k} CVSS"] = round((e.r_cvss <= k).mean(), 2)
            row[f"Recall@{k} Comb"] = round((e.r_comb <= k).mean(), 2)
        row["Full coverage CVSS (% of list)"] = round(100 * e.r_cvss.max() / len(d), 1)
        row["Full coverage Comb (% of list)"] = round(100 * e.r_comb.max() / len(d), 1)
        row["First exploited CVSS"] = e.r_cvss.min()
        row["First exploited Comb"] = e.r_comb.min()
        rows.append(row)
    E2 = pd.DataFrame(rows)
    E2.to_csv(f"{out}/table_E2_effort.csv", index=False)
    p("\nE2 effort per application")
    p(E2.to_string(index=False))
    for k in (10, 20, 50):
        p(f"pooled recall@{k}: CVSS={(f[f.exploited_now].r_cvss <= k).mean():.3f} "
          f"Comb={(f[f.exploited_now].r_comb <= k).mean():.3f}")

    # Wilcoxon on per-finding paired ranks (exploited findings), descriptive only
    e = f[f.exploited_now]
    w = stats.wilcoxon(e.r_cvss, e.r_comb, alternative="greater")
    p(f"Wilcoxon paired (rank_cvss > rank_comb) over {len(e)} exploited findings: stat={w.statistic:.1f} p={w.pvalue:.2e}"
      f"; improved={int((e.r_comb < e.r_cvss).sum())}, worse={int((e.r_comb > e.r_cvss).sum())}")

    # ---------------- E3: scope ----------------
    k = f[f.dev.notna()]
    rows = []
    for name, sel in {"All findings": k.index == k.index,
                      "High/Critical (CVSS >= 7)": k.cvss_now >= 7,
                      "Exploited now": k.exploited_now}.items():
        d = k[sel]
        rows.append({"Subset (4 apps with scope data)": name, "Findings": len(d),
                     "Dev-only": int(d.dev.sum()), "Dev-only share": round(d.dev.mean(), 3)})
    E3 = pd.DataFrame(rows)
    E3.to_csv(f"{out}/table_E3_scope.csv", index=False)
    p("\nE3 scope")
    p(E3.to_string(index=False))
    ex = k[k.exploited_now]
    p("exploited dev-only packages:", ex[ex.dev].package.value_counts().to_dict())
    p("exploited production packages:", ex[~ex.dev.astype(bool)].package.value_counts().to_dict())

    # ---------------- E4: unique CVEs pooled ----------------
    u = f[f.cve.notna()].sort_values("cvss_now", ascending=False).drop_duplicates("cve").copy()
    u["r_cvss_u"] = (-u.cvss_now).rank(method="average")
    u["r_comb_u"] = (-comb(u.cvss_now, u.epss_pct_now.fillna(0), u.kev_now, (0.4, 0.4, 0.2))).rank(method="average")
    eu = u[u.exploited_now]
    p(f"\nE4 unique CVEs: {len(u)} CVEs, {len(eu)} exploited")
    p(f"median rank exploited: CVSS={eu.r_cvss_u.median()} ({100*eu.r_cvss_u.median()/len(u):.1f}%), "
      f"Comb={eu.r_comb_u.median()} ({100*eu.r_comb_u.median()/len(u):.1f}%)")
    p(f"recall@20 unique: CVSS={(eu.r_cvss_u<=20).mean():.2f} Comb={(eu.r_comb_u<=20).mean():.2f}; "
      f"recall@50: CVSS={(eu.r_cvss_u<=50).mean():.2f} Comb={(eu.r_comb_u<=50).mean():.2f}")
    a_c, p_c = auc_p((u.cvss_now).to_numpy(), u.exploited_now.to_numpy(bool))
    p(f"AUC CVSS-only for current exploitation (unique CVEs, non-circular): {a_c:.3f} p={p_c:.3f}")
    pkg_share = f[f.exploited_now].package.value_counts(normalize=True).round(3).to_dict()
    p("share of exploited findings by package:", pkg_share)
    eu[["cve", "package", "cvss_now", "epss_now", "kev_now", "r_cvss_u", "r_comb_u"]].sort_values("r_comb_u") \
        .to_csv(f"{out}/table_E4_unique_exploited.csv", index=False)
    p(eu[["cve", "package", "cvss_now", "epss_now", "kev_now", "r_cvss_u", "r_comb_u"]].sort_values("r_comb_u").to_string(index=False))

    # ---------------- E5: CVSS ties ----------------
    rows = []
    for pr in PROJECTS:
        d = f[f.project == pr]
        vc = d.cvss_now.round(1).value_counts()
        rows.append({"Application": LABEL[pr], "Findings": len(d), "Distinct CVSS values": len(vc),
                     "Largest tie group": int(vc.max()), "Most common score": vc.idxmax(),
                     "Distinct combined scores": d.r_comb.nunique()})
    E5 = pd.DataFrame(rows)
    E5.to_csv(f"{out}/table_E5_ties.csv", index=False)
    p("\nE5 ties")
    p(E5.to_string(index=False))

    # ---------------- E6: weight sensitivity ----------------
    t = f[f.in_t0_snapshot].copy()
    t["cvss_t0"] = t["cvss_t0"].fillna(0)
    t = t.sort_values("cvss_t0", ascending=False).drop_duplicates("cve")
    y = t["new_exploitation_after_t0"].to_numpy(bool)
    rows = []
    for wk in (0.0, 0.1, 0.2, 0.3):
        for wc in np.round(np.arange(0, 1 - wk + 1e-9, 0.1), 1):
            we = round(1 - wk - wc, 1)
            # current data: pooled median relative position of exploited findings
            pos = []
            for pr in PROJECTS:
                d = f[f.project == pr]
                r = (-comb(d.cvss_now, d.epss_pct_now.fillna(0), d.kev_now, (wc, we, wk))).rank(method="average")
                pos += list(100 * r[d.exploited_now] / len(d))
            s0 = comb(t.cvss_t0, t.epss_pct_t0.fillna(0), t.kev_t0, (wc, we, wk)).to_numpy()
            a, pv = auc_p(s0, y) if np.ptp(s0) > 0 else (0.5, 1.0)
            rows.append({"w_CVSS": wc, "w_EPSS": we, "w_KEV": wk,
                         "Median position of exploited now (%)": round(np.median(pos), 1),
                         "Temporal AUC": round(a, 3), "Temporal p": round(pv, 3)})
    E6 = pd.DataFrame(rows)
    E6.to_csv(f"{out}/table_E6_weights.csv", index=False)
    p("\nE6 weight sensitivity")
    p(E6.to_string(index=False))
    p(f"temporal AUC range over grid: {E6['Temporal AUC'].min():.3f}-{E6['Temporal AUC'].max():.3f}; "
      f"min p = {E6['Temporal p'].min():.3f}")
    p(f"median position range: {E6['Median position of exploited now (%)'].min()}-{E6['Median position of exploited now (%)'].max()}")
    cv = E6[(E6.w_CVSS == 1.0) & (E6.w_KEV == 0)]
    p("CVSS-only row:", cv.to_dict("records"))

    # figure: sensitivity
    fig, axs = plt.subplots(1, 2, figsize=(7.2, 2.8))
    for wk, mk in zip((0.0, 0.1, 0.2, 0.3), ("o", "s", "^", "D")):
        d = E6[E6.w_KEV == wk]
        axs[0].plot(d.w_CVSS, d["Median position of exploited now (%)"], marker=mk, ms=3.5, lw=1, label=f"w_KEV = {wk}")
        axs[1].plot(d.w_CVSS, d["Temporal AUC"], marker=mk, ms=3.5, lw=1, label=f"w_KEV = {wk}")
    axs[0].set_xlabel("w_CVSS (w_EPSS = 1 - w_CVSS - w_KEV)")
    axs[0].set_ylabel("Median position of\nexploited findings (% of list)")
    axs[0].set_title("(a) Current data, triage", fontsize=9)
    axs[1].axhline(0.5, color="grey", lw=0.8, ls="--")
    axs[1].set_xlabel("w_CVSS (w_EPSS = 1 - w_CVSS - w_KEV)")
    axs[1].set_ylabel("AUC (T0 ranking,\nnew exploitation)")
    axs[1].set_title("(b) Temporal test", fontsize=9)
    axs[1].set_ylim(0.2, 0.8)
    for a in axs:
        a.grid(alpha=0.3)
    axs[1].legend(frameon=False, fontsize=7, loc="lower right", ncol=2)
    plt.tight_layout()
    plt.savefig(f"{out}/fig3_weight_sensitivity.png", dpi=200, bbox_inches="tight")
    plt.close()

    # ---------------- E7: power of the temporal test ----------------
    n1, n0 = int(y.sum()), int((~y).sum())
    # critical AUC for one-sided alpha = 0.05 (normal approximation of Mann-Whitney U)
    mu, sd = n1 * n0 / 2, np.sqrt(n1 * n0 * (n1 + n0 + 1) / 12)
    u_crit = mu + stats.norm.ppf(0.95) * sd
    p(f"\nE7 power: n_pos={n1}, n_neg={n0}; critical AUC (alpha=0.05, one-sided) = {u_crit/(n1*n0):.3f}")
    rng = np.random.default_rng(7)
    rows = []
    for true_auc in (0.6, 0.7, 0.8, 0.9):
        d_ = np.sqrt(2) * stats.norm.ppf(true_auc)       # binormal model, equal variances
        hits = 0
        for _ in range(4000):
            s = np.concatenate([rng.normal(d_, 1, n1), rng.normal(0, 1, n0)])
            yy = np.r_[np.ones(n1, bool), np.zeros(n0, bool)]
            hits += auc_p(s, yy)[1] < 0.05
        rows.append({"True AUC": true_auc, "Power (5 vs 105)": round(hits / 4000, 2)})
    for true_auc in (0.7, 0.8):
        d_ = np.sqrt(2) * stats.norm.ppf(true_auc)
        for npos in range(5, 80, 1):
            hits = 0
            for _ in range(1000):
                nneg = int(round(npos * n0 / n1))          # keep the observed prevalence (5 of 110)
                s = np.concatenate([rng.normal(d_, 1, npos), rng.normal(0, 1, nneg)])
                yy = np.r_[np.ones(npos, bool), np.zeros(nneg, bool)]
                hits += auc_p(s, yy)[1] < 0.05
            if hits / 1000 >= 0.8:
                p(f"positives needed for 80% power at true AUC {true_auc} (same prevalence): about {npos} (with {int(round(npos*n0/n1))} negatives)")
                break
    E7 = pd.DataFrame(rows)
    E7.to_csv(f"{out}/table_E7_power.csv", index=False)
    p(E7.to_string(index=False))

    # ---------------- E8: CVSS vs EPSS ----------------
    uu = u[u.epss_now > 0]
    rho = stats.spearmanr(uu.cvss_now, uu.epss_now)
    hc = uu[uu.cvss_now >= 7]
    p(f"\nE8 unique CVEs with EPSS: {len(uu)}; Spearman CVSS~EPSS rho={rho[0]:.2f} p={rho[1]:.2e}")
    p(f"High/Critical unique CVEs: {len(hc)}, with EPSS >= 0.10: {(hc.epss_now >= 0.10).sum()} "
      f"({100*(hc.epss_now >= 0.10).mean():.1f}%)")
    p(f"High/Critical findings: {(f.cvss_now>=7).sum()}, with EPSS>=0.10: {((f.cvss_now>=7)&(f.epss_now>=0.10)).sum()}")
    p(f"exploited findings with CVSS < 7: {((f.cvss_now<7)&f.exploited_now).sum()} of {n_exp}")

    open(f"{out}/extended_analysis_log.txt", "w").write("\n".join(log) + "\n")


if __name__ == "__main__":
    main(*sys.argv[1:3])
