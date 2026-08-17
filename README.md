# Protect the Attacker — Kali Linux Hardening (GRC)

A hands-on **Governance, Risk & Compliance** project: audit a Kali Linux system like an attacker, then harden it like a defender — and document the full GRC cycle end to end.

The premise: penetration testers spend their time attacking others, but their own tooling and infrastructure are high-value targets. This project flips the script and secures the attacker's own machine, using professional tooling (Lynis) for discovery and the CIS Benchmark as the remediation standard.

---

## Result at a glance

| Metric | Initial | Final |
| --- | --- | --- |
| Hardening Index | 64 | **67** |
| Warnings | 1 | 1 |
| Suggestions | 56 | **43** |

**13 suggestions closed, 0 functionality broken.** Six findings remediated, one partially fixed with the rest accepted as risk, one accepted as risk, three assessed as already compliant.

> The modest index rise understates the work: Lynis weights Kali's deliberately-retained offensive tooling (Docker, exposed services, compilers) heavily. Those were intentionally left in place — the **−13 suggestions** figure is the honest measure. See the report's conclusion for the full reasoning.

---

## GRC cycle applied

**Identify** (Lynis audit) → **Analyze** (triage, risk register) → **Remediate** (CIS Benchmark) → **Map controls** (CIS + NIST 800-171) → **Document** (this report).

## Tools & Frameworks

- **Audit:** Lynis 3.1.6, `debsums`, `apt-listbugs`, `apt-show-versions`
- **Target:** Kali GNU/Linux Rolling (2026.3), Kernel 7.0.12+kali, VMware VM
- **Frameworks:** CIS Debian Linux 13 Benchmark v1.0.0 (primary), NIST 800-171

---

## Findings addressed

| Finding | CIS | Status |
| --- | --- | --- |
| AUTH-9328 — default umask | 5.4.3.3 | Done |
| AUTH-9286 — password aging | 5.4.1.1–5.4.1.3 | Done |
| AUTH-9230 — password hashing (yescrypt) | 5.4.1.4 | Compliant |
| BANN-7126/7130 — login banners | 1.6.2–1.6.6 | Done |
| BOOT-5122 — GRUB password | 1.4.1 | Done |
| ACCT-9628 — auditd (daemon + config + rules) | 6.2.1–6.2.3 | Done |
| PKGS/DEB — package verification tooling | — | Done |
| NETW-3200 — unused kernel modules | 3.2.3–3.2.6 | Done |
| SSH-7408 — SSH hardening | — | Partial / Accepted |
| NETW-2705 — nameserver resilience | — | Accepted Risk |
| CIS 1.2.1.3 — GPG key permissions (bonus) | 1.2.1.3 | Compliant |

---

## Repository structure

```
.
├── README.md                     ← you are here
├── report/
│   ├── report.md                 ← full audit report (source)
│   └── report.pdf                ← rendered deliverable
└── docs/
    ├── initial-scan/             ← baseline Lynis logs + summary
    ├── final-scan/               ← post-remediation Lynis logs + summary
    ├── backup-files/             ← config backups taken before edits
    └── screenshots/              ← evidence, organised per finding ID
```

Screenshots are grouped by Lynis finding ID (e.g. `docs/screenshots/BOOT-5122/`), each holding the before / remediation / after evidence referenced in the report.

---

## Read the report

Start with **`report/report.pdf`** for the full write-up: per-finding risk, mitigation, evidence, and control mappings, plus a conclusion on what the numbers do and don't say.

---

*Educational hardening exercise on a personal lab VM. Several CIS controls were deliberately not applied where disproportionate for an offensive-security workstation; each such decision is documented as an accepted risk in the report.*