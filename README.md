# Sentinel DNS — DNS Firewall for a Lab Network

CSE 324 lab project #4 · Team 66_B1 · 7 weeks (5 Nov – 23 Dec 2026)

A DNS server for a lab network with a DNS firewall, an ML detector and a web dashboard.
**BIND 9 answers the queries; Sentinel manages it.** Zones, firewall rules and query history live in
SQLite, and every change is written to BIND's configuration, zone files and response-policy zone (RPZ),
checked with `named-checkzone` / `named-checkconf` and applied with `rndc`.

**Live UI demo: https://xrenes.github.io/sentinel-dns/** (source: [`demo-site/`](demo-site/)) — a static,
clickable copy of the dashboard with sample data.
**Proposal:** [`docs/proposal/`](docs/proposal/)

## Progress tracker

| Week | Dates | Milestone | Status |
|------|-------|-----------|--------|
| W1 | 5–11 Nov | Planning & proposal slides | ✅ Done |
| W2 | 12–18 Nov | Proposal presentation (12 Nov); basic DNS: BIND, zones, recursion, RPZ, database | ✅ Done |
| W3 | 19–25 Nov | DNSSEC & threat feeds; records page | ⬜ Planned |
| W4 | 26 Nov–2 Dec | Firewall & management: validation, rate limiting, allow/block rules, policies page, `dnsctl` | ⬜ Planned |
| W5 | 3–9 Dec | All features complete: integration on the VM, AppArmor, HTTPS, login security, users & roles | ⬜ Planned |
| W6 | 10–16 Dec | Testing & measurement | ⬜ Planned |
| W7 | 17–23 Dec | Final report, demo & submission | ⬜ Planned |

Legend: ✅ done · 🔄 in progress · ⬜ planned

### Week-by-week tasks

<details open>
<summary><b>W1 — Planning & proposal</b> ✅</summary>

- [x] VM, network, static IP; slides: title, problem, scope — *Sayed Ifti Ahmed*
- [x] Study DNSSEC; slides: OS concepts, design — *Mackrajul*
- [x] Select threat feeds; slides: tools, plan, work split — *MD. Kaikobad*
- [x] Dashboard mock-up; slides: timeline, challenges, demo — *Rituparna Banik*
</details>

<details open>
<summary><b>W2 — Proposal presentation & basic DNS</b> ✅</summary>

- [x] Proposal presented (12 Nov)
- [x] BIND, both zones (`lab.local` + reverse), all record types — *Sayed Ifti Ahmed*
- [x] Recursion ACL, forwarders — *Mackrajul*
- [x] RPZ zone set up — *MD. Kaikobad*
- [x] Database & dashboard skeleton (static UI demo) — *Rituparna Banik*
</details>

<details>
<summary><b>W3 — DNSSEC & feeds</b></summary>

- [ ] Record tests, reverse zone — *Sayed Ifti Ahmed*
- [ ] Keys, signing, DS record — *Mackrajul*
- [ ] Feed download & parsing — *MD. Kaikobad*
- [ ] Records page — *Rituparna Banik*
</details>

<details>
<summary><b>W4 — Firewall & management</b></summary>

- [ ] `install.sh` draft — *Sayed Ifti Ahmed*
- [ ] Validation, rate limiting — *Mackrajul*
- [ ] Categories, allow/block rules — *MD. Kaikobad*
- [ ] Policies page, `dnsctl` — *Rituparna Banik*
</details>

<details>
<summary><b>W5 — All features complete</b></summary>

- [ ] Integrate all parts on the VM — *Sayed Ifti Ahmed*
- [ ] Permissions, AppArmor, HTTPS, login security — *Mackrajul*
- [ ] systemd timer, threat log — *MD. Kaikobad*
- [ ] Users & roles, analytics — *Rituparna Banik*
</details>

<details>
<summary><b>W6 — Testing & measurement</b></summary>

- [ ] Full install test, bug fixes — *Sayed Ifti Ahmed*
- [ ] Security tests — *Mackrajul*
- [ ] Firewall tests — *MD. Kaikobad*
- [ ] `measure.sh`, measurements — *Rituparna Banik*
</details>

<details>
<summary><b>W7 — Final report, demo & submission</b></summary>

- [ ] Report sections; demo: records — *Sayed Ifti Ahmed*
- [ ] Report sections; demo: DNSSEC — *Mackrajul*
- [ ] Report sections; demo: blocking — *MD. Kaikobad*
- [ ] Report editing; demo: dashboard — *Rituparna Banik*
</details>

## What is in the repository so far (W2)

```
dnscore/
  config.py, timeutil.py     runtime configuration (env variables), time zones
  db.py, schema.sql          SQLite database and schema
  validators.py              input validation (domains, IPs, records)
  zonefile.py                BIND zone-file renderer (lab.local + 56.168.192.in-addr.arpa)
  bind/render.py, sync.py    named.conf includes (recursion ACL, forwarders), zones, RPZ
  bind/ops.py                named-checkzone / named-checkconf / rndc wrapper
  policy.py, catalog.py      RPZ decision basics and block categories
  repositories/              records, settings, policies data access
demo-site/                   static UI demo of the dashboard (sample data)
scripts/build_static_demo.py rebuilds demo-site/ from the dashboard
docs/proposal/               project proposal
```

## Tech stack

BIND 9.18 on Ubuntu 24.04 (VirtualBox) · Python 3.12 · Flask · SQLite · dnspython · vanilla JS · Chart.js

## Team

Sayed Ifti Ahmed (lead) · Mackrajul · MD. Kaikobad · Rituparna Banik
