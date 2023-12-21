# linux-ir-cheatsheet

A single-page first-responder cheatsheet for Linux incident response — the
commands I run when something is on fire and I don't have time to look stuff
up. Started this in late 2023 from class notes, kept tweaking it through
final-year coursework, KPI club lab work, and home-lab tinkering.

> **Audience:** me, plus anyone in the KPI student cybersec club. **Not** an
> exhaustive IR guide — there are better ones (SANS, Volatility's own docs,
> Mandiant). This is just my "hands-on-the-keyboard" reference.

---

## 0. Don't make it worse

Before anything else:

- Snapshot first if you can — VM snapshot, `dd` of disk, ZFS clone. Live
  triage destroys evidence.
- If you must work live, write to a **different** disk than the suspect one.
- Time-stamp every command. `script -t triage.timing triage.log` keeps a
  reproducible session.
- Don't reboot. Memory is gone after reboot.

---
