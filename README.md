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

## 1. Volatile data — collect first

```bash
# Memory dump (LiME or AVML if pre-installed; otherwise /proc/kcore copy)
date -u +%FT%TZ
uptime
who
last -F | head
ss -anpe         # all sockets, with PID + uid
ip -s addr
ip -s route
arp -an
ip neigh
ps auxfww
ps -eo pid,ppid,user,start,etime,cmd --sort=start
top -b -n1 -o %CPU | head -40
lsof -P -n -i +c0  # all open sockets, no DNS lookups, no command truncation
lsof +L1            # files with no link count (deleted but held)
```

Save all that to a single `volatile-$(date +%s).txt` and move it OFF the box
before doing anything else.

---
