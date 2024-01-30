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

## 2. Persistence checks — where attackers hide

```bash
# Cron
for u in $(cut -d: -f1 /etc/passwd); do crontab -u "$u" -l 2>/dev/null; done
ls -la /etc/cron.* /var/spool/cron/

# Systemd units (look for recently-modified)
find /etc/systemd /lib/systemd /usr/lib/systemd /run/systemd -name '*.service' -newer /etc/hostname -ls
systemctl list-unit-files --state=enabled --type=service

# Login items (PAM, profile, etc.)
ls -la /root/.{bash_profile,bashrc,bash_login,profile} ~/.profile ~/.bashrc 2>/dev/null
ls -la /etc/profile.d/

# SUID/SGID
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -newer /etc/hostname -ls 2>/dev/null

# SSH
cat /etc/ssh/sshd_config | grep -E 'PermitRoot|PasswordAuth|Authorized'
find / -xdev -name 'authorized_keys*' -ls 2>/dev/null

# Init / rc
ls -la /etc/init.d /etc/rc*.d /etc/rc.local 2>/dev/null
```

---

## 3. Log triage

```bash
# auth.log — failed logins, sudo, su
grep -E 'Failed|Accepted|sudo|su\[' /var/log/auth.log | tail -100

# All log files modified in the last 24h
find /var/log -mtime -1 -ls

# journald (if systemd)
journalctl --since '2 hours ago' -p warning

# Common service logs
ls -la /var/log/{nginx,apache2,mysql,postgresql,redis,docker}/ 2>/dev/null

# Tampering: gaps in log timestamps
awk '{print $1, $2, $3}' /var/log/auth.log | uniq -c
```

---
