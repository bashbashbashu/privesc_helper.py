# privesc_helper 

A tiny, friendly **privilege-escalation enumerator** for labs — written in Python, cross-platform (Linux & Windows), and focused on **collection-only** (no exploits included). 

> _“When the going gets tough and you've landed on user, use me and get root”_ some wise ol woman (maybe me)

---

##  Quick disclaimer (please read)
This tool is **for educational use only** — run it on machines you own or on systems where you have explicit written permission (CTFs, lab VMs, etc.).

**It does not exploit** vulnerabilities or attempt privilege escalation by itself; it just collects info and suggests potential leads.

---

## ✨ Features
- Auto-detects **Linux** vs **Windows** and runs platform-appropriate checks.  
- Produces both:
  - `privesc_report.txt` — human-friendly summary  
  - `privesc_report.json` — structured output for automation  
- Lightweight and quieter than full PEAS suites — great for quick triage.  
- Provides simple, actionable hints (e.g., writable PATH dirs, SUID files, unquoted service paths, suspicious registry keys).

---

##  What it collects (high level)

**Linux**
- `id`, `whoami`, kernel & `/etc/os-release`  
- `sudo -n -l` (non-interactive sudo checks)  
- Writable dirs in `$PATH`  
- SUID binaries (common-path sample)  
- File capabilities (`getcap` if available)  
- Cron jobs, root-owned processes, container hints (`/proc/1/cgroup`)  
- Environment variables and interesting file permissions

**Windows**
- `whoami` + groups/privileges  
- `systeminfo`, running processes, services  
- Scheduled tasks, UAC registry, `AlwaysInstallElevated` checks  
- Heuristic scan for unquoted service paths  
- Environment variables and common admin/user enumerations

---

##  Quick start

1. Clone your repo (or copy `privesc_helper.py`) to the target machine.

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
```

2. Make sure Python 3 is installed on the target.

3. Run:

```bash
# Linux
python3 privesc_helper.py

# Windows (PowerShell / CMD)
python privesc_helper.py
```

4. The script creates a timestamped folder like `privesc_helper_YYYYMMDD_HHMMSS/` containing:
- `privesc_report.txt` (human-readable)  
- `privesc_report.json` (machine-readable)

---

##  Example snippet (from `privesc_report.txt`)

```
Privilege Escalation Helper (Enumeration Only)
Timestamp (UTC): 2025-10-09_17:53
Platform: Linux-5.15.0-xx-x86_64
User: www-data

--- sudo -n -l ---
User may run the following commands:
  (root) NOPASSWD: /usr/bin/vim

--- SUID binaries (sample) ---
/usr/bin/passwd
/usr/bin/find

--- Potential leads ---
- Sudo NOPASSWD detected for /usr/bin/vim -> check GTFOBins
- Writable PATH dirs detected -> possible PATH hijack
```

---

##  How this helps you
- Faster triage than running a dozen manual commands.  
- Avoids noise from huge tools when you just need the essentials.  
- Easy to script: JSON output can be parsed to feed into your workflow or C2.  
- Great for teaching/practice: run it on a VM, review the output, then attempt safe privilege escalation in a controlled lab.

---

##  Extending & contributing
Want it dimmer, louder, or spicier?
- Add checks (e.g., `--deep` scans, HTML reports).  
- Add command-line flags (`--quick`, `--deep`, `--linux-only`, `--windows-only`).  
- Improve heuristics that map findings to GTFOBins/LOLBAS/PoCs (keep it enumeration-only if you plan to publish).

Contributions welcome — open an issue or PR with your idea!

---

##  License
MIT — use responsibly, I am not to blame for any illegal use.

---

## ❤️ Final note
If you want, I can add:
- A one-line install badge and quick-install snippet
- A tiny demo gif (recorded in a VM)
- Extra command-line flags for `--quick`/`--deep`

