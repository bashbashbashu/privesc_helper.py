# privesc_helper 

A tiny, friendly **privilege-escalation enumerator** for labs — written in Python, cross-platform (Linux & Windows), and focused on **collection-only** (no exploits included). 

> _“When the going gets tough and you've landed on user, use me and get root”_ some wise ol woman (maybe me)

---

##  Quick disclaimer (please read)
This tool is **for educational use only** — run it on machines you own or on systems where you have explicit written permission (CTFs, lab VMs, etc.).

**It does not exploit** vulnerabilities or attempt privilege escalation by itself; it just collects info and suggests potential leads.

---

## Features
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

---

### What it checks (concise)
- **User & Host**: `id`, `whoami`, `hostname`, `uname -a`.
- **Sudo**: `sudo -n -l` (non-interactive sudo rights; looks for NOPASSWD entries).
- **SUID binaries**: quick scan in common paths (`--quick`) or full `find / -perm -4000` (`--deep`).
- **File capabilities**: `getcap -r /` when available.
- **Writable PATH dirs**: detects directories in `$PATH` you can write to (PATH hijack vector).
- **Cron jobs**: current user crontab and system cron directories.
- **Processes & Services**: `ps`, `tasklist`, `sc query` to identify high-privilege services.
- **Scheduled tasks (Windows)**: `schtasks` output parsing.
- **Unquoted service paths (Windows)**: heuristic scan of `sc qc` outputs.
- **UAC / AlwaysInstallElevated (Windows)**: registry checks for common misconfigurations.
- **Environment dump**: collects environment variables (useful for creds/paths).
- **Hints**: maps findings to GTFOBins/LOLBAS links for research (enumeration-only).

---

### How to use (examples)
- **Quick (default / fast)** — good for initial triage:
```bash
python3 privesc_helper.py
```

- **Deep Linux scan** — slow but thorough SUID & capabilities search:
```bash
python3 privesc_helper.py --deep --linux-only --outdir /tmp/privesc_deep
```

- **Deep Windows scan with HTML report**:
```powershell
python privesc_helper.py --deep --windows-only --html --outdir C:\privesc_out
```

- **List all checks the tool can run**:
```bash
python3 privesc_helper.py --list-functions
```

- **Save output to custom folder**:
```bash
python3 privesc_helper.py --outdir ./my_report
```

---

### Notes & safety
- The tool is **enumeration-only**: it does not exploit, run PoCs, or change system state.  
- Use `--deep` only on lab systems—it can be noisy and slow.  


## How this helps you
- Faster triage than running a dozen manual commands.  
- Avoids noise from huge tools when you just need the essentials.  
- Easy to script: JSON output can be parsed to feed into your workflow or C2.  
- Great for teaching/practice: run it on a VM, review the output, then attempt safe privilege escalation in a controlled lab.

---

##  License
MIT — use responsibly, I am not to blame for any illegal use.

