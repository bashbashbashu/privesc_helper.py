#!/usr/bin/env python3
"""
privesc_helper.py

Cross-platform Privilege Escalation Enumerator (Linux & Windows)
- Modes: --quick (default) and --deep (slower, more thorough)
- Optional HTML output
- OS forcing flags (--linux-only, --windows-only)
- Outputs TXT + JSON and optional HTML
- --list-functions prints all checks/descriptions
- Enumeration-only: NO EXPLOITS, NO AUTOEXECUTION. Educational/lab use only.
"""

import os
import sys
import json
import platform
import argparse
import subprocess
import datetime
from pathlib import Path
from shutil import which
import html as html_lib

# ---------------------- Config / Mappings ----------------------
GTFOBINS = {
    "vim": "https://gtfobins.github.io/gtfobins/vim/",
    "nmap": "https://gtfobins.github.io/gtfobins/nmap/",
    "python": "https://gtfobins.github.io/gtfobins/python/",
    "bash": "https://gtfobins.github.io/gtfobins/bash/",
    "find": "https://gtfobins.github.io/gtfobins/find/",
    "less": "https://gtfobins.github.io/gtfobins/less/",
}

LOLBAS = {
    "certutil": "https://lolbas-project.github.io/lolbas/Binaries/CertUtil/",
    "bitsadmin": "https://lolbas-project.github.io/lolbas/Binaries/BITSAdmin/",
    "mshta": "https://lolbas-project.github.io/lolbas/Binaries/mshta/",
}

WINDOWS_PRIV_HINTS = {
    "seimpersonateprivilege": "Token impersonation (JuicyPotato / PrintSpoofer) research link: https://github.com/itm4n/juicy-potato",
}

# ---------------------- Function registry for --list-functions ----------------------
FUNCTIONS = [
    {
        "name": "id / whoami / uname",
        "platform": "Linux",
        "desc": "Basic user and kernel info: who you are, kernel, hostname."
    },
    {
        "name": "sudo -n -l",
        "platform": "Linux",
        "desc": "Non-interactive sudo listing (reveals NOPASSWD entries if present)."
    },
    {
        "name": "Writable PATH dirs",
        "platform": "Linux",
        "desc": "Checks PATH entries for write permissions (PATH hijack opportunities)."
    },
    {
        "name": "SUID binaries (sample / full)",
        "platform": "Linux",
        "desc": "Searches for SUID binaries in common paths (quick) or full filesystem (deep)."
    },
    {
        "name": "getcap -r /",
        "platform": "Linux",
        "desc": "Lists file capabilities (possible cap_setuid etc.)."
    },
    {
        "name": "crontab / cron dirs",
        "platform": "Linux",
        "desc": "Checks current user's crontab and system cron directories."
    },
    {
        "name": "ps aux (top / root)",
        "platform": "Linux",
        "desc": "Shows top processes or root-owned processes for suspicious services."
    },
    {
        "name": "/proc/1/cgroup",
        "platform": "Linux",
        "desc": "Container / Docker hints (are we inside container?)."
    },
    {
        "name": "whoami /whoami /priv + systeminfo",
        "platform": "Windows",
        "desc": "User identity, group membership, privileges and systeminfo."
    },
    {
        "name": "net user / net localgroup administrators",
        "platform": "Windows",
        "desc": "Lists local users and admin group membership."
    },
    {
        "name": "tasklist / sc query",
        "platform": "Windows",
        "desc": "Running processes and services list for suspicious high-privilege services."
    },
    {
        "name": "schtasks",
        "platform": "Windows",
        "desc": "Scheduled tasks - find tasks running as SYSTEM or admin."
    },
    {
        "name": "Registry UAC / AlwaysInstallElevated checks",
        "platform": "Windows",
        "desc": "Detects classic misconfigurations (EnableLUA, AlwaysInstallElevated)."
    },
    {
        "name": "Unquoted service paths heuristic",
        "platform": "Windows",
        "desc": "Scans services for unquoted BINARY_PATH_NAME values that could enable hijack."
    },
    {
        "name": "Environment dump",
        "platform": "Both",
        "desc": "Collects environment variables (useful for creds/paths)."
    },
    {
        "name": "GTFOBins/LOLBAS hinting",
        "platform": "Both",
        "desc": "If certain binaries or misconfigs found, suggest relevant GTFOBins/LOLBAS links (research only)."
    },
]

# ---------------------- Utilities ----------------------
def run(cmd, shell=False, timeout=30):
    """Run a command and return tuple (ok, stdout, stderr, rc)."""
    try:
        cp = subprocess.run(
            cmd,
            shell=shell,
            text=True,
            capture_output=True,
            timeout=timeout
        )
        out = (cp.stdout or "").strip()
        err = (cp.stderr or "").strip()
        return True, out, err, cp.returncode
    except Exception as e:
        return False, "", str(e), -1

def section(title):
    line = "=" * len(title)
    return f"{title}\n{line}\n"

def write_report(outdir: Path, text_body: str, json_body: dict, html_body: str=None):
    outdir.mkdir(parents=True, exist_ok=True)
    txt = outdir / "privesc_report.txt"
    jsn = outdir / "privesc_report.json"
    txt.write_text(text_body, encoding="utf-8", errors="ignore")
    jsn.write_text(json.dumps(json_body, indent=2), encoding="utf-8")
    if html_body:
        h = outdir / "privesc_report.html"
        h.write_text(html_body, encoding="utf-8")
    return txt, jsn

def env_to_dict():
    return dict(os.environ)

def add_block(text_list, title, content):
    text_list.append(section(title))
    text_list.append(content if content else "(no output)")
    text_list.append("")

# ---------------------- Linux Collection ----------------------
def linux_quick():
    text = []
    data = {}

    ok, out, _, _ = run(["id"])
    data["id"] = out; add_block(text, "id", out)

    for cmd in (["whoami"], ["uname","-a"], ["hostname"]):
        ok, out, _, _ = run(cmd)
        data[" ".join(cmd)] = out
        add_block(text, " ".join(cmd), out)

    osrel = ""
    try:
        osrel = Path("/etc/os-release").read_text(errors="ignore")
    except Exception:
        pass
    data["/etc/os-release"] = osrel; add_block(text, "/etc/os-release", osrel)

    ok, out, err, rc = run("sudo -n -l", shell=True)
    data["sudo_-n_-l"] = {"rc": rc, "stdout": out, "stderr": err}
    add_block(text, "sudo -n -l", out or err)

    # PATH writable check
    writable = []
    for d in (os.environ.get("PATH","").split(":")):
        p = Path(d)
        try:
            if p.exists() and os.access(p, os.W_OK):
                writable.append(str(p))
        except Exception:
            pass
    data["writable_path_dirs"] = writable
    add_block(text, "Writable PATH dirs", "\n".join(writable) if writable else "(none)")

    # SUID (sample common paths)
    suid_cmd = r'find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm -4000 -type f 2>/dev/null'
    ok, out, _, _ = run(suid_cmd, shell=True, timeout=30)
    suid_files = out.splitlines() if out else []
    data["suid_files_sample"] = suid_files
    add_block(text, "SUID binaries (common paths sample)", out)

    # minimal cron
    ok, out, _, _ = run("crontab -l", shell=True)
    data["crontab_current_user"] = out
    add_block(text, "crontab -l", out)

    # quick ps
    ok, out, _, _ = run("ps aux --sort=-%mem | head -n 20", shell=True)
    data["ps_top"] = out
    add_block(text, "Top processes (ps aux)", out)

    data["env"] = env_to_dict()
    add_block(text, "Environment", "\n".join(f"{k}={v}" for k,v in data["env"].items()))

    return "\n".join(text), data

def linux_deep():
    text = []
    data = {}

    # reuse quick base
    qt_text, qt_data = linux_quick()
    text.append(qt_text)
    data.update(qt_data)

    # deeper SUID search across filesystem (slow!)
    suid_cmd = r'find / -perm -4000 -type f -exec ls -ld {} \; 2>/dev/null'
    ok, out, _, _ = run(suid_cmd, shell=True, timeout=300)
    data["suid_files_full"] = out.splitlines() if out else []
    add_block(text, "SUID binaries (full search)", out)

    # getcap full
    if which("getcap"):
        ok, out, _, _ = run("getcap -r / 2>/dev/null", shell=True, timeout=120)
        data["file_capabilities_full"] = out.splitlines() if out else []
        add_block(text, "getcap -r /", out)

    # cron dirs
    cron_paths = ["/etc/cron.d","/etc/cron.daily","/etc/cron.hourly","/etc/cron.weekly","/etc/cron.monthly"]
    for p in cron_paths:
        ok, out, _, _ = run(f"ls -la {p}", shell=True)
        data[f"ls_{p}"] = out
        add_block(text, f"ls {p}", out)

    # full root processes
    ok, out, _, _ = run("ps aux | awk '$1==\"root\"{print $0}'", shell=True)
    data["root_processes_full"] = out.splitlines() if out else []
    add_block(text, "Root-owned processes (full)", out)

    # find interesting files
    interesting = []
    for p in ["/etc/passwd","/etc/shadow","/etc/sudoers","/var/www","/home"]:
        try:
            st = Path(p)
            if st.exists():
                interesting.append(str(p))
        except Exception:
            pass
    data["interesting_paths_exist"] = interesting
    add_block(text, "Interesting paths (exists)", "\n".join(interesting))

    return "\n".join(text), data

# ---------------------- Windows Collection ----------------------
def windows_quick():
    text = []
    data = {}

    for cmd in ["whoami","whoami /groups","whoami /priv","hostname","ver"]:
        ok, out, _, _ = run(cmd, shell=True)
        data[cmd] = out
        add_block(text, cmd, out)

    ok, out, _, _ = run("systeminfo", shell=True, timeout=60)
    data["systeminfo"] = out; add_block(text, "systeminfo", out)

    ok, out, _, _ = run("net user", shell=True)
    data["net_user"] = out; add_block(text, "net user", out)

    ok, out, _, _ = run("tasklist /v", shell=True, timeout=60)
    data["tasklist"] = out; add_block(text, "tasklist /v", out)

    ok, out, _, _ = run("sc query state= all", shell=True, timeout=60)
    data["services_raw"] = out; add_block(text, "sc query state= all", out)

    ok, out, _, _ = run("schtasks /query /fo LIST /v", shell=True, timeout=60)
    data["scheduled_tasks"] = out; add_block(text, "schtasks", out)

    ok, out, _, _ = run(r'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA', shell=True)
    data["UAC_EnableLUA"] = out; add_block(text, "UAC (EnableLUA)", out)

    # AlwaysInstallElevated checks
    for hive in ["HKCU","HKLM"]:
        cmd = rf'reg query {hive}\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated'
        ok, out, _, _ = run(cmd, shell=True)
        data[f"{hive}_AlwaysInstallElevated"] = out
        add_block(text, f"{hive} AlwaysInstallElevated", out)

    ok, out, _, _ = run("set", shell=True)
    data["env"] = dict([tuple(s.split("=",1)) for s in out.splitlines() if "=" in s]) if out else {}
    add_block(text, "Environment", out)

    return "\n".join(text), data

def windows_deep():
    text = []
    data = {}

    qt_text, qt_data = windows_quick()
    text.append(qt_text)
    data.update(qt_data)

    # Unquoted service paths heuristic
    services = []
    lines = (data.get("services_raw") or "").splitlines()
    for line in lines:
        if "SERVICE_NAME" in line:
            try:
                name = line.split(":",1)[1].strip()
                services.append(name)
            except Exception:
                pass

    unquoted = []
    for name in services[:500]:
        ok, out, _, _ = run(f'sc qc "{name}"', shell=True)
        if not out:
            continue
        for l in out.splitlines():
            if "BINARY_PATH_NAME" in l:
                path = l.split(":",1)[1].strip()
                if " " in path and not path.startswith('"'):
                    unquoted.append({"service": name, "path": path})
                break
    data["unquoted_service_paths_full"] = unquoted
    add_block(text, "Unquoted service paths (full sample)", "\n".join(f"{u['service']}: {u['path']}" for u in unquoted))

    return "\n".join(text), data

# ---------------------- Heuristics / Hints ----------------------
def suggest_linux(data):
    hints = []
    sudo_info = data.get("sudo_-n_-l", {})
    sudo_out = (sudo_info.get("stdout") or "").lower()
    if "nopasswd" in sudo_out or "may run the following" in sudo_out:
        hints.append("Sudo rights present (possibly NOPASSWD). Check entries and GTFOBins for safe escalation paths.")
        for key in GTFOBINS:
            if key in sudo_out:
                hints.append(f"Found sudo for {key} -> {GTFOBINS.get(key)}")

    if data.get("suid_files_sample"):
        hints.append("SUID binaries found in common paths. Review against GTFOBins for known privesc techniques.")

    if data.get("file_capabilities"):
        hints.append("Files with capabilities present. Some capabilities (e.g., cap_setuid) can enable escalation.")

    if data.get("writable_path_dirs"):
        hints.append("Writable directories in $PATH detected. Potential PATH hijack if privileged scripts/services are invoked.")

    if data.get("crontab_current_user"):
        hints.append("Cron entries present for current user. Look for writable scripts or misconfigured root crons.")

    if data.get("in_docker_group"):
        hints.append("User is in 'docker' group. Docker abuse can often escalate to root on host.")

    return hints

def suggest_windows(data):
    hints = []
    privs = (data.get("whoami /priv") or "").lower()
    for k,v in WINDOWS_PRIV_HINTS.items():
        if k in privs:
            hints.append(v)

    if (data.get("HKLM_AlwaysInstallElevated") or "").strip():
        hints.append("HKLM AlwaysInstallElevated configured. Combined with HKCU may allow MSI escalation. (Research only)")
    if (data.get("HKCU_AlwaysInstallElevated") or "").strip():
        hints.append("HKCU AlwaysInstallElevated configured. Combined with HKLM may allow MSI escalation. (Research only)")

    if data.get("unquoted_service_paths_full"):
        hints.append("Unquoted service paths detected. If writable directories exist in the path chain, service hijack may be possible.")
        hints.append("See: https://gtfobins.github.io/ and LOLBAS for guidance")

    uac = (data.get("UAC_EnableLUA") or "").lower()
    if "0x0" in uac:
        hints.append("UAC appears disabled. Elevation boundaries may be weaker.")

    return hints

# ---------------------- HTML Report ----------------------
def generate_html_report(title, header_info, text_body, json_body, hints):
    safe_title = html_lib.escape(title)
    header_html = "\n".join(f"<p><strong>{html_lib.escape(k)}</strong>: {html_lib.escape(str(v))}</p>" for k,v in header_info.items())
    hints_html = "\n".join(f"<li>{html_lib.escape(h)}</li>" for h in hints) if hints else "<li>(none)</li>"
    html = f"""
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <title>{safe_title}</title>
      <style>
        body {{ font-family: Arial, Helvetica, sans-serif; padding: 18px; background:#f7f7f9; color:#111; }}
        pre {{ background:#fff; padding:12px; border-radius:6px; box-shadow:0 0 4px rgba(0,0,0,.06); overflow:auto; max-height:500px }}
        h1,h2 {{ color:#222 }}
        .meta {{ margin-bottom:12px }}
      </style>
    </head>
    <body>
      <h1>{safe_title}</h1>
      <div class="meta">{header_html}</div>
      <h2>Potential leads / hints</h2>
      <ul>
        {hints_html}
      </ul>
      <h2>Raw output (text)</h2>
      <pre>{html_lib.escape(text_body)}</pre>
      <h2>Raw output (JSON)</h2>
      <pre>{html_lib.escape(json.dumps(json_body, indent=2))}</pre>
    </body>
    </html>
    """
    return html

# ---------------------- Help / function listing ----------------------
def print_function_list():
    print("Available checks & brief descriptions:\n")
    for f in FUNCTIONS:
        print(f" - {f['name']} [{f['platform']}]")
        print(f"     {f['desc']}\n")

# ---------------------- Main Entrypoint ----------------------
def main():
    parser = argparse.ArgumentParser(
        description="privesc_helper - cross-platform enumeration (lab use only)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--linux-only", action="store_true", help="Force Linux mode")
    group.add_argument("--windows-only", action="store_true", help="Force Windows mode")
    parser.add_argument("--deep", action="store_true", help="Run deep scans (slower, more noisy)")
    parser.add_argument("--quick", action="store_true", help="Run quick scan (default)")
    parser.add_argument("--html", action="store_true", help="Also write an HTML report")
    parser.add_argument("--outdir", type=str, default=None, help="Output directory (defaults to cwd/privesc_helper_TIMESTAMP)")
    parser.add_argument("--list-functions", action="store_true", help="Print a list of all checks the tool can perform and exit")
    args = parser.parse_args()

    if args.list_functions:
        print_function_list()
        sys.exit(0)

    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    default_outdir = Path.cwd() / f"privesc_helper_{ts}"
    outdir = Path(args.outdir) if args.outdir else default_outdir

    # header
    header = {
        "timestamp_utc": ts,
        "platform": platform.platform(),
    }
    try:
        header["user"] = os.getlogin()
    except Exception:
        header["user"] = os.environ.get("USERNAME") or os.environ.get("USER") or "(unknown)"

    # determine mode
    sysname = platform.system()
    forced = None
    if args.linux_only:
        forced = "Linux"
    elif args.windows_only:
        forced = "Windows"

    if forced:
        mode = forced
    else:
        mode = sysname

    quick_mode = True
    if args.deep:
        quick_mode = False

    # run collectors
    if mode == "Linux":
        if quick_mode:
            text_body, data = linux_quick()
        else:
            text_body, data = linux_deep()
        hints = suggest_linux(data)
    elif mode == "Windows":
        if quick_mode:
            text_body, data = windows_quick()
        else:
            text_body, data = windows_deep()
        hints = suggest_windows(data)
    else:
        print(f"[!] Unsupported/forced OS: {mode}")
        sys.exit(1)

    header_text = section("Privilege Escalation Helper (Enumeration Only)")
    header_text += f"Timestamp (UTC): {ts}\n"
    header_text += f"Platform: {platform.platform()}\n"
    header_text += f"User: {header.get('user')}\n\n"

    hints_text = "\n".join(f"- {h}" for h in hints) if hints else "(none)"
    full_text = header_text + text_body + section("Potential leads / hints") + hints_text + "\n"

    json_body = {
        "header": header,
        "mode": {"os_forced": forced, "detected": sysname, "used": mode, "quick_mode": quick_mode},
        "results": data,
        "hints": hints,
    }

    html_content = None
    if args.html:
        html_content = generate_html_report("privesc_helper report", header, full_text, json_body, hints)

    txt_path, json_path = write_report(outdir, full_text, json_body, html_content)

    print("[+] Enumeration complete.")
    print(f"[+] Text report : {txt_path}")
    print(f"[+] JSON report : {json_path}")
    if html_content:
        print(f"[+] HTML report : {outdir / 'privesc_report.html'}")
    print("[!] Reminder: Use ethically and legally in your own lab or with explicit written permission only.")


if __name__ == "__main__":
    main()
