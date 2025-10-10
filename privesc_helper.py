#!/usr/bin/env python3
# privesc_helper.py
# Cross-platform (Windows + Linux) privilege escalation enumerator.
# Collection-only (no exploitation). For lab/educational use.

import os
import sys
import json
import platform
import subprocess
import datetime
from pathlib import Path
from shutil import which

# ---------------------- Utils ----------------------

def run(cmd, shell=False, timeout=30):
    """
    Run a command and return (ok, stdout, stderr, rc).
    - On Windows, many built-ins need shell=True (cmd.exe).
    - Avoids throwing; always returns a tuple.
    """
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

def write_report(outdir, text_body, json_body):
    outdir.mkdir(parents=True, exist_ok=True)
    txt = outdir / "privesc_report.txt"
    jsn = outdir / "privesc_report.json"
    txt.write_text(text_body, encoding="utf-8", errors="ignore")
    jsn.write_text(json.dumps(json_body, indent=2), encoding="utf-8")
    return txt, jsn

def env_to_dict():
    return dict(os.environ)

def add_block(text_list, title, content):
    text_list.append(section(title))
    text_list.append(content if content else "(no output)")
    text_list.append("")  # blank line

# ---------------------- Linux ----------------------

def linux_collect():
    text = []
    data = {}

    # Basic host/user
    ok, out, _, _ = run(["id"])
    data["id"] = out; add_block(text, "id", out)

    for cmd in (["whoami"], ["uname", "-a"], ["hostname"]):
        ok, out, _, _ = run(cmd)
        data[" ".join(cmd)] = out
        add_block(text, " ".join(cmd), out)

    # /etc/os-release
    osrel = ""
    try:
        osrel = Path("/etc/os-release").read_text(errors="ignore")
    except Exception:
        pass
    data["/etc/os-release"] = osrel; add_block(text, "/etc/os-release", osrel)

    # sudo -n -l (non-interactive)
    ok, out, err, rc = run("sudo -n -l", shell=True)
    data["sudo_-n_-l"] = {"rc": rc, "stdout": out, "stderr": err}
    add_block(text, "sudo -n -l", out or err)

    # PATH writeable dirs
    writable = []
    for d in (os.environ.get("PATH","").split(":")):
        p = Path(d)
        try:
            if p.exists() and os.access(p, os.W_OK):
                writable.append(str(p))
        except Exception:
            pass
    data["writable_path_dirs"] = writable
    add_block(text, "Writable PATH dirs", "\n".join(writable) if writable else "")

    # SUID (common paths, limited scope for speed)
    suid_cmd = r'find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm -4000 -type f 2>/dev/null'
    ok, out, _, _ = run(suid_cmd, shell=True, timeout=60)
    suid_files = out.splitlines() if out else []
    data["suid_files_sample"] = suid_files
    add_block(text, "SUID binaries (common paths sample)", out)

    # Capabilities (if getcap present)
    caps_out = ""
    if which("getcap"):
        ok, out, _, _ = run("getcap -r / 2>/dev/null", shell=True, timeout=60)
        caps_out = out
    data["file_capabilities"] = caps_out.splitlines() if caps_out else []
    add_block(text, "File capabilities", caps_out)

    # Cron
    cron_cmds = [
        "crontab -l",
        "ls -la /etc/cron.d",
        "ls -la /etc/cron.daily",
        "ls -la /etc/cron.hourly",
        "ls -la /etc/cron.weekly",
        "ls -la /etc/cron.monthly",
        "cat /etc/crontab"
    ]
    cron_blocks = []
    for c in cron_cmds:
        ok, out, _, _ = run(c, shell=True)
        cron_blocks.append({"cmd": c, "out": out})
        add_block(text, c, out)
    data["cron"] = cron_blocks

    # Root-owned processes
    ok, out, _, _ = run("ps aux | awk '$1==\"root\"{print $0}'", shell=True)
    data["root_processes_sample"] = out.splitlines() if out else []
    add_block(text, "Root-owned processes (sample)", out)

    # Interesting file perms
    interesting = []
    for p in ["/etc/passwd","/etc/shadow","/etc/sudoers"]:
        try:
            st = Path(p).stat()
            readable = os.access(p, os.R_OK)
            interesting.append({"path": p, "readable": readable, "mode": oct(st.st_mode)[-4:]})
        except Exception:
            interesting.append({"path": p, "readable": False, "mode": "?"})
    data["interesting_files"] = interesting
    add_block(text, "Interesting files",
              "\n".join(f"{i['path']} readable={i['readable']} mode={i['mode']}" for i in interesting))

    # Docker membership / container hint
    ok, out, _, _ = run("getent group docker", shell=True)
    data["in_docker_group"] = ("docker" in (out or ""))
    add_block(text, "getent group docker", out)
    cgroup = ""
    try:
        cgroup = Path("/proc/1/cgroup").read_text(errors="ignore")
    except Exception:
        pass
    data["/proc/1/cgroup"] = cgroup
    add_block(text, "/proc/1/cgroup", cgroup)

    # Environment
    data["env"] = env_to_dict()
    add_block(text, "Environment", "\n".join(f"{k}={v}" for k,v in data["env"].items()))

    return "\n".join(text), data

# ---------------------- Windows ----------------------

def windows_collect():
    text = []
    data = {}

    # Core info
    for cmd in [
        "whoami",
        "whoami /groups",
        "whoami /priv",
        "hostname",
        "ver"
    ]:
        ok, out, _, _ = run(cmd, shell=True)
        data[cmd] = out
        add_block(text, cmd, out)

    # Systeminfo
    ok, out, _, _ = run("systeminfo", shell=True, timeout=90)
    data["systeminfo"] = out; add_block(text, "systeminfo", out)

    # Users and admins
    for cmd in ["net user", "net localgroup administrators"]:
        ok, out, _, _ = run(cmd, shell=True)
        data[cmd] = out; add_block(text, cmd, out)

    # Processes
    ok, out, _, _ = run("tasklist /v", shell=True, timeout=90)
    data["tasklist"] = out; add_block(text, "tasklist /v", out)

    # Services
    ok, out, _, _ = run("sc query state= all", shell=True, timeout=90)
    data["services_raw"] = out; add_block(text, "sc query state= all", out)

    # Scheduled tasks
    ok, out, _, _ = run("schtasks /query /fo LIST /v", shell=True, timeout=90)
    data["scheduled_tasks"] = out; add_block(text, "schtasks /query /fo LIST /v", out)

    # UAC setting
    ok, out, _, _ = run(r'reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA', shell=True)
    data["UAC_EnableLUA"] = out; add_block(text, "UAC (EnableLUA)", out)

    # AlwaysInstallElevated (classic misconfig)
    for hive in ["HKCU", "HKLM"]:
        cmd = rf'reg query {hive}\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated'
        ok, out, _, _ = run(cmd, shell=True)
        data[f"{hive}_AlwaysInstallElevated"] = out
        add_block(text, f"{hive} AlwaysInstallElevated", out)

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
    for name in services[:200]:  # sample for speed
        ok, out, _, _ = run(f'sc qc "{name}"', shell=True)
        if not out: 
            continue
        for l in out.splitlines():
            if "BINARY_PATH_NAME" in l:
                path = l.split(":",1)[1].strip()
                if " " in path and not path.startswith('"'):
                    unquoted.append({"service": name, "path": path})
                break
    data["unquoted_service_paths_sample"] = unquoted
    add_block(text, "Unquoted service paths (sample)",
              "\n".join(f"{u['service']}: {u['path']}" for u in unquoted))

    # Env
    ok, out, _, _ = run("set", shell=True)
    data["env"] = dict([tuple(s.split("=",1)) for s in out.splitlines() if "=" in s]) if out else {}
    add_block(text, "Environment", out)

    return "\n".join(text), data

# ---------------------- Hints (lightweight) ----------------------

def suggest_linux(data):
    hints = []

    # sudo -n -l output
    sudo_info = data.get("sudo_-n_-l", {})
    sudo_out = (sudo_info.get("stdout") or "").lower()
    if "nopasswd" in sudo_out or "may run the following" in sudo_out:
        hints.append("Sudo rights present (possibly NOPASSWD). Check entries and GTFOBins for safe escalation paths.")

    # SUID & caps
    if data.get("suid_files_sample"):
        hints.append("SUID binaries found in common paths. Review against GTFOBins for known privesc techniques.")
    if data.get("file_capabilities"):
        hints.append("Files with capabilities present. Some caps (e.g., cap_setuid) can enable escalation.")

    # Writable PATH
    if data.get("writable_path_dirs"):
        hints.append("Writable directories in $PATH detected. Potential PATH hijack if privileged scripts/services are invoked.")

    # Cron
    if data.get("cron"):
        hints.append("Cron entries present. Look for writable scripts or misconfigurations invoked by root.")

    # Docker
    if data.get("in_docker_group"):
        hints.append("User is in 'docker' group. Docker abuse can often escalate to root on the host.")

    return hints

def suggest_windows(data):
    hints = []
    privs = (data.get("whoami /priv") or "").lower()
    if "seimpersonateprivilege" in privs or "seassignprimarytokenprivilege" in privs:
        hints.append("Token privileges (e.g., SeImpersonatePrivilege) enabled. Research token impersonation techniques.")

    if (data.get("HKLM_AlwaysInstallElevated") or "").strip():
        hints.append("HKLM AlwaysInstallElevated configured. Combined with HKCU may allow MSI escalation.")
    if (data.get("HKCU_AlwaysInstallElevated") or "").strip():
        hints.append("HKCU AlwaysInstallElevated configured. Combined with HKLM may allow MSI escalation.")

    if data.get("unquoted_service_paths_sample"):
        hints.append("Unquoted service paths detected. If writable directories exist in the path chain, service hijack may be possible.")

    # UAC
    uac = (data.get("UAC_EnableLUA") or "").lower()
    if "0x0" in uac:
        hints.append("UAC appears disabled. Elevation boundaries may be weaker.")

    return hints

# ---------------------- Main ----------------------

def main():
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    outdir = Path.cwd() / f"privesc_helper_{ts}"

    header = section("Privilege Escalation Helper (Enumeration Only)")
    header += f"Timestamp (UTC): {ts}\n"
    header += f"Platform: {platform.platform()}\n"
    try:
        user_display = os.getlogin()
    except Exception:
        user_display = os.environ.get("USERNAME") or os.environ.get("USER") or "(unknown)"
    header += f"User: {user_display}\n\n"

    sysname = platform.system()
    if sysname == "Windows":
        text_body, data = windows_collect()
        hints = suggest_windows(data)
    elif sysname == "Linux":
        text_body, data = linux_collect()
        hints = suggest_linux(data)
    else:
        print(f"[!] Unsupported OS: {sysname}")
        sys.exit(1)

    # Append hints
    hints_text = "\n".join(f"- {h}" for h in hints) if hints else "(none)"
    text_body = header + text_body + section("Potential leads / hints") + hints_text + "\n"

    # JSON
    json_body = {
        "timestamp_utc": ts,
        "platform": platform.platform(),
        "user": user_display,
        "os_family": sysname,
        "results": data,
        "hints": hints
    }

    txt_path, json_path = write_report(outdir, text_body, json_body)

    print("[+] Enumeration complete.")
    print(f"[+] Text report : {txt_path}")
    print(f"[+] JSON report : {json_path}")
    print("[!] Use ethically and legally in your own lab or with explicit written permission only.")

if __name__ == "__main__":
    main()
