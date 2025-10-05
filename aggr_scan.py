#!/usr/bin/env python3
"""
deep_enum.py

All-in-one container/host enumeration script for CTFs / local test systems.

Performs:
 - basic system info
 - sudo privileges (sudo -l)
 - accurate SUID/SGID search
 - capability (CapEff) decoding
 - docker/socket/runtime checks
 - /proc (pid 1) and namespace info
 - mounts and overlay checks
 - world-writable/root-owned files search (limited)
 - cron jobs and sudoers inspection
 - ssh key checks
 - /etc/passwd and attempt /etc/shadow (with sudo)
 - lightweight network discovery (local net) with optional --aggressive
 - attempt to list listening sockets (ss/netstat)
 - optional: attempt to ls /proc/1/root (with sudo if available)

Use only on systems you own or are authorized to test.
"""
from __future__ import annotations
import os, sys, subprocess, re, socket, argparse, time
from ipaddress import IPv4Network
from typing import List, Tuple

TIMEOUT = 1.0

def run(cmd: str, timeout=20, capture_err=False) -> Tuple[int,str,str]:
    """Run shell cmd; return (rc, stdout, stderr)."""
    try:
        p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 255, "", f"TIMEOUT after {timeout}s"
    except Exception as e:
        return 254, "", f"ERR: {e}"

def header(title: str):
    print("\n" + "="*78)
    print("== " + title)
    print("="*78)

def basic_info():
    header("Basic system & identity")
    rc, out, err = run("uname -a")
    print("uname:", out or err)
    print("user id / groups:", run("id")[1])
    print("EUID:", os.geteuid(), "Effective username:", os.getenv("USER"))
    for f in ("/etc/os-release","/etc/issue"):
        if os.path.exists(f):
            print(f"\n{f}:\n", open(f).read().strip())

def check_sudo():
    header("SUDO checks")
    # -l (may prompt) and -n (non-interactive)
    rc, out, err = run("sudo -l", timeout=10)
    if rc == 0:
        print("sudo -l (interactive) output:\n", out)
    else:
        print("sudo -l failed or requires password. (rc=%s) stderr: %s" % (rc, err))
    rc2, out2, err2 = run("sudo -l -n 2>&1 || true", timeout=5)
    print("\nsudo -l -n (non-interactive) output:\n", out2 or "(no output)")

def find_suid(paths:List[str]=None, limit=500):
    header("SUID/SGID binaries (accurate search)")
    if paths is None:
        paths=["/bin","/sbin","/usr/bin","/usr/sbin","/usr/local/bin","/usr/local/sbin"]
    # build find command to limit time
    paths_str = " ".join(paths)
    find_cmd = f"find {paths_str} -xdev -type f \\( -perm -4000 -o -perm -2000 \\) -ls 2>/dev/null | sed -n '1,{limit}p'"
    rc, out, err = run(find_cmd, timeout=60)
    if out.strip()=="":
        print("No SUID/SGID files found in common paths (or none readable).")
    else:
        print(out)

def decode_CapEff():
    header("Capabilities (CapEff)")
    try:
        s = open("/proc/self/status").read()
        m = re.search(r"CapEff:\s*([0-9a-fA-F]+)", s)
        caphex = m.group(1) if m else None
        if caphex:
            capint = int(caphex, 16)
            print("CapEff hex:", caphex)
            # capability names (first 38 approx)
            caps = [
                "CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_DAC_READ_SEARCH","CAP_FOWNER","CAP_FSETID",
                "CAP_KILL","CAP_SETGID","CAP_SETUID","CAP_SETPCAP","CAP_LINUX_IMMUTABLE",
                "CAP_NET_BIND_SERVICE","CAP_NET_BROADCAST","CAP_NET_ADMIN","CAP_NET_RAW",
                "CAP_IPC_LOCK","CAP_IPC_OWNER","CAP_SYS_MODULE","CAP_SYS_RAWIO","CAP_SYS_CHROOT",
                "CAP_SYS_PTRACE","CAP_SYS_PACCT","CAP_SYS_ADMIN","CAP_SYS_BOOT","CAP_SYS_NICE",
                "CAP_SYS_RESOURCE","CAP_SYS_TIME","CAP_SYS_TTY_CONFIG","CAP_MKNOD","CAP_LEASE",
                "CAP_AUDIT_WRITE","CAP_AUDIT_CONTROL","CAP_SETFCAP","CAP_MAC_OVERRIDE","CAP_MAC_ADMIN",
                "CAP_SYSLOG","CAP_WAKE_ALARM","CAP_BLOCK_SUSPEND","CAP_AUDIT_READ"
            ]
            have=[]
            for i,name in enumerate(caps):
                if capint & (1 << i):
                    have.append(name)
            print("Effective capabilities:", ", ".join(have) if have else "<none>")
        else:
            print("Could not parse CapEff from /proc/self/status.")
    except Exception as e:
        print("Error reading capabilities:", e)

def docker_checks():
    header("Docker / container runtime artifacts")
    candidates = ["/var/run/docker.sock","/run/docker.sock","/run/containerd/containerd.sock","/run/podman/podman.sock"]
    for p in candidates:
        try:
            print(f"{p}: exists={os.path.exists(p)}", end="")
            if os.path.exists(p):
                st = os.stat(p)
                print(f", mode={oct(st.st_mode & 0o777)}, uid={st.st_uid}, gid={st.st_gid}")
            else:
                print("")
        except Exception as e:
            print(" - err:", e)
    # docker binary
    rc,out,err = run("which docker || true")
    print("docker binary:", out or "(not found)")
    if out:
        print("docker --version:", run("docker --version")[1])
    # listeners
    rc, out, err = run("ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null", timeout=10)
    print("\nListening TCP sockets (ss/netstat output snippet):")
    if out.strip()=="":
        print("(no output or requires privileges)")
    else:
        print("\n".join(out.splitlines()[:50]))

def proc_and_mounts():
    header("PID 1, cgroups, mounts, namespaces")
    try:
        cmdline = open("/proc/1/cmdline","rb").read().replace(b'\x00', b' ').decode().strip()
        print("PID 1 cmdline:", cmdline)
    except Exception as e:
        print("PID 1 cmdline: err:", e)
    try:
        cg = open("/proc/self/cgroup").read().strip()
        print("\n/proc/self/cgroup:\n", cg)
    except Exception as e:
        print("/proc/self/cgroup: err:", e)
    # /proc/1/root ls (will fail without privileges)
    try:
        print("\n/proc/1/root ->", os.readlink("/proc/1/root"))
    except Exception as e:
        print("/proc/1/root readlink err:", e)
    # mounts
    rc,out,err = run("mount | sed -n '1,80p'")
    print("\nMounts (first lines):")
    print(out or err)

def sudoers_and_files():
    header("Sudoers files and sudo-related config")
    rc,out,err = run("ls -l /etc/sudoers /etc/sudoers.d 2>/dev/null || true")
    print(out or err)
    # show fragments
    rc,out,err = run("for f in /etc/sudoers.d/*; do echo '----' $f; sed -n '1,200p' $f 2>/dev/null; done", timeout=15)
    print(out or "(no fragments readable)")

def find_world_writable(limit=200):
    header("World-writable root-owned files (limited)")
    # limited search to avoid long runtime
    cmd = "find / -xdev -type f -perm -0002 -uid 0 -ls 2>/dev/null | sed -n '1,%d p'" % limit
    rc,out,err = run(cmd, timeout=40)
    print(out or "(none found or permission denied)")

def cron_checks():
    header("Cron and scheduled tasks")
    rc,out,err = run("ls -la /etc/cron* /var/spool/cron* 2>/dev/null || true", timeout=10)
    print(out or "(no cron dirs found)")
    # show crontabs for root (if readable)
    rc,out,err = run("crontab -l 2>/dev/null || true")
    print("\ncrontab -l (current user):\n", out or "(none or not allowed)")

def ssh_key_checks():
    header("SSH key checks (private keys / authorized_keys)")
    candidates = ["/root/.ssh/id_rsa","/root/.ssh/authorized_keys","/home/*/.ssh/id_rsa","/home/*/.ssh/authorized_keys"]
    for p in candidates:
        rc,out,err = run(f"ls -la {p} 2>/dev/null || true")
        if out.strip():
            print(out)

def passwd_shadow():
    header("/etc/passwd and /etc/shadow checks")
    rc,out,err = run("sed -n '1,200p' /etc/passwd")
    print("/etc/passwd:\n", out or err)
    # attempt to read /etc/shadow with sudo (may prompt)
    rc,out,err = run("sudo cat /etc/shadow 2>/dev/null || true", timeout=5)
    if out.strip():
        print("\n/etc/shadow (NOTE: you used sudo to read this):\n", out.splitlines()[:50])
    else:
        print("\n/etc/shadow not readable (no sudo or permission).")

def lightweight_scan(aggressive=False):
    header("Lightweight network discovery")
    rc,out,err = run("ip -o addr || ip addr", timeout=5)
    ips = []
    for ln in out.splitlines():
        m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', ln)
        if m:
            ips.append(f"{m.group(1)}/{m.group(2)}")
    print("Detected addresses:", ips)
    rc, route, err = run("ip route show")
    print("\nIP route:\n", route or err)
    # For each /24+/ prefix, do a small TCP connect on common ports
    ports = [22,80,443,2375,2376,3306,5432,8080,8000,5000]
    for addr in ips:
        ipstr, prefix = addr.split("/")
        prefix = int(prefix)
        if ipstr.startswith("127."): continue
        # if aggressive, allow scanning less-restrictive prefixes; if not, only /24..30
        if not aggressive and (prefix < 24 or prefix > 30):
            continue
        try:
            net = IPv4Network(f"{ipstr}/{prefix}", strict=False)
            hosts = list(net.hosts())[:128] if aggressive else list(net.hosts())[:32]
            print(f"\nScanning {len(hosts)} hosts in {net} on ports {ports} (timeout {TIMEOUT}s)...")
            found=[]
            for h in hosts:
                hstr=str(h)
                for p in ports:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(TIMEOUT)
                    try:
                        r = s.connect_ex((hstr,p))
                        s.close()
                        if r==0:
                            print(f" {hstr}:{p} OPEN")
                            found.append((hstr,p))
                            break
                    except Exception:
                        pass
            if not found:
                print("No open common ports found in this range (or network blocks connect).")
        except Exception as e:
            print("Network scan error:", e)

def main():
    parser = argparse.ArgumentParser(description="Deep enumeration for containers/hosts (CTF use only).")
    parser.add_argument("--aggressive", action="store_true", help="Enable wider host scanning")
    parser.add_argument("--suid-paths", nargs="*", help="Paths to search for SUID/SGID")
    args = parser.parse_args()

    print("Enumeration started:", time.ctime())
    basic_info()
    proc_and_mounts()
    decode_CapEff()
    docker_checks()
    check_sudo()
    find_suid(paths=args.suid_paths)
    sudoers_and_files()
    find_world_writable()
    cron_checks()
    ssh_key_checks()
    passwd_shadow()
    lightweight_scan(aggressive=args.aggressive)

    header("Quick actionable summary")
    print("- If 'sudo -l' lists commands or NOPASSWD entries, that's the fastest escalation path.")
    print("- SUID/SGID binaries found above are worth checking against known local privesc checklists.")
    print("- CapEff above: CAP_SYS_ADMIN, CAP_SYS_MODULE, CAP_SYS_PTRACE etc are powerful.")
    print("- Docker socket presence allows interacting with the daemon if readable.")
    print("- World-writable root-owned files or writable cron scripts are high-value leads.")
    print("\nDone.")

if __name__ == "__main__":
    main()
