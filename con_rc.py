#!/usr/bin/env python3
"""
enum_container.py

Lightweight enumeration script to map container environment and
surface common configuration issues that could enable breakout/escalation.

Outputs human-readable sections. Safe for CTF use (no exploit code).
"""

import os
import sys
import subprocess
import socket
import struct
import fcntl
import re
import time
from ipaddress import IPv4Network, IPv4Address

TIMEOUT = 1.0  # socket connect timeout

def run_cmd(cmd):
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, text=True, timeout=10)
        return p.stdout.strip(), p.stderr.strip(), p.returncode
    except Exception as e:
        return "", str(e), 255

def header(t):
    print("\n" + "="*78)
    print("== " + t)
    print("="*78)

def basic_info():
    header("Basic system & identity")
    uname_o, _, _ = run_cmd("uname -a")
    print("uname:", uname_o)
    whoami, _, _ = run_cmd("id")
    print("id:", whoami)
    print("Effective UID:", os.geteuid())
    print("Home:", os.path.expanduser("~"))
    # OS release files
    for f in ["/etc/os-release", "/etc/issue"]:
        if os.path.exists(f):
            print(f"\nContents of {f}:")
            try:
                print(open(f,'r').read().strip())
            except Exception as e:
                print("  <error reading>", e)

def proc_and_cgroups():
    header("Process, PID 1, and cgroups")
    # PID 1 info
    try:
        with open("/proc/1/cmdline","rb") as f:
            cmd = f.read().replace(b'\x00', b' ').decode().strip()
            print("PID 1 cmdline:", cmd)
    except Exception as e:
        print("PID 1 cmdline: <err>", e)

    # /proc/self/cgroup
    try:
        cg = open("/proc/self/cgroup").read().strip()
        print("\n/proc/self/cgroup:\n", cg)
    except Exception as e:
        print("/proc/self/cgroup: <err>", e)

    # mounts
    mounts, _, _ = run_cmd("mount")
    print("\nMounts (first 40 lines):")
    for ln in mounts.splitlines()[:40]:
        print(" ", ln)

def ns_and_procroot():
    header("Namespaces & potential host root visibility")
    # check /proc/1/root and readlink
    try:
        link = os.readlink("/proc/1/root")
        print("/proc/1/root ->", link)
    except Exception as e:
        print("Could not read /proc/1/root:", e)
    # check /proc/self/ns
    try:
        nss = run_cmd("ls -l /proc/self/ns")[0]
        print("\n/proc/self/ns:\n", nss)
    except Exception as e:
        print("/proc/self/ns: <err>", e)

def docker_artifacts():
    header("Docker-related artifacts")
    # docker sock
    sock = "/var/run/docker.sock"
    print("Docker socket exists:", os.path.exists(sock))
    if os.path.exists(sock):
        st = os.stat(sock)
        print(" docker.sock mode:", oct(st.st_mode & 0o777), "uid:", st.st_uid, "gid:", st.st_gid)
    # docker binary
    out, err, rc = run_cmd("which docker || true")
    print("docker binary path:", out or "<not found>")
    if out:
        v, _, _ = run_cmd("docker --version")
        print("docker --version:", v)

def capabilities():
    header("Capabilities (process effective capabilities)")
    # parse /proc/self/status CapEff
    try:
        s = open("/proc/self/status").read()
        m = re.search(r"CapEff:\s*([0-9a-fA-F]+)", s)
        if m:
            caphex = m.group(1)
            capint = int(caphexe, 16)
            print("CapEff (hex):", caphex)
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
            have = []
            for i,name in enumerate(caps):
                if capint & (1 << i):
                    have.append(name)
            print("Effective capabilities:", ", ".join(have) if have else "<none>")
        else:
            print("Could not find CapEff in /proc/self/status")
    except Exception as e:
        print("Error reading capabilities:", e)

def suid_files(limit=200):
    header("SUID/SGID binaries (may indicate local privilege escalation paths)")
    print("Searching common paths for SUID/SGID (this may take a few seconds)...")
    # Limit search to common binary directories to save time
    paths = ["/bin","/sbin","/usr/bin","/usr/sbin","/usr/local/bin","/usr/local/sbin"]
    found = []
    for p in paths:
        for root,dirs,files in os.walk(p, topdown=True):
            for f in files:
                fp = os.path.join(root,f)
                try:
                    st = os.stat(fp)
                    if (st.st_mode & 0o4000) or (st.st_mode & 0o2000):
                        found.append((fp, oct(st.st_mode & 0o777), st.st_uid, st.st_gid))
                except Exception:
                    pass
            # speed limit
            if len(found) >= limit:
                break
        if len(found) >= limit:
            break
    if not found:
        print("No SUID/SGID found in common paths.")
    else:
        for fp,mode,uid,gid in found[:limit]:
            print(f"{fp} mode={mode} uid={uid} gid={gid}")

def file_access_checks():
    header("Sensitive file access checks")
    checks = [
        ("/etc/shadow","/etc/shadow"),
        ("/var/run/docker.sock","/var/run/docker.sock"),
        ("/root/.ssh/authorized_keys","/root/.ssh/authorized_keys"),
        ("/root/.ssh/id_rsa","/root/.ssh/id_rsa"),
    ]
    for name,path in checks:
        try:
            ok = os.access(path, os.R_OK)
            print(f"{path} readable: {ok}")
        except Exception as e:
            print(f"{path}: <err> {e}")

def filesystem_writable():
    header("Filesystem writeability checks")
    for p in ["/","/root","/tmp","/var"]:
        try:
            print(f"{p} writable:", os.access(p, os.W_OK))
        except Exception as e:
            print(p, "<err>", e)

def network_info_and_scan():
    header("Network interfaces, routes and lightweight local scan")
    ip_out,_,_ = run_cmd("ip -o addr || ip addr")
    print("ip addr output (first 50 lines):")
    for ln in ip_out.splitlines()[:50]:
        print(" ", ln)
    route,_,_ = run_cmd("ip route show")
    print("\nIP route:")
    print(route)
    # Attempt to determine local IPv4 and prefix
    local_ips = []
    for ln in ip_out.splitlines():
        m = re.search(r'inet (\d+\.\d+\.\d+\.\d+/\d+)', ln)
        if m:
            local_ips.append(m.group(1))
    print("\nDetected local addresses:", local_ips)
    # find default gateway + interface
    def_gw = None
    match = re.search(r'default via (\d+\.\d+\.\d+\.\d+) dev (\S+)', route)
    if match:
        def_gw, def_if = match.group(1), match.group(2)
        print("Default gateway:", def_gw, "interface:", def_if)
    # If we have an IPv4 /24 candidate, do a small TCP connect scan on selected ports (very limited)
    ports = [22,80,443,2375,2376,3306,5432,8080,8000,5000]
    scanned_hosts = []
    for addr in local_ips:
        ipstr, prefix = addr.split("/")
        prefix = int(prefix)
        # only scan if prefix between 24 and 30 and not loopback
        if ipstr.startswith("127.") or prefix < 24 or prefix > 30:
            continue
        net = IPv4Network(f"{ipstr}/{prefix}", strict=False)
        # limit number of hosts
        hosts = list(net.hosts())[:64]
        print(f"\nPerforming light TCP connect scan on {len(hosts)} hosts in {net} on ports {ports} (timeout {TIMEOUT}s).")
        for host in hosts:
            host = str(host)
            for p in ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(TIMEOUT)
                    r = s.connect_ex((host, p))
                    s.close()
                    if r == 0:
                        print(f" {host}:{p} OPEN")
                        scanned_hosts.append((host,p))
                        # don't enumerate multiple ports if same host already listed heavily
                except Exception:
                    pass
        print("Scan finished for network", net)
    if not scanned_hosts:
        print("No open ports detected on common ports in scanned ranges (or no suitable local net detected).")
    else:
        print("\nSummary of open services found (host,port):")
        for h,p in scanned_hosts:
            print(" ", h, p)

def check_ssh_keys():
    header("SSH key checks (local authorized keys / private keys readable)")
    # Check /root and /home
    paths = ["/root/.ssh/id_rsa", "/root/.ssh/authorized_keys"]
    for d in os.listdir("/home") if os.path.exists("/home") else []:
        paths.append(os.path.join("/home", d, ".ssh", "id_rsa"))
        paths.append(os.path.join("/home", d, ".ssh", "authorized_keys"))
    for p in paths:
        if os.path.exists(p):
            try:
                st = os.stat(p)
                print(f"{p} exists, mode {oct(st.st_mode & 0o777)}, readable: {os.access(p, os.R_OK)}")
            except Exception as e:
                print(p, "<err>", e)

def search_docker_api_ports():
    header("Search for exposed Docker API on local interfaces")
    # check listening sockets for 2375
    ss_out,_,_ = run_cmd("ss -ltnp || netstat -ltnp || true")
    if "2375" in ss_out or "dockerd" in ss_out:
        print("Possible docker API listening:\n", "\n".join([ln for ln in ss_out.splitlines() if "2375" in ln or "docker" in ln]))
    else:
        print("No obvious docker API on common port 2375 found in listening sockets output.")

def checks_summary():
    header("Quick actionable summary (interpretable hints)")
    print("- If /var/run/docker.sock is present and readable, you can interact with the Docker daemon (potential privilege escalation).")
    print("- If you have CAP_SYS_ADMIN or CAP_SYS_MODULE, the container is highly privileged.")
    print("- If /proc/1/root points to host root (/) or an unexpected path, the container may share host FS.")
    print("- Presence of many SUID binaries with writable dirs or readable ssh private keys are good local escalation leads.")
    print("- Exposed Docker API (port 2375) on network or listening inside container is a red flag.")
    print("- Writable root filesystem is unusual for non-privileged containers.")

def main():
    print("\nContainer enumeration script (safe, passive). Time:", time.ctime())
    basic_info()
    proc_and_cgroups()
    ns_and_procroot()
    docker_artifacts()
    capabilities()
    suid_files()
    file_access_checks()
    filesystem_writable()
    check_ssh_keys()
    network_info_and_scan()
    search_docker_api_ports()
    checks_summary()
    print("\nDone.\n")

if __name__ == "__main__":
    main()
