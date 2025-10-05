#!/usr/bin/env python3
"""
Docker Container Reconnaissance Script
For CTF container breakout challenges
"""

import os
import subprocess
import socket
import json
import re
import argparse
from pathlib import Path
import shutil
import platform
from datetime import datetime

class ContainerRecon:
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hostname": socket.gethostname(),
            "container_info": {},
            "network_info": {},
            "filesystem_info": {},
            "privileges": {},
            "potential_breakouts": []
        }
        
    def run_command(self, command, shell=False):
        """Run a system command and return the output"""
        try:
            if shell:
                result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
            else:
                result = subprocess.run(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
            return result.stdout.strip()
        except (subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
            return f"Command failed: {e}"
            
    def check_container_environment(self):
        """Check if we're running inside a container and collect basic info"""
        print("[+] Checking container environment...")
        
        # Check for container-specific files
        container_indicators = [
            "/.dockerenv",
            "/run/.containerenv"
        ]
        
        for indicator in container_indicators:
            if os.path.exists(indicator):
                self.results["container_info"]["is_container"] = True
                self.results["container_info"]["indicators"] = indicator
                break
        else:
            self.results["container_info"]["is_container"] = False
            
        # Get container ID if in Docker
        cgroup_content = ""
        try:
            with open('/proc/self/cgroup', 'r') as f:
                cgroup_content = f.read()
                
            # Look for Docker container ID pattern
            docker_pattern = r'[0-9a-f]{64}'
            match = re.search(docker_pattern, cgroup_content)
            if match:
                self.results["container_info"]["container_id"] = match.group(0)
            
            self.results["container_info"]["cgroups"] = cgroup_content
        except Exception as e:
            self.results["container_info"]["cgroup_error"] = str(e)
        
        # Check if this is a privileged container
        self.results["container_info"]["capabilities"] = self.run_command("capsh --print")
        
        # Check for common container orchestration environments
        if os.path.exists('/var/run/secrets/kubernetes.io'):
            self.results["container_info"]["orchestration"] = "Kubernetes"
        
    def scan_network(self):
        """Scan network interfaces and open ports"""
        print("[+] Scanning network configuration...")
        
        # Get network interfaces and IPs
        ip_output = self.run_command("ip addr show")
        self.results["network_info"]["interfaces"] = ip_output
        
        # Get routing table
        route_output = self.run_command("ip route")
        self.results["network_info"]["routing"] = route_output
        
        # Check open ports (listening services)
        if shutil.which("ss"):
            listening_ports = self.run_command("ss -tuln")
            self.results["network_info"]["listening_ports"] = listening_ports
        else:
            self.results["network_info"]["listening_ports"] = "ss command not available"
        
        # Try to detect Docker bridge network
        if "docker0" in ip_output:
            self.results["network_info"]["docker_bridge_detected"] = True
            
        # Try to reach the Docker socket
        if os.path.exists('/var/run/docker.sock'):
            self.results["potential_breakouts"].append({
                "type": "docker_socket_access",
                "description": "Docker socket is accessible. Can be used to escape the container.",
                "exploitation": "You can use the Docker API through this socket to create a new privileged container and mount the host filesystem."
            })
            
        # Check if host network namespace is used
        if "host" in self.run_command("ls -l /proc/self/ns/net"):
            self.results["potential_breakouts"].append({
                "type": "host_network",
                "description": "Container is using the host network namespace",
                "exploitation": "You have access to all host network interfaces and services"
            })
            
    def check_filesystem_access(self):
        """Check filesystem mounts and permissions"""
        print("[+] Checking filesystem access...")
        
        # Get mounted filesystems
        mounts = self.run_command("mount")
        self.results["filesystem_info"]["mounts"] = mounts
        
        # Check for volume mounts that might allow escaping
        proc_mounts = ""
        try:
            with open('/proc/mounts', 'r') as f:
                proc_mounts = f.read()
            self.results["filesystem_info"]["proc_mounts"] = proc_mounts
        except Exception as e:
            self.results["filesystem_info"]["proc_mounts_error"] = str(e)
        
        # Check for interesting mounted volumes
        interesting_mounts = []
        mount_paths = [
            "/host", "/var/lib/docker", "/", "/proc", "/dev"
        ]
        
        for mount in mount_paths:
            if os.path.exists(mount) and os.path.ismount(mount):
                interesting_mounts.append(mount)
                
        self.results["filesystem_info"]["interesting_mounts"] = interesting_mounts
        
        # Check if the container has access to host devices
        if os.path.exists('/dev/sda') or os.path.exists('/dev/xvda'):
            self.results["potential_breakouts"].append({
                "type": "host_device_access",
                "description": "Container has access to host block devices",
                "exploitation": "You might be able to read/write directly to host storage"
            })
            
        # Check for sensitive file mounts
        sensitive_files = [
            "/etc/shadow", "/etc/passwd", "/etc/hosts", 
            "/proc/1/environ", "/proc/1/root"
        ]
        
        for file in sensitive_files:
            try:
                if os.path.exists(file) and os.access(file, os.R_OK):
                    self.results["filesystem_info"]["sensitive_files_readable"] = self.results.get(
                        "filesystem_info", {}).get("sensitive_files_readable", []) + [file]
            except:
                pass
                
    def check_privileges(self):
        """Check for privileged container indicators"""
        print("[+] Checking for privileged container indicators...")
        
        # Check if we're root
        is_root = (os.geteuid() == 0)
        self.results["privileges"]["is_root"] = is_root
        
        # Check for dangerous capabilities
        capabilities = self.run_command("capsh --print")
        self.results["privileges"]["capabilities"] = capabilities
        
        dangerous_caps = ["cap_sys_admin", "cap_sys_ptrace", "cap_sys_module", "cap_net_admin"]
        for cap in dangerous_caps:
            if cap in capabilities:
                self.results["potential_breakouts"].append({
                    "type": "dangerous_capability",
                    "capability": cap,
                    "description": f"Container has {cap} capability which might allow container escape",
                })
                
        # Check if SYS_ADMIN capability is granted
        if "cap_sys_admin" in capabilities:
            self.results["potential_breakouts"].append({
                "type": "sys_admin_capability",
                "description": "Container has CAP_SYS_ADMIN capability",
                "exploitation": "You can try to mount filesystems or manipulate device files"
            })
            
        # Check if we can modify kernel parameters
        try:
            # Try to access /proc/sys/kernel
            kernel_params = os.listdir('/proc/sys/kernel')
            if kernel_params:
                self.results["privileges"]["can_access_kernel_params"] = True
                self.results["potential_breakouts"].append({
                    "type": "kernel_parameters_access",
                    "description": "Container can access and potentially modify kernel parameters",
                })
        except:
            self.results["privileges"]["can_access_kernel_params"] = False
            
        # Check for seccomp settings
        if os.path.exists('/proc/self/status'):
            with open('/proc/self/status', 'r') as f:
                status_content = f.read()
                if "Seccomp:" in status_content:
                    seccomp_line = [line for line in status_content.split('\n') if "Seccomp:" in line][0]
                    # 0 means disabled
                    if "Seccomp:\t0" in seccomp_line:
                        self.results["privileges"]["seccomp_disabled"] = True
                        self.results["potential_breakouts"].append({
                            "type": "seccomp_disabled",
                            "description": "Seccomp is disabled, which allows syscall operations normally blocked",
                        })
                        
    def check_breakout_techniques(self):
        """Check various container breakout techniques"""
        print("[+] Checking for breakout techniques...")
        
        # Check for unshare command (useful for namespace escapes)
        if shutil.which("unshare"):
            self.results["potential_breakouts"].append({
                "type": "unshare_available",
                "description": "unshare command is available and might be used for namespace manipulation",
            })
            
        # Check for ctr, docker, or kubectl
        for command in ["docker", "ctr", "kubectl", "crictl"]:
            if shutil.which(command):
                self.results["potential_breakouts"].append({
                    "type": "container_management_tool",
                    "tool": command,
                    "description": f"{command} binary is available inside container",
                })
                
        # Check for exposed environment variables that might contain secrets
        env_vars = os.environ
        sensitive_prefixes = ["AWS_", "KUBE_", "DOCKER_", "API_", "TOKEN_", "PASSWORD", "SECRET"]
        found_sensitive = {}
        
        for var in env_vars:
            for prefix in sensitive_prefixes:
                if var.startswith(prefix) or prefix in var:
                    found_sensitive[var] = env_vars[var][:10] + "..." if env_vars[var] else "(empty)"
                    
        if found_sensitive:
            self.results["potential_breakouts"].append({
                "type": "sensitive_env_vars",
                "variables": found_sensitive,
                "description": "Container has sensitive environment variables that might contain secrets",
            })
            
        # Check for runc exploit indicators (CVE-2019-5736)
        if os.path.exists('/proc/self/exe') and os.access('/proc/self/exe', os.W_OK):
            self.results["potential_breakouts"].append({
                "type": "runc_proc_write",
                "description": "Container can write to /proc/self/exe (potential for runc exploit)",
            })

    def check_unusual_mounts(self):
        """Check for unusual mounts that could lead to container escape"""
        print("[+] Checking for unusual mounts...")
        
        interesting_paths = [
            "/var/run/docker.sock",  # Docker socket
            "/host",                 # Common host mount
            "/var/lib/kubelet",      # Kubernetes files
            "/.docker",              # Docker config
            "/root/.ssh",            # SSH keys
            "/root/.kube",           # Kubernetes config
            "/var/run/secrets",      # Container secrets
            "/dev/kmsg"              # Kernel messages
        ]
        
        for path in interesting_paths:
            if os.path.exists(path):
                self.results["filesystem_info"]["unusual_mounts"] = self.results.get(
                    "filesystem_info", {}).get("unusual_mounts", []) + [path]
                
                self.results["potential_breakouts"].append({
                    "type": "unusual_mount",
                    "path": path,
                    "description": f"Unusual path {path} is accessible from container",
                })

    def run_all_checks(self):
        """Run all reconnaissance checks"""
        self.check_container_environment()
        self.scan_network()
        self.check_filesystem_access()
        self.check_privileges()
        self.check_breakout_techniques()
        self.check_unusual_mounts()
        
        return self.results
        
    def save_results(self, output_file=None):
        """Save results to a file"""
        if not output_file:
            output_file = f"container_recon_{socket.gethostname()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
            
        print(f"[+] Results saved to {output_file}")
        return output_file

def main():
    parser = argparse.ArgumentParser(description="Docker Container Reconnaissance Tool for CTFs")
    parser.add_argument("-o", "--output", help="Output file for results (JSON format)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Don't print summary to stdout")
    args = parser.parse_args()
    
    print("╔═══════════════════════════════════════════════╗")
    print("║ Container Reconnaissance Tool for CTFs        ║")
    print("║ Use responsibly for authorized assessments    ║")
    print("╚═══════════════════════════════════════════════╝")
    
    recon = ContainerRecon()
    results = recon.run_all_checks()
    output_file = recon.save_results(args.output)
    
    if not args.quiet:
        # Print a summary of findings
        print("\n╔═══════════════════════════════════════════════╗")
        print("║ SUMMARY OF FINDINGS                           ║")
        print("╚═══════════════════════════════════════════════╝")
        
        # Container info
        if results["container_info"].get("is_container", False):
            print("\n[+] Running inside a container")
        else:
            print("\n[-] Not running inside a container (or detection failed)")
            
        # Network information
        print("\n[+] Network Information:")
        interfaces = results["network_info"].get("interfaces", "").split("\n")
        for iface in interfaces[:2]:  # Just show first two lines
            if iface.strip():
                print(f"  - {iface.strip()}")
        if len(interfaces) > 2:
            print(f"  - ... ({len(interfaces) - 2} more lines)")
            
        # Potential breakouts
        if results["potential_breakouts"]:
            print(f"\n[!] Found {len(results['potential_breakouts'])} potential breakout methods:")
            for idx, breakout in enumerate(results["potential_breakouts"]):
                print(f"  {idx+1}. {breakout['type']}: {breakout['description']}")
                if "exploitation" in breakout:
                    print(f"     → {breakout['exploitation']}")
        else:
            print("\n[-] No obvious container breakout methods found")
            
        # Privileges
        print("\n[+] Privilege Information:")
        if results["privileges"].get("is_root", False):
            print("  - Running as root")
        else:
            print("  - Not running as root")
            
        dangerous_caps = [cap for cap in ["cap_sys_admin", "cap_sys_ptrace", "cap_sys_module"] 
                        if cap in results["privileges"].get("capabilities", "")]
        if dangerous_caps:
            print(f"  - Dangerous capabilities: {', '.join(dangerous_caps)}")
        
        # Final notes
        print("\n[+] Complete results saved to:", output_file)
        print("[+] Run with -q for quiet mode\n")

if __name__ == "__main__":
    main()