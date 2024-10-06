import nmap
import subprocess
import sys
from datetime import datetime

# Function to check if a host is live using ping
def is_host_live(ip):
    try:
        response = subprocess.check_output(['ping', '-c', '1', '-W', '1', ip], stderr=subprocess.STDOUT, universal_newlines=True)
        return True
    except subprocess.CalledProcessError:
        return False

# Function to scan ports using nmap
def scan_ports(ip, ports):
    open_ports = []
    nm = nmap.PortScanner()

    try:
        # Convert ports to a format nmap can understand
        if isinstance(ports, range):
            port_range = f"{ports.start}-{ports.stop - 1}"
        else:
            port_range = ','.join(str(port) for port in ports)

        # Scan the IP for the given port range
        print(f"Scanning {ip} for ports: {port_range}")
        nm.scan(ip, port_range)
        
        # Check if the host is up
        if nm[ip].state() == 'up':
            # Check for open ports and add them to the list
            for proto in nm[ip].all_protocols():
                if proto == 'tcp':
                    lport = nm[ip]['tcp'].keys()
                    for port in lport:
                        if nm[ip]['tcp'][port]['state'] == 'open':
                            open_ports.append(port)
        else:
            print(f"[-] Host {ip} is down.")
            
    except KeyError as e:
        print(f"Error scanning ports on {ip}: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

    return open_ports

# Function for live host detection
def live_host_scan(target):
    print(f"\n[+] Scanning for live hosts in the network: {target}\n")
    ip_prefix = target.rsplit('.', 1)[0]
    live_hosts = []

    try:
        for i in range(1, 255):
            ip = f"{ip_prefix}.{i}"
            if is_host_live(ip):
                live_hosts.append(ip)
                print(f"[+] Live Host: {ip}")

        if not live_hosts:
            print("[-] No live hosts found.")
    except KeyboardInterrupt:
        print("\n[-] Scan aborted by user.")
        sys.exit()
    except Exception as e:
        print(f"\n[-] Error occurred: {e}")
        sys.exit()

    return live_hosts

# Function for port scanning
def port_scan_option(live_hosts, ports):
    if not live_hosts:
        print("[-] No live hosts to scan for open ports.")
        return

    print(f"\n[+] Scanning for open ports on live hosts: {live_hosts}\n")
    for ip in live_hosts:
        open_ports = scan_ports(ip, ports)
        if open_ports:
            ports_list = ', '.join(str(port) for port in open_ports)
            print(f"[+] Host {ip} has open ports: {ports_list}")
        else:
            print(f"[-] No open ports found on {ip}.")

# Main function to handle user choices
def main():
    print("Network and Port Scanner")
    print("------------------------")
    print("1. Live Host Detection")
    print("2. Port Scanning")
    print("3. Both Live Host Detection and Port Scanning")
    print("4. Exit")

    choice = input("\nEnter your choice (1/2/3/4): ")

    if choice == '1':
        target = input("Enter the IP address range (e.g., 192.168.1.0): ")
        live_host_scan(target)

    elif choice == '2':
        target = input("Enter the IP address of a live host to scan ports: ")
        port_choice = input("Do you want to scan specific ports or all ports? (specific/all): ").lower()
        
        if port_choice == 'specific':
            ports = input("Enter the ports to scan (comma separated, e.g., 80,22,443): ")
            ports = [int(port.strip()) for port in ports.split(',')]
        elif port_choice == 'all':
            ports = range(1, 1025)  # Scanning well-known ports (1-1024)
        else:
            print("Invalid choice! Scanning common ports.")
            ports = [80, 22, 443, 8080]  # Default common ports

        port_scan_option([target], ports)

    elif choice == '3':
        target = input("Enter the IP address range (e.g., 192.168.1.0): ")
        port_choice = input("Do you want to scan specific ports or all ports? (specific/all): ").lower()
        
        if port_choice == 'specific':
            ports = input("Enter the ports to scan (comma separated, e.g., 80,22,443): ")
            ports = [int(port.strip()) for port in ports.split(',')]
        elif port_choice == 'all':
            ports = range(1, 1025)  # Scanning well-known ports (1-1024)
        else:
            print("Invalid choice! Scanning common ports.")
            ports = [80, 22, 443, 8080]  # Default common ports

        live_hosts = live_host_scan(target)
        port_scan_option(live_hosts, ports)

    elif choice == '4':
        print("Exiting Program")
        sys.exit()

    else:
        print("Invalid choice! Please enter a valid option (1/2/3/4).")
        main()

# Execute the main function
if __name__ == "__main__":
    main()
