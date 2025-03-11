import socket
import csv

# Function to check if a port is open and also returns a vulnerability score based on risk
def check_port(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((ip, port))  # Try connecting to the port
    vulnerability = 0
    status = "CLOSED"
    
    if result == 0:
        status = "OPEN"
        if port == 22:  # SSH
            vulnerability += 3  # High risk if exposed
        elif port == 80:  # HTTP
            vulnerability += 2  # Moderate risk
        elif port == 443:  # HTTPS
            vulnerability += 1  # Lower risk
        else:
            vulnerability += 1  # Default vulnerability for all other ports
    
    s.close()
    return status, vulnerability

# Function to scan ports and save results 
def scan_ports(ip, start_port, end_port, filename="scan_results.csv"):
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['IP Address', 'Port', 'Status', 'Vulnerability Score'])

        total_vulnerability = 0
        # Scan the specified range of ports
        for port in range(start_port, end_port + 1):
            status, vulnerability = check_port(ip, port)
            writer.writerow([ip, port, status, vulnerability])
            total_vulnerability += vulnerability
            print(f"Port {port} is {status} on {ip}. Vulnerability score: {vulnerability}")

        print(f"Total vulnerability score for {ip}: {total_vulnerability}")
        # Vulnerability Score saved in CSV
        writer.writerow(['', 'Total Vulnerability', total_vulnerability])
