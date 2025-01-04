import re
from collections import defaultdict

def analyze_ssh_logs(log_file, threshold=5):
    """
    Analyzes SSH logs for brute-force attack patterns.

    Args:
        log_file (str): Path to the SSH log file.
        threshold (int): Number of failed attempts to classify an IP as suspicious.
    """
    failed_attempts = defaultdict(int)  # Dictionary to count failed attempts by IP
    suspicious_ips = []  # List to store IPs exceeding the threshold

    # Define a regex pattern to match failed login attempts
    failed_login_pattern = re.compile(
        r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)"
    )

    try:
        with open(log_file, "r") as file:
            for line in file:
                match = failed_login_pattern.search(line)
                if match:
                    ip = match.group(1)
                    failed_attempts[ip] += 1

                    # Add IP to suspicious list if it exceeds the threshold
                    if failed_attempts[ip] == threshold:
                        suspicious_ips.append(ip)

        print("\nAnalysis Complete!")
        print("Suspicious IPs:")
        for ip in suspicious_ips:
            print(f"{ip} (Failed attempts: {failed_attempts[ip]})")

        print("\nDetailed Log:")
        for ip, count in failed_attempts.items():
            print(f"{ip}: {count} failed attempts")

    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Example usage
log_file_path = input("Enter the path to the SSH log file (e.g., /var/log/auth.log): ")
analyze_ssh_logs(log_file_path)
