# analyzer.py
import re
from collections import Counter # We'll use this to count things

def analyze_logs(log_file_path):
    print(f"[*] Starting analysis of: {log_file_path}")
    
    log_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - - \[(.*?)\] "(.*?)" (\d{3}) (\d+)')

    # --- Our Detective's Notebooks ---
    error_404_sources = []
    failed_logins = Counter() # A special dictionary for counting
    # --------------------------------

    try:
        with open(log_file_path, 'r') as f:
            for line in f: # Read line by line for efficiency
                match = log_pattern.match(line)
                if match:
                    ip_address = match.group(1)
                    request = match.group(3)
                    status_code = int(match.group(4)) # Convert to integer

                    # --- Rule 1: Detect potential scanning ---
                    if status_code == 404:
                        # If a 404 error occurs, log the IP and the requested page
                        suspicious_scan_info = {"ip": ip_address, "request": request}
                        error_404_sources.append(suspicious_scan_info)
                    
                    # --- Rule 2: Detect failed logins ---
                    # We assume any POST to login.php with status 401 is a failed login
                    if "POST /login.php" in request and status_code == 401:
                        failed_logins[ip_address] += 1
                        
    except FileNotFoundError:
        print(f"[!] ERROR: The file was not found at: {log_file_path}")
        return # Exit the function if file not found

    # --- Step 5: Generating the Report ---
    print("\n" + "="*40)
    print("      SECURITY ANALYSIS REPORT")
    print("="*40 + "\n")

    # Report on Scanning Activity
    if error_404_sources:
        print("[!] Potential Scanning Activity Detected (404 Errors):")
        for item in error_404_sources:
            print(f"  - IP: {item['ip']} tried to access {item['request']}")
    
    # Report on Brute-Force Activity
    print("\n[!] Potential Brute-Force Activity Detected (Failed Logins):")
    for ip, count in failed_logins.items():
        # We define a threshold. If an IP fails more than 3 times, it's suspicious.
        if count > 3:
            print(f"  - IP: {ip} failed to log in {count} times.")

    print("\n" + "="*40)
    print("            END OF REPORT")
    print("="*40 + "\n")


if __name__ == "__main__":
    target_log_file = "access.log"
    analyze_logs(target_log_file)