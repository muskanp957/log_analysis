import csv
from collections import Counter
import re

# Function to read the log file
def read_log_file(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

# Function to parse log lines
def parse_log_line(line):
    pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+).*"(?P<method>[A-Z]+) (?P<endpoint>\/\S+).*" (?P<status>\d+)'
    match = re.search(pattern, line)
    if match:
        return match.group('ip'), match.group('endpoint'), match.group('status')
    return None, None, None

# Function to count requests by IP
def count_requests_by_ip(logs):
    ip_counts = Counter()
    for line in logs:
        ip, _, _ = parse_log_line(line)
        if ip:
            ip_counts[ip] += 1
    return ip_counts

# Function to find the most accessed endpoint
def find_most_accessed_endpoint(logs):
    endpoint_counts = Counter()
    for line in logs:
        _, endpoint, _ = parse_log_line(line)
        if endpoint:
            endpoint_counts[endpoint] += 1
    most_accessed = endpoint_counts.most_common(1)
    return most_accessed[0] if most_accessed else (None, 0)

# Function to detect suspicious activity
def detect_suspicious_activity(logs, threshold=10):
    failed_logins = Counter()
    for line in logs:
        ip, _, status = parse_log_line(line)
        if ip and status == '401':
            failed_logins[ip] += 1
    return {ip: count for ip, count in failed_logins.items() if count > threshold}

# Function to save results to CSV
def save_results_to_csv(ip_counts, most_accessed, suspicious_ips, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write IP request counts
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        
        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(['Most Frequently Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow(most_accessed)
        
        # Write suspicious activity
        writer.writerow([])
        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

# Main function to integrate all parts
def main():
    log_file = 'sample.log'  # Specify your log file path
    output_file = 'log_analysis_results.csv'  # Output file name
    
    # Read logs
    logs = read_log_file(log_file)
    
    # Analyze logs
    ip_counts = count_requests_by_ip(logs)
    most_accessed = find_most_accessed_endpoint(logs)
    suspicious_ips = detect_suspicious_activity(logs)
    
    # Display results
    print("IP Address           Request Count")
    for ip, count in ip_counts.most_common():
        print(f"{ip:<20}{count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20}{count}")
    else:
        print("No suspicious activity detected.")
    
    # Save results to CSV
    save_results_to_csv(ip_counts, most_accessed, suspicious_ips, output_file)
    print(f"\nResults saved to {output_file}")

if __name__ == '__main__':
    main()
