import re
import csv
from collections import Counter

def analyze_log_file(log_file_path, threshold=10):
    ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'  
    endpoint_pattern = r'\"[A-Z]+\s([^\s]+)' 
    failed_login_pattern = r'\"[A-Z]+\s[^\s]+.*\" 401'  
    ip_counts, endpoint_counts, suspicious_ips = Counter(), Counter(), Counter()

    with open(log_file_path, 'r') as file:
        for line in file:
        
            ip_match = re.search(ip_pattern, line)
            if ip_match: ip_counts[ip_match.group(1)] += 1
            
           
            endpoint_match = re.search(endpoint_pattern, line)
            if endpoint_match: endpoint_counts[endpoint_match.group(1)] += 1
            
            if re.search(failed_login_pattern, line):
                ip = re.search(ip_pattern, line).group(1)
                suspicious_ips[ip] += 1

    most_accessed_endpoint = endpoint_counts.most_common(1)

    suspicious_activity = {ip: count for ip, count in suspicious_ips.items() if count > threshold}

    print("### Requests per IP ###")
    for ip, count in ip_counts.most_common(): print(f"IP: {ip}, Requests: {count}")

    print("\n### Most Accessed Endpoint ###")
    if most_accessed_endpoint: print(f"Endpoint: {most_accessed_endpoint[0][0]}, Access Count: {most_accessed_endpoint[0][1]}")
    else: print("No endpoints found.")
    
    print("\n### Suspicious Activity (Failed Logins) ###")
    if suspicious_activity:
        for ip, count in suspicious_activity.items(): print(f"IP: {ip}, Failed Logins: {count}")
    else: print("No suspicious activity detected.")
    
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=['Category', 'Item', 'Count'])
        writer.writeheader()
        
        for ip, count in ip_counts.most_common():
            writer.writerow({'Category': 'Requests per IP', 'Item': ip, 'Count': count})
        if most_accessed_endpoint:
            writer.writerow({'Category': 'Most Accessed Endpoint', 'Item': most_accessed_endpoint[0][0], 'Count': most_accessed_endpoint[0][1]})
        for ip, count in suspicious_activity.items():
            writer.writerow({'Category': 'Suspicious Activity', 'Item': ip, 'Count': count})

    print("\nResults saved to 'log_analysis_results.csv'.")

log_file_path = 'logging.txt'
analyze_log_file(log_file_path)
