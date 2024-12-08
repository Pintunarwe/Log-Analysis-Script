# import re
# import csv
# from collections import defaultdict

# # Configurations
# FAILED_LOGIN_THRESHOLD = 10

# def parse_log_file(file_path):
#     """Parse the log file and extract relevant information."""
#     with open(file_path, 'r') as file:
#         lines = file.readlines()
    
#     ip_addresses = defaultdict(int)
#     endpoints = defaultdict(int)
#     failed_logins = defaultdict(int)

#     # Regular expressions
#     ip_regex = r"(\d+\.\d+\.\d+\.\d+)"
#     endpoint_regex = r'\"[A-Z]+\s(/[\w/]+)'
#     failed_login_regex = r'401'

#     for line in lines:
#         # Extract IP address
#         ip_match = re.search(ip_regex, line)
#         if ip_match:
#             ip_addresses[ip_match.group(1)] += 1

#         # Extract endpoint
#         endpoint_match = re.search(endpoint_regex, line)
#         if endpoint_match:
#             endpoints[endpoint_match.group(1)] += 1

#         # Check for failed login attempts
#         if re.search(failed_login_regex, line):
#             ip_match = re.search(ip_regex, line)
#             if ip_match:
#                 failed_logins[ip_match.group(1)] += 1

#     return ip_addresses, endpoints, failed_logins

# def display_results(ip_addresses, endpoints, failed_logins):
#     """Display the analysis results in the terminal."""
#     print("Requests per IP Address:")
#     print(f"{'IP Address':<20} {'Request Count'}")
#     for ip, count in sorted(ip_addresses.items(), key=lambda x: x[1], reverse=True):
#         print(f"{ip:<20} {count}")

#     print("\nMost Frequently Accessed Endpoint:")
#     most_accessed_endpoint = max(endpoints, key=endpoints.get)
#     print(f"{most_accessed_endpoint} (Accessed {endpoints[most_accessed_endpoint]} times)")

#     print("\nSuspicious Activity Detected:")
#     print(f"{'IP Address':<20} {'Failed Login Attempts'}")
#     for ip, count in failed_logins.items():
#         if count > FAILED_LOGIN_THRESHOLD:
#             print(f"{ip:<20} {count}")

# def save_results_to_csv(ip_addresses, endpoints, failed_logins):
#     """Save the results to a CSV file."""
#     with open('log_analysis_results.csv', 'w', newline='') as file:
#         writer = csv.writer(file)
        
#         # Write Requests per IP
#         writer.writerow(["IP Address", "Request Count"])
#         for ip, count in sorted(ip_addresses.items(), key=lambda x: x[1], reverse=True):
#             writer.writerow([ip, count])

#         # Write Most Accessed Endpoint
#         most_accessed_endpoint = max(endpoints, key=endpoints.get)
#         writer.writerow(["Most Accessed Endpoint", most_accessed_endpoint])
#         writer.writerow(["Access Count", endpoints[most_accessed_endpoint]])

#         # Write Suspicious Activity
#         writer.writerow(["IP Address", "Failed Login Count"])
#         for ip, count in failed_logins.items():
#             if count > FAILED_LOGIN_THRESHOLD:
#                 writer.writerow([ip, count])

# def main():
#     # Parse the log file
#     ip_addresses, endpoints, failed_logins = parse_log_file('D:/intern/log_analysis_project/sample.log')

#     # Display results in the terminal
#     display_results(ip_addresses, endpoints, failed_logins)

#     # Save results to CSV file
#     save_results_to_csv(ip_addresses, endpoints, failed_logins)

# if __name__ == "__main__":
#     main()


import re
import csv
from collections import defaultdict

# Function to parse the log file and extract relevant data
def parse_log_file(file_path):
    ip_addresses = defaultdict(int)
    endpoints = defaultdict(int)
    failed_logins = defaultdict(int)
    
    # Regex pattern for parsing log lines
    log_pattern = r'(?P<ip>[\d\.]+) - - \[.*\] "(?P<method>[A-Z]+) (?P<endpoint>[^ ]+) .*" (?P<status_code>\d+)'
    
    # Open the log file for reading
    with open(file_path, 'r') as file:
        for line in file:
            match = re.match(log_pattern, line)
            if match:
                ip = match.group('ip')
                endpoint = match.group('endpoint')
                status_code = match.group('status_code')
                
                # Count IP addresses and request counts
                ip_addresses[ip] += 1
                
                # Count endpoint requests
                endpoints[endpoint] += 1
                
                # Count failed logins (status code 401)
                if status_code == '401':
                    failed_logins[ip] += 1
    
    return ip_addresses, endpoints, failed_logins

# Function to write the analysis results to a CSV file
def write_to_csv(ip_counts, most_accessed_endpoint, access_count, failed_logins):
    with open("log_analysis_results.csv", mode="w", newline="") as file:
        writer = csv.writer(file)
        
        # Write IP counts
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow([most_accessed_endpoint, access_count])

        # Write Suspicious Activity (Failed Login Attempts)
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in failed_logins.items():
            writer.writerow([ip, count])

# Main function
def main():
    # Define the threshold for failed login attempts to flag suspicious activity
    threshold = 3
    
    # Parse the log file
    ip_addresses, endpoints, failed_logins = parse_log_file('D:/intern/log_analysis_project/sample.log')
    
    # Find the most accessed endpoint
    most_accessed_endpoint = max(endpoints, key=endpoints.get)
    access_count = endpoints[most_accessed_endpoint]
    
    # Print the results
    print("Requests per IP:")
    for ip, count in ip_addresses.items():
        print(f"{ip}: {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"/{most_accessed_endpoint} (Accessed {access_count} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in failed_logins.items():
        if count > threshold:
            print(f"{ip}        {count}")
    
    # Write the results to a CSV file
    write_to_csv(ip_addresses, most_accessed_endpoint, access_count, failed_logins)

if __name__ == '__main__':
    main()
