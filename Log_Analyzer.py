import time

log_file = 'Log_Analyzer\log_data.txt'  # Replace with your log file name along with its path

ip_event_counts = {}
ip_login_failure_count = {}
blocked_ips = {}

start_time = time.time()

with open(log_file, 'r') as file:
    for line in file:
        log_entry = eval(line.strip())
        ip_address = log_entry.get('ip_address')
        event_type = log_entry.get('event_type')

        if ip_address and event_type:
            key = (ip_address, event_type)
            ip_event_counts[key] = ip_event_counts.get(key, 0) + 1

            if event_type == 'login_failure':
                ip_login_failure_count[ip_address] = ip_login_failure_count.get(ip_address, 0) + 1
                if ip_login_failure_count[ip_address] > 5 and ip_address not in blocked_ips:
                    blocked_ips[ip_address] = round(time.time(), 2)
                    print("Bruteforce activity detected: IP =", ip_address)
                    # Perform blocking action for the IP
                    print("Blocked IP Address:", ip_address)
                    print("Time taken to block:", round(time.time() - blocked_ips[ip_address], 2), "seconds")
                    print()

            elif event_type == 'login_success':
                if ip_login_failure_count.get(ip_address, 0) > 5 and ip_address in blocked_ips:
                    #del blocked_ips[ip_address]
                    print("Intrusion detected: IP =", ip_address)
                    print()


repeated_entries = [entry for entry, count in ip_event_counts.items() if count > 1 and entry[1] == 'access_denied']

for entry in repeated_entries:
    ip_address, event_type = entry
    if ip_address not in blocked_ips:
        blocked_ips[ip_address] = round(time.time(), 2)
        print("Suspicious activity detected: IP =", ip_address)
        # Perform blocking action for the IP
        print("Blocked IP Address:", ip_address)
        print("Time taken to block:", round(time.time() - blocked_ips[ip_address], 2), "seconds")
        print()
