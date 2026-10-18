import time
import subprocess
import re
import os

LOG_FILE = "/var/log/auth.log"
MAX_ATTEMPTS = 5
failed_attempts = {}
blocked_ip = set()

def block_ip(ip_address):
	print(f"Attack detected. Blocking IP address: {ip_address}")
	subprocess.run(f"sudo ufw deny from {ip_address} to any", shell=True)
	blocked_ip.add(ip_address)

def monitor_logs():
	print(f"Monitoring logs in file {LOG_FILE}")

	f = open(LOG_FILE, "r")
	f.seek(0, os.SEEK_END)
	
	while True:
		line = f.readline()
		if not line:
			time.sleep(0.5)
			continue
		if "Failed password" in line or "preauth" in line:
			match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line) 
			if match:
				ip = match.group(1)
				if ip in blocked_ip:
					continue
				if ip == "127.0.0.1":
					continue
				failed_attempts[ip] = failed_attempts.get(ip,0) + 1
				print(f"Failed log in with IP: {ip} (Try: {failed_attempts[ip]}/{MAX_ATTEMPTS})")
				if failed_attempts[ip] >= MAX_ATTEMPTS:
					block_ip(ip)
					failed_attempts[ip] = 0

if __name__ == "__main__":
	monitor_logs()
