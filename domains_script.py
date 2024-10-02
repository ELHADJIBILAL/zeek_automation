import os
import subprocess
import requests  
import json  
from datetime import datetime, timedelta
import time  

# Get yesterday's date in the format 'YYYY-MM-DD'
yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')

log_folder = f"/opt/zeek/logs/{yesterday}"
output_file = "/opt/zeek/logs/domains.txt"
malicious_output_file = "/opt/zeek/logs/malicious_domains.txt"
domains = set()

# List of popular domains to filter out
popular_domains = {
    "google", "cloudflare", "microsoft", "zvelo",
    "gravatar", "kali", "amazon", "chatgpt", "bing", "msn",
    "in-addr.arpa","yahoo","twitter","github","virustotal"
}

API_KEYS = [
]

VIRUSTOTAL_URL = "https://www.virustotal.com/vtapi/v2/domain/report"
api_index = 0  
request_count = 0  

def get_next_api_key():
    global api_index, request_count
    api_key = API_KEYS[api_index]
    
    if request_count >= 4:
        api_index = (api_index + 1) % len(API_KEYS)
        request_count = 0  
        print(f"Switching to API key index: {api_index} after {request_count} requests.")
        time.sleep(3) 
    
    request_count += 1
    print(f"Using API key: {api_key}, Request count: {request_count}")
    return api_key

# check doamin reputation
def check_domain_reputation(domain):
    api_key = get_next_api_key()
    params = {"apikey": api_key, "domain": domain}
    response = requests.get(VIRUSTOTAL_URL, params=params)

    if response.status_code == 200:
        data = response.json()

        malicious = False 

        safety_score = 100 
        if 'Webutation domain info' in data and 'Safety score' in data['Webutation domain info']:
            safety_score = data['Webutation domain info']['Safety score']
            if safety_score < 70:
                malicious = True 

        if 'BitDefender category' in data:
            bitdefender_info = data['BitDefender category']
            if "badware" in bitdefender_info.lower():
                malicious = True  

        if 'Opera domain info' in data:
            opera_info = data['Opera domain info']
            if "badware" in opera_info.lower():
                malicious = True 

        if 'Websense ThreatSeeker category' in data:
            vendor_reliability = data['Websense ThreatSeeker category']
            if vendor_reliability not in ["Excellent", "Good"]:
                malicious = True 

        if 'Alexa domain info' in data:
            alexa_info = data['Alexa domain info']
            if "top" in alexa_info.lower():
                pass 
            else:
                malicious = True 

        return malicious

    else:
        print(f"Error accessing VirusTotal for {domain}: {response.status_code}")

    return False 

if os.path.exists(log_folder):
    print(f"Accessing folder: {log_folder}")

    gz_files = [f for f in os.listdir(log_folder) if f.endswith('.log.gz')]

    extracted_files = [f for f in os.listdir(log_folder) if f.endswith('.log')]

    if not extracted_files and gz_files:

        gunzip_command = f"gunzip {log_folder}/*.log.gz"
        try:
            subprocess.run(gunzip_command, shell=True, check=True)
            print(f"Successfully extracted all .log.gz files in {log_folder}")
        except subprocess.CalledProcessError as e:
            print(f"Error occurred while extracting files: {e}")
    elif extracted_files:
        print(f"Already extracted: {len(extracted_files)} log files found.")
    else:
        print("No log files to extract.")
    
    for file in extracted_files:
        if file.startswith("dns.") and file.endswith(".log"):
            with open(os.path.join(log_folder, file), 'r') as f:
                for line in f:
                    if not line.startswith("#"):
                        fields = line.split()
                        if len(fields) > 9:  
                            domain = fields[9]  

                            if not any(popular in domain for popular in popular_domains):

                                domain_parts = domain.split('.')
                                if len(domain_parts) >= 2:
                                    base_domain = '.'.join(domain_parts[-2:]) 
                                    domains.add(base_domain)

    with open(output_file, 'w') as f_out, open(malicious_output_file, 'w') as mal_out:
        for domain in sorted(domains):
            f_out.write(domain + "\n")
            
            if check_domain_reputation(domain):
                mal_out.write(domain + "\n")
                print(f"Malicious domain detected: {domain}")

    print(f"Extracted {len(domains)} unique domains. Saved to {output_file}")
    print(f"Malicious domains (if any) saved to {malicious_output_file}")

else:
    print(f"Folder not found: {log_folder}")
