import subprocess
import requests
import datetime
import re
import csv
from termcolor import colored

def check_certificate(domain):
    try:
        # Run openssl command to obtain certificate information
        cmd = f"echo | openssl s_client -servername {domain} -connect {domain}:443 2>/dev/null | openssl x509 -text -noout -issuer -subject -dates -serial"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Check for errors in obtaining the certificate
        if result.stderr and "Warning: Reading certificate from stdin" not in result.stderr:
            raise Exception(f"Error obtaining certificate: {result.stderr.strip()}")
        
        # Extract certificate information using regular expressions
        issuer = re.search(r'issuer=(.*)', result.stdout).group(1)
        subject = re.search(r'subject=(.*)', result.stdout).group(1)
        not_before = re.search(r'notBefore=(.*)', result.stdout).group(1)
        not_after = re.search(r'notAfter=(.*)', result.stdout).group(1)
        serial_number = re.search(r'serial=(.*)', result.stdout).group(1)
        dns_names = re.findall(r'DNS:(\S+)', result.stdout)
        
        # Return the certificate information
        return issuer, subject, not_before, not_after, serial_number, dns_names
    except Exception as e:
        print(e)

def get_certificate_expiry(not_after):
    # Parse the certificate expiry date and calculate the remaining days
    if 'GMT' in not_after:
        end_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
    else:
        end_date = datetime.datetime.strptime(not_after, '%Y-%m-%dT%H:%M:%S')
    end_date = end_date.replace(tzinfo=datetime.timezone.utc)
    return (end_date - datetime.datetime.now(datetime.timezone.utc)).days

def get_active_certs(domain):
    response = requests.get(f"https://crt.sh/?q={domain}&output=json")
    try:
        certs = response.json()
    except ValueError:
        print(f"Error decoding JSON response for domain: {domain}")
        return []
    ip_addresses = get_ip_addresses(domain)
    for cert in certs:
        cert['ip_address'] = ip_addresses
    return certs

def get_ip_addresses(domain):
    # Use dig command to retrieve IP addresses for a domain
    result = subprocess.run(f"dig +short {domain}", shell=True, stdout=subprocess.PIPE, text=True)
    return result.stdout.strip().split("\n")

def write_to_csv(filename, data):
    fieldnames = ['Common Name', 'Serial Number', 'DNS Names', 'Certificate Issued Date', 'Certificate Start Date', 'Certificate Expiry Date', 'Certificate Issuer Name', 'Count of Days remaining to Expiry']
    
    # Read existing data
    existing_data = []
    try:
        with open(filename, 'r', newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                existing_data.append(row)
    except FileNotFoundError:
        pass  # File does not exist yet, we'll create it below

    # Get set of existing serial numbers
    existing_serial_numbers = {row['Serial Number'] for row in existing_data}

    # Prepare new data
    new_data = []
    for row in data:
        new_row = {
            'Common Name': row['common_name'],
            'Serial Number': row['serial_number'],
            'DNS Names': row['san_names'],
            'Certificate Issued Date': row['entry_timestamp'],
            'Certificate Start Date': row['not_before'],
            'Certificate Expiry Date': row['not_after'],
            'Certificate Issuer Name': row['issuer_name'],
            'Count of Days remaining to Expiry': row['remaining_days_to_expiry']
        }
        if new_row['Serial Number'] not in existing_serial_numbers:
            new_data.append(new_row)
            existing_serial_numbers.add(new_row['Serial Number'])  # Add the serial number to the set of existing serial numbers

    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        # Write existing data
        for row in existing_data:
            writer.writerow(row)

        # Write new data
        for row in new_data:
            writer.writerow(row)
            
def is_valid_domain(domain):
    # Regular expression to check if the domain name is valid
    pattern = r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]"
    return re.match(pattern, domain) is not None

# Prompt the user to enter domains
domains = input("Enter the domains (comma separated): ").split(',')

# Validate the domains
for i, domain in enumerate(domains):
    domain = domain.strip()  # Strip leading and trailing spaces
    while not is_valid_domain(domain):
        print(f"Invalid domain: {domain}")
        domain = input("Please enter a valid domain: ").strip()  # Strip leading and trailing spaces
    domains[i] = domain

all_certs = []
serial_numbers = set()

# Process each domain
for domain in domains:
    # Check the certificate for the domain
    issuer, subject, not_before, not_after, serial_number, dns_names = check_certificate(domain)
    
    # Get active certificates for the domain
    certs = get_active_certs(domain)
    
    # Calculate the remaining days until certificate expiry
    expiry_days = get_certificate_expiry(not_after)
    
    # Determine the color for the expiry days
    if expiry_days < 15:
        expiry_color = 'red'
    elif expiry_days < 30:
        expiry_color = 'yellow'
    else:
        expiry_color = 'green'
    
    # Filter certificates based on expiry days
    certs = [cert for cert in certs if 0 < get_certificate_expiry(cert['not_after']) <= 60]
    
    # Print certificate information
    print(colored(f"Domain Name: {domain}", 'blue'))
    print(f"Issuer Name: {issuer}")
    print(colored(f"Serial Number: {serial_number}", 'blue'))
    print(f"Cert Issued Date: {not_before}")
    print(f"Cert Expiry Date: {not_after}")
    print(colored(f"Count on number of days certificate expiring in: {expiry_days}", expiry_color))
    print(f"SAN Names: {', '.join(dns_names)}")
    
    if certs:
        print(f"IP address of the cert location: {certs[0]['ip_address']}")
    else:
        print("No active certificates found")
    
    # Add additional information to each certificate
    for cert in certs:
        cert['domain'] = domain
        cert['san_names'] = ', '.join(dns_names)
        cert['remaining_days_to_expiry'] = get_certificate_expiry(cert['not_after'])
        if 'result_count' in cert:
            del cert['result_count']
    
    # Add certificates to the list
    all_certs.extend(certs)
    print("*" * 60)

# Write all certificate information to a CSV file
write_to_csv('all_cert_status.csv', all_certs)