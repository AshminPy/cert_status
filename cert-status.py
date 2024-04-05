import subprocess
import requests
import datetime
import re
import csv
from termcolor import colored

def is_valid_domain(domain):
    domain_regex = re.compile(
        r'^(\*\.)?(?:[a-z0-9-]+\.)+[a-z0-9-]+$'
    )
    return bool(domain_regex.match(domain))

def check_certificate(domain):
    try:
        # Run openssl command to obtain certificate information
        cmd = f"echo | openssl s_client -servername {domain} -connect {domain}:443 2>/dev/null | openssl x509 -text -noout -issuer -subject -dates -serial"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Check for errors in obtaining the certificate
        if result.stderr and "Warning: Reading certificate from stdin" not in result.stderr:
            raise Exception(f"Error obtaining certificate: {result.stderr.strip()}")
        
        # Extract certificate information using regular expressions
        issuer_match = re.search(r'issuer=(.*)', result.stdout)
        issuer = issuer_match.group(1) if issuer_match else None
        subject_match = re.search(r'subject=(.*)', result.stdout)
        subject = subject_match.group(1) if subject_match else None
        not_before_match = re.search(r'notBefore=(.*)', result.stdout)
        not_before = not_before_match.group(1) if not_before_match else None
        not_after_match = re.search(r'notAfter=(.*)', result.stdout)
        not_after = not_after_match.group(1) if not_after_match else None
        serial_number_match = re.search(r'serial=(.*)', result.stdout)
        serial_number = serial_number_match.group(1) if serial_number_match else None
        dns_names = re.findall(r'DNS:(\S+)', result.stdout)
        
        # Return the certificate information
        return issuer, subject, not_before, not_after, serial_number, dns_names
    except Exception as e:
        print(e)

def get_certificate_expiry(not_after):
    # Check if not_after is None
    if not_after is None:
        print("Error: not_after is None")
        return None

    # Parse the certificate expiry date and calculate the remaining days
    try:
        if 'GMT' in not_after:
            end_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
        else:
            end_date = datetime.datetime.strptime(not_after, '%Y-%m-%dT%H:%M:%S')
        end_date = end_date.replace(tzinfo=datetime.timezone.utc)
        return (end_date - datetime.datetime.now(datetime.timezone.utc)).days
    except ValueError:
        print(f"Error parsing date: {not_after}")
        return None

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

def write_to_csv(filename, row):
    fieldnames = ['Domain Name', 'Issuer Name', 'Serial Number', 'Cert Issued Date', 'Cert Expiry Date', 'Count of Days remaining to Expiry', 'SAN Names']
    filename = f"{filename}_{datetime.datetime.now().strftime('%Y_%m_%d')}.csv"
    try:
        with open(filename, 'x', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerow(row)
    except FileExistsError:
        with open(filename, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow(row)

# Prompt the user to enter domains
domains = input("Enter the domains (comma separated): ").split(',')

# Validate the domains
for i, domain in enumerate(domains):
    domain = domain.strip()  # Strip leading and trailing spaces
    while not is_valid_domain(domain):
        print(f"Invalid domain: {domain}")
        domain = input("Please enter a valid domain: ").strip()  # Strip leading and trailing spaces
    domains[i] = domain

# Process each domain
for domain in domains:
    # Check the certificate for the domain
    issuer, subject, not_before, not_after, serial_number, dns_names = check_certificate(domain)
    
    # Get active certificates for the domain
    certs = get_active_certs(domain)
    
    # Calculate the remaining days until certificate expiry
    expiry_days = get_certificate_expiry(not_after)
    
    # Determine the color for the expiry days
    if expiry_days is not None and expiry_days < 15:
        expiry_color = 'red'
    elif expiry_days is not None and expiry_days < 30:
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
    
    # Write certificate information to CSV
    row = {
        'Domain Name': domain,
        'Issuer Name': issuer,
        'Serial Number': serial_number,
        'Cert Issued Date': not_before,
        'Cert Expiry Date': not_after,
        'Count of Days remaining to Expiry': expiry_days,
        'SAN Names': ', '.join(dns_names)
    }
    write_to_csv('cert_status.csv', row)
    
    if certs:
        print(f"IP address of the cert location: {certs[0]['ip_address']}")
    else:
        print("No active certificates found")
    
    print("*" * 60)