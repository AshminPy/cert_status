import subprocess
import requests
import datetime
import re
import csv
from OpenSSL import crypto

def check_certificate(domain):
    try:
        # Run the openssl command to get the certificate details
        cmd = f"echo | openssl s_client -servername {domain} -connect {domain}:443 2>/dev/null | openssl x509 -noout -issuer -subject -dates -serial"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        #print(f"OpenSSL command output: {result.stdout}")
        if result.stderr and "Warning: Reading certificate from stdin" not in result.stderr:
            raise Exception(f"Error obtaining certificate: {result.stderr.strip()}")
        # Extract the certificate details from the output
        issuer = re.search(r'issuer=(.*)', result.stdout).group(1)
        subject = re.search(r'subject=(.*)', result.stdout).group(1)
        not_before = re.search(r'notBefore=(.*)', result.stdout).group(1)
        not_after = re.search(r'notAfter=(.*)', result.stdout).group(1)
        serial_number = re.search(r'serial=(.*)', result.stdout).group(1)
        return issuer, subject, not_before, not_after, serial_number
    except Exception as e:
        print(e)

def get_certificate_expiry(not_after):
    # Check the format of the not_after date
    if 'GMT' in not_after:
        # Convert the not_after string to a datetime object
        end_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
    else:
        end_date = datetime.datetime.strptime(not_after, '%Y-%m-%dT%H:%M:%S')
    # Replace the timezone information with UTC
    end_date = end_date.replace(tzinfo=datetime.timezone.utc)
    # Calculate the number of days from now until the certificate expires
    return (end_date - datetime.datetime.now(datetime.timezone.utc)).days

def get_active_certs(domain):
    # Query crt.sh for active certificates
    response = requests.get(f"https://crt.sh/?q={domain}&output=json")
    certs = response.json()
    # Add the IP address to the certificate data
    ip_addresses = get_ip_addresses(domain)
    for cert in certs:
        cert['ip_address'] = ip_addresses
    return certs

def get_ip_addresses(domain):
    # Run the dig command to get the IP addresses for the domain
    result = subprocess.run(f"dig +short {domain}", shell=True, stdout=subprocess.PIPE, text=True)
    return result.stdout.strip().split("\n")

def write_to_csv(filename, data):
    # Define the field names for the CSV file
    fieldnames = ['issuer_ca_id', 'issuer_name', 'common_name', 'name_value', 'id', 'entry_timestamp', 'not_before', 'not_after', 'serial_number', 'result_count', 'ip_address']
    # Open the file in write
    with open(filename, 'w', newline='') as csvfile:
        # Create a CSV writer
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        # Write the header row
        writer.writeheader()
        # Write the data rows
        for row in data:
            writer.writerow(row)

def write_to_csvs(domain, certs):
    # Write all certificates to a CSV file
    write_to_csv(f'all_certs_{domain}.csv', certs)
    # Filter the certificates to only include those expiring in the next 60 days
    expiring_certs = [cert for cert in certs if 0 < get_certificate_expiry(cert['not_after']) <= 60]
    # Write the expiring certificates to a CSV file
    write_to_csv(f'cert_expiry_60days_{domain}.csv', expiring_certs)

domain = input("Enter a domain: ")
issuer, subject, not_before, not_after, serial_number = check_certificate(domain)
certs = get_active_certs(domain)

print(f"Domain Name: {domain}")
print(f"Issuer Name: {issuer}")
print(f"SAN Names: {subject}")
print(f"Serial Number: {serial_number}")
print(f"Cert Issued Date: {not_before}")
print(f"Cert Expiry Date: {not_after}")
print(f"Count on number of days certificate expiring in: {get_certificate_expiry(not_after)}")
print(f"IP address of the cert location: {certs[0]['ip_address']}")

# Write the certificates to CSV files
write_to_csvs(domain, certs)