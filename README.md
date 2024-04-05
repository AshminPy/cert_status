README
Certificate Status Checker:
This script is used to check the status of SSL certificates for a list of domains. 
It retrieves certificate information such as the issuer, subject, issue date, expiry date, serial number, and Subject Alternative Names (SANs). 
It also calculates the number of days remaining until the certificate expires and writes this information to a CSV file.

How to Use
Run the script in a Python environment.
When prompted, enter the domains you want to check, separated by commas.
The script will validate each domain, retrieve the certificate information, and write it to a CSV file.

Dependencies: check requirement.txt

This script requires the following Python packages:

requests
datetime
re
csv
termcolor
subprocess
Technical Documentation

The script is composed of several functions:

is_valid_domain(domain): Validates the domain name using a regular expression.
check_certificate(domain): Uses the openssl command to retrieve certificate information for the given domain.
get_certificate_expiry(not_after): Calculates the number of days remaining until the certificate expires.
get_active_certs(domain): Retrieves active certificates for the domain from crt.sh.
get_ip_addresses(domain): Uses the dig command to retrieve IP addresses for the domain.
write_to_csv(filename, row): Writes the certificate information to a CSV file.

The script prompts the user to enter a list of domains. It then validates each domain and retrieves the certificate information. 
The certificate information is printed to the console and written to a CSV file. If the certificate is expiring in less than 15 days, the number of days until expiry is printed in red. 
If it's expiring in less than 30 days, it's printed in yellow. Otherwise, it's printed in green. 
The script also retrieves active certificates for the domain and prints the IP address of the certificate location.
