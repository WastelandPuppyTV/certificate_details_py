import ssl
import socket
import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID

def get_certificate(hostname):
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    conn.connect((hostname, 443))
    certificate = conn.getpeercert(binary_form=True)
    conn.close()
    return certificate

def extract_sans(certificate):
    cert = x509.load_der_x509_certificate(certificate, default_backend())
    sans = []
    try:
        san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_extension.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    return sans

def extract_common_name(certificate):
    cert = x509.load_der_x509_certificate(certificate, default_backend())
    try:
        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        return common_name
    except IndexError:
        return None

def main():
    results = []
    with open("hosts.txt", "r") as file:
        hostnames = file.readlines()
    
    for hostname in hostnames:
        hostname = hostname.strip()
        if hostname:
            certificate = get_certificate(hostname)
            common_name = extract_common_name(certificate)
            sans = extract_sans(certificate)
            result = {
                "hostname": hostname,
                "common_name": common_name,
                "subject_alternative_names": sans
            }
            results.append(result)
    
    with open("certificate_details.json", "w") as f:
        json.dump(results, f, indent=4)
    
    print("Results written to certificate_details.json")

if __name__ == "__main__":
    main()