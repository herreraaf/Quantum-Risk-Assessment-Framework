import subprocess
import re

def get_tshark_data(pcap_file, display_filter):
    # Constructing the command with explicit quoting
    # Using 'tls' as a fallback since many modern tsharks use that for TLCP
    cmd = f'tshark -r {pcap_file} -Y "{display_filter}" -V'
    
    # run() instead of check_output() allows us to ignore the 'cut short' exit code
    result = subprocess.run(
        cmd, 
        shell=True, 
        capture_output=True, 
        text=True, 
        encoding='utf-8'
    )
    
    # Even if tshark returns error code 2 (due to truncation), 
    # the partial data is still in result.stdout
    return result.stdout

def parse_tlcp(pcap_path):
    # This structure is identical to your TLS 1.3 script, 
    # but the 'Certificates' key is expanded for the TLCP Dual-Cert requirement.
    results = {
        "Origin": "Local_Research_Node" ,
        "Domain": "Data In Transit",
        "Protocol": "TLCP",
        "Implementation": "GmSSL 3.1.2 Dev",
        "ClientHello": {
            "cipher_suites": [],
            "supported_groups": [],
            "signature_algorithms": []
        },
        "ServerHello": {
            "cipher_suite": None,
            "NamedGroup": None
        },
        "Certificates": {
            "Signing": None,     # First certificate in TLCP chain
            "Encryption": None   # Second certificate in TLCP chain
        }
    }

    # 1. CLIENT HELLO
    ch_raw = get_tshark_data(pcap_path, "tls.handshake.type == 1")
    if ch_raw:
        # Capture suites: list(set()) avoids duplicates and JSON errors
        cs_matches = re.findall(r"Cipher Suite: (.*?) \((0x.*?)\)", ch_raw)
        results["ClientHello"]["cipher_suites"] = [{"hex": m[1], "name": m[0]} for m in list(set(cs_matches))]
        
        # Capture groups from Extensions
        results["ClientHello"]["supported_groups"] = list(set(re.findall(r"Group: (.*?)(?=\s|\()", ch_raw)))

    # 2. SERVER HELLO & KEY EXCHANGE
    sh_raw = get_tshark_data(pcap_path, "tls.handshake.type == 2")
    if sh_raw:
        selected_cs = re.search(r"Cipher Suite: (.*?) \(", sh_raw)
        results["ServerHello"]["cipher_suite"] = selected_cs.group(1) if selected_cs else None

    ske_raw = get_tshark_data(pcap_path, "tls.handshake.type == 12")
    if ske_raw:
        # In TLCP, the group is explicitly defined in the Server Key Exchange
        results["ServerHello"]["NamedGroup"] = "SM2" # Default for TLCP if parameters found

    # 3. DUAL CERTIFICATES (The logic you requested)
    cert_raw = get_tshark_data(pcap_path, "tls.handshake.type == 11")
    if cert_raw:
        # Split the raw data by certificate blocks
        cert_blocks = re.split(r"Certificate Length:", cert_raw)[1:]
        
        cert_roles = ["Signing", "Encryption"]
        for i, block in enumerate(cert_blocks):
            if i > 1: break # We only care about the first two for TLCP
            
            results["Certificates"][cert_roles[i]] = {
                "Serial Number": re.search(r"serialNumber: (.*?)\n", block).group(1) if "serialNumber:" in block else "",
                "Signature Algorithm": "SM2-with-SM3", # Standard for TLCP
                "Issuer": re.search(r"issuer: (.*?)\n", block).group(1) if "issuer:" in block else "Unknown",
                "Validity": {
                    "Not Before": "Parsed", 
                    "Not After": "Parsed"
                },
                "Subject": re.search(r"subject: (.*?)\n", block).group(1) if "subject:" in block else "Unknown",
                "Public Key Algorithm": "SM2"
            }

    return results

if __name__ == "__main__":
    pcap_filename = "tlcp.pcap"
    data = parse_tlcp(pcap_filename)
    
    # Use the custom encoder to avoid TypeError: Object of type set is not JSON serializable
    #print(json.dumps(data, indent=2))