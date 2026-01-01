import re

def parse_openssl_log(file_path):
    """
    Parses OpenSSL trace/log files into a unified JSON structure 
    compatible with the 6-layer framework.
    """
    output = {
        "Origin": "Local_Research_Node" ,
        "Domain": "Data In Transit",
        "Protocol": "TLS 1.3",
        "Implementation": "OpenSSL 3.0.17",
        "ClientHello": {
            "cipher_suites": [],
            "supported_groups": [],
            "signature_algorithms": []
        },
        "ServerHello": {
            "cipher_suite": None,
            "NamedGroup": None
        },
        "Certificate": None # Initialized as None for 'Missing Cert' logic
    }

    try:
        with open(file_path, "r", encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading log file: {e}")
        return None

    current_section = None
    certificate_data = {}
    capture_signature = False
    signature_lines = []

    for line in lines:
        line = line.strip()

        # --- Section Detection ---
        if line.startswith("ClientHello"):
            current_section = "ClientHello"
        elif line.startswith("ServerHello"):
            current_section = "ServerHello"
        elif line.startswith("Certificate:"):
            current_section = "Certificate"
            capture_signature = False

        # --- Layer 5: ClientHello Parsing ---
        if current_section == "ClientHello":
            # 1. Capture Cipher Suites: Matches hex pattern {0x13, 0x01} and the name
            m_cipher = re.match(r"(\{0x[0-9A-Fa-f]+,\s*0x[0-9A-Fa-f]+\})\s*(.+)", line)
            if m_cipher:
                output["ClientHello"]["cipher_suites"].append({
                    "hex": m_cipher.group(1),
                    "name": m_cipher.group(2)
                })

            # 2. Capture Supported Groups: Layer 5/6 bridge
            # Identify potential group lines by keywords
            if any(key in line for key in ["secp", "x25519", "ffdhe","x448"]):
                
                # REFINEMENT: Exclude lines that are actually Signature Algorithms
                # These lines contain 'ecdsa' or have the '(0xXXXX)' hex signature ID
                if "ecdsa" not in line.lower() and not re.search(r"\(0x[0-9A-Fa-f]+\)", line):
                    
                    # Clean up "NamedGroup: secp256r1" vs just "secp256r1"
                    m_group = re.search(r"(?:NamedGroup:\s*)?([\w-]+)", line)
                    if m_group:
                        group_name = m_group.group(1)
                        # Ensure we don't accidentally append the label "NamedGroup" itself
                        if group_name != "NamedGroup":
                            output["ClientHello"]["supported_groups"].append(group_name)

            # signature_algorithms
            m = re.match(r"(\w+.*)\s+\((0x[0-9A-Fa-f]+)\)", line)
            if m:
                output["ClientHello"]["signature_algorithms"].append({
                    "name": m.group(1),
                    "hex": m.group(2)
                })

        # --- Layer 5: ServerHello Parsing ---
        elif current_section == "ServerHello":
            m = re.match(r"cipher_suite\s*\{.*\}\s*(.+)", line)
            if m:
                output["ServerHello"]["cipher_suite"] = m.group(1)
            m = re.match(r"NamedGroup:\s*(\w+)", line)
            if m:
                output["ServerHello"]["NamedGroup"] = m.group(1)

        # --- Layer 5: Certificate Parsing (Metadata) ---
        elif current_section == "Certificate":
            if line.startswith("Serial Number:"):
                certificate_data["Serial Number"] = line.replace("Serial Number:", "").strip()
            elif line.startswith("Signature Algorithm:") and "Signature Value" not in certificate_data:
                certificate_data["Signature Algorithm"] = line.replace("Signature Algorithm:", "").strip()
            elif line.startswith("Issuer:"):
                certificate_data["Issuer"] = line.replace("Issuer:", "").strip()
            elif line.startswith("Not Before:"):
                certificate_data.setdefault("Validity", {})["Not Before"] = line.replace("Not Before:", "").strip()
            elif line.startswith("Not After :"):
                certificate_data.setdefault("Validity", {})["Not After"] = line.replace("Not After :", "").strip()
            elif line.startswith("Subject:"):
                certificate_data["Subject"] = line.replace("Subject:", "").strip()
            elif line.startswith("Public Key Algorithm:"):
                certificate_data["Public Key Algorithm"] = line.replace("Public Key Algorithm:", "").strip()
            elif "ASN1 OID:" in line:
                certificate_data["ASN1 OID"] = line.split("ASN1 OID:")[1].strip()
            elif line.startswith("Signature Value:"):
                capture_signature = True
                signature_lines = []
            elif capture_signature and re.match(r"[0-9A-Fa-f:]+", line):
                signature_lines.append(line.replace(":", ""))
            elif capture_signature and not re.match(r"[0-9A-Fa-f:]+", line):
                capture_signature = False
                certificate_data["Signature Value"] = "".join(signature_lines)

    # Only attach certificate_data if we actually found a "Certificate" section
    if certificate_data:
        output["Certificate"] = certificate_data
    return output