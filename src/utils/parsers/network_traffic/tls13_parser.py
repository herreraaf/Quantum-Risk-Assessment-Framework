import pyshark
import json
from src.utils.mappers.iana_mapper import mapper

def run_analysis(pcap_path):
    return parse_tls13(str(pcap_path))

def parse_tls13(file_path):
    """
    Consolidates TLS 1.3 Handshake data into ClientHello, 
    ServerHello, and Certificate sections.
    """
    # Filter for ClientHello (1), ServerHello (2), and Certificate (11)
    cap = pyshark.FileCapture(
        file_path, 
        display_filter='tls.handshake.type == 1 || tls.handshake.type == 2 || tls.handshake.type == 11'
    )
    
    # Initialize the output structure
    extracted_data = {
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
        "Certificate": None  # Will remain None if handshake type 11 is missing
    }

    for pkt in cap:
        if not hasattr(pkt, 'tls'): continue
        tls = pkt.tls
        h_type = getattr(tls, 'handshake_type', None)

        # 1. CLIENT HELLO
        if h_type == '1':
            if hasattr(tls, 'handshake_ciphersuite'):
                suites = tls.handshake_ciphersuite.all_fields
                extracted_data["ClientHello"]["cipher_suites"] = [
                    {"hex": f"{s.get_default_value()}", "name": mapper.get_name("cipher_suites", s.get_default_value())}
                    for s in suites
                ]

            if hasattr(tls, 'handshake_extensions_supported_group'):
                groups = tls.handshake_extensions_supported_group.all_fields
                extracted_data["ClientHello"]["supported_groups"] = [
                    mapper.get_name("supported_groups", g.get_default_value()) for g in groups
                ]

            # Signature Algorithm parsing
            sig_algs = []
            if hasattr(tls, 'handshake_extensions_signature_hash_alg'):
                sig_algs = tls.handshake_extensions_signature_hash_alg.all_fields
            elif hasattr(tls, 'handshake_sig_hash_alg'):
                sig_algs = tls.handshake_sig_hash_alg.all_fields
            
            if sig_algs:
                extracted_data["ClientHello"]["signature_algorithms"] = [
                    {"name": mapper.get_name("signature_algorithms", s.get_default_value()), "hex": f"{s.get_default_value()}"}
                    for s in sig_algs
                ]

        # 2. SERVER HELLO
        elif h_type == '2':
            if hasattr(tls, 'handshake_ciphersuite'):
                raw_cipher = tls.handshake_ciphersuite.get_default_value()
                extracted_data["ServerHello"]["cipher_suite"] = mapper.get_name("cipher_suites", raw_cipher)
            
            if hasattr(tls, 'handshake_extensions_key_share_group'):
                raw_group = tls.handshake_extensions_key_share_group.get_default_value()
                extracted_data["ServerHello"]["NamedGroup"] = mapper.get_name("supported_groups", raw_group)

        # 3. CERTIFICATE (Captured if decrypted or using key logs)
        elif h_type == '11':
            extracted_data["Certificate"] = {
                "Serial Number": getattr(tls, 'x509af_serialNumber', ""),
                "Signature Algorithm": getattr(tls, 'x509af_algorithm_id', "Unknown"),
                "Issuer": getattr(tls, 'x509ce_issuer', "Unknown"),
                "Validity": {
                    "Not Before": getattr(tls, 'x509af_utcTime', "Unknown"),
                    "Not After": getattr(tls, 'x509af_utcTime', "Unknown")
                },
                "Subject": getattr(tls, 'x509ce_subject', "Unknown"),
                "Public Key Algorithm": getattr(tls, 'x509af_algorithm_id', "Unknown"),
                "ASN1 OID": getattr(tls, 'x509ce_object_identifier_id', "Unknown"),
                "Signature Value": getattr(tls, 'x509af_signature', "None")
            }

    cap.close()
    return extracted_data

if __name__ == "__main__":
    target_pcap = "tls13_1.pcapng" 
    results = run_analysis(target_pcap)
    
    # Print as indented JSON to match your requested aesthetic
    print(json.dumps(results, indent=2))