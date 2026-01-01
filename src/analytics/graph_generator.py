import csv
import os

# --- COMPLIANCE LISTS ---
TLS13_ALLOWED = {
    "ciphers": ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"],
    "groups": ["ecdh_x25519", "secp256r1", "ecdh_x448", "secp521r1", "secp384r1", "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192"],
    "sigs": ["ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384", "ecdsa_secp521r1_sha512", "ed25519", "ed448", "rsa_pss_rsae_sha256","rsa_pss_rsae_sha384","rsa_pss_rsae_sha512","ecdsa-with-SHA256"] #we removed the rsa_pss_pss_* for simplicity in the analysis
}

TLCP_ALLOWED = {
    "ciphers": ["ECC_SM4_CBC_SM3", "ECC_SM4_GCM_SM3", "ECDHE_SM4_CBC_SM3", "ECDHE_SM4_GCM_SM3"],
    "groups": ["sm2", "sm2p256v1"], 
    "sigs": ["SM2-with-SM3"]
}

def generate_graph_files(all_results, nodes_path, edges_path):
    """
    Transforms a list of analysis results into Gephi-compatible CSV files.
    """
    unique_nodes = {}
    unique_edges = set()

    for entry in all_results:
        # --- LAYER 1-4: BACKBONE ---
        origin = entry.get("Origin", "Local_Research_Node")
        domain = entry.get("Domain", "Data_In_Transit")
        proto  = entry.get("Protocol", "UNKNOWN")
        impl   = entry.get("Implementation", "GmSSL 3.1.2 Dev")

        unique_nodes[origin] = (origin, f"Origin: {origin}", "Layer 1")
        unique_nodes[domain] = (domain, f"Domain: {domain}", "Layer 2")
        unique_nodes[proto]  = (proto, f"Protocol: {proto}", "Layer 3")
        unique_nodes[impl]   = (impl, f"Implementation: {impl}", "Layer 4")

        unique_edges.add((origin, domain, "contains"))
        unique_edges.add((domain, proto, "hosts"))
        unique_edges.add((proto, impl, "implemented_by"))

        # --- HARDCODED GMSSL LINK ---
        # Direct relationship: GmSSL -> SM2-with-SM3
        if "gmssl" in impl.lower():
            unique_nodes["sm2_with_sm3"] = ("sm2_with_sm3", "SM2-with-SM3", "Layer 6")
            unique_edges.add((impl, "sm2_with_sm3", "offers_sig_alg"))

        # --- LAYER 5-6: ASSETS & PRIMITIVES ---
        is_tlcp = (proto == "TLCP")
        whitelist = TLCP_ALLOWED if is_tlcp else TLS13_ALLOWED
        ch = entry.get("ClientHello", {})

        # 1. Cipher Suites with IDs Cleaned
        for suite in ch.get("cipher_suites", []):
            if suite["name"] in whitelist["ciphers"]:
                raw_id = suite["hex"]
                # Normalization for TLS 1.3 curly brace formats
                s_id = str(raw_id).replace('{0x13, 0x01}', '0x1301').replace('{0x13, 0x02}', '0x1302').replace('{0x13, 0x03}', '0x1303')
                unique_nodes[s_id] = (s_id, suite["name"], "Layer 5")
                unique_edges.add((impl, s_id, "offers_suite"))

        # 2. Supported Groups
        for group in ch.get("supported_groups", []):
            if group.lower() in [g.lower() for g in whitelist["groups"]]:
                unique_nodes[group] = (group, group, "Layer 5")
                unique_edges.add((impl, group, "offers_group"))

        # 3. Signature Algorithms
        ch_sigs = ch.get("signature_algorithms", [])
        for sig in ch_sigs:
            sig_name = sig.get("name") if isinstance(sig, dict) else sig
            sig_hex = sig.get("hex") if isinstance(sig, dict) else sig_name
            
            if sig_name in whitelist["sigs"]:
                unique_nodes[sig_hex] = (sig_hex, sig_name, "Layer 5")
                unique_edges.add((impl, sig_hex, "offers_sig_alg"))

        # 4. Certificates (Static Key Exchange Link)
        certs_dict = entry.get("Certificates", {}) if is_tlcp else {}
        if not is_tlcp and entry.get("Certificate"):
            certs_dict = {"Standard": entry.get("Certificate")}
        
        for role, cert_data in certs_dict.items():
            if cert_data:
                cert_id = cert_data.get("Serial Number") or cert_data.get("Signature Value")
                if not cert_id: continue 
                
                sig_algo_in_cert = cert_data.get("Signature Algorithm")
                unique_nodes[cert_id] = (cert_id, f"{role} Cert: {cert_id[:10]}...", "Layer 5.5")
                unique_edges.add((impl, cert_id, f"presents_{role.lower()}"))

                if sig_algo_in_cert:
                    math_id = f"{sig_algo_in_cert.replace('-','_').lower()}"
                    unique_nodes[math_id] = (math_id, sig_algo_in_cert, "Layer 6")
                    unique_edges.add((cert_id, math_id, "signed_with"))

    # FINAL DEDUPLICATION BY LABEL
    unique_nodes_list = {node[1]: node for node in unique_nodes.values()}.values()

    # --- WRITE CSV FILES ---
    with open(nodes_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Id', 'Label', 'Layer'])
        writer.writerows(unique_nodes_list)
    

    with open(edges_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Source', 'Target', 'Type'])
        writer.writerows(unique_edges)

    print(f"[*] Unified Graph Generated: {len(unique_nodes_list)} nodes and {len(unique_edges)} edges.")
    print(unique_nodes_list)