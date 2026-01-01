import os
import subprocess
import sys
import json
from src.utils.parsers.network_traffic import tlcp_parser, tls13_parser
from src.utils.parsers.lib_out_parser import openssl_output_parser
from src.analytics import graph_generator

RAW_FOLDER = "data/raw/"
PROCESSED_FOLDER = "data/processed"
MASTER_REPORT_NAME = "final_analysis_report.json"

PARSER_REGISTRY = {
    "TLCP": tlcp_parser.parse_tlcp,
    "TLS": tls13_parser.run_analysis,
    "OPENSSL_LOG": openssl_output_parser.parse_openssl_log
}


def get_protocol_type(file_path):
    # If it's a text file, we don't use Tshark
    if file_path.endswith('.txt'):
        return "OPENSSL_LOG"
        
    try:
        cmd = f'tshark -r "{file_path}" -Y "tls.record.version or ssl.record.version" -T fields -e tls.record.version -e ssl.record.version'
        result = subprocess.run(cmd, text=True, shell=True, capture_output=True, encoding='utf-8')
        output = result.stdout.strip()

        if "0x0101" in output:
            return "TLCP"
        elif "0x03" in output: 
            return "TLS"
        else:
            return "UNKNOWN"
            
    except Exception as e:
        print(f"Error identification: {e}")
        return "ERROR"

def main():
    os.makedirs(PROCESSED_FOLDER, exist_ok=True)
    all_results = []

    # Update: Look for .pcap, .pcapng, and .txt files
    files = [f for f in os.listdir(RAW_FOLDER) if f.endswith(('.pcap', '.pcapng', '.txt'))]
    
    print(f"[*] Found {len(files)} files to analyze...")

    for filename in files:
        path = os.path.join(RAW_FOLDER, filename)
        protocol = get_protocol_type(path)
        
        # Look up the correct tool for the job
        parser = PARSER_REGISTRY.get(protocol)
        
        if parser:
            # Stage 1: Discovery
            raw_data = parser(path)
            all_results.append(raw_data)
        else:
            print(f"[!] Analysis failed or returned no data for {filename}.")

    # Save merged results
    master_report_path = os.path.join(PROCESSED_FOLDER, MASTER_REPORT_NAME)
    with open(master_report_path, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=4)

    # 2. Call the Graph Generator IMMEDIATELY using the list in memory
    print("[*] Generating Gephi graph files...")
    nodes_out = os.path.join(PROCESSED_FOLDER, "nodes.csv")
    edges_out = os.path.join(PROCESSED_FOLDER, "edges.csv")
    
    # You pass the list 'all_results', not the file path
    graph_generator.generate_graph_files(all_results, nodes_out, edges_out)

if __name__ == "__main__":
    main()