import pandas as pd
import itertools

def generate_combinations_from_graph(nodes_path, edges_path):
    # Load the graph data
    nodes = pd.read_csv(nodes_path)
    edges = pd.read_csv(edges_path)

    # 1. Identify our Implementations (Layer 4)
    implementations = nodes[nodes['Layer'] == 'Layer 4']['Id'].tolist()
    
    simulation_results = []

    for impl in implementations:
        # Find all Cipher Suites (Layer 5) linked to this Impl
        suites = edges[(edges['Source'] == impl) & (edges['Type'] == 'offers_suite')]['Target'].tolist()
        
        # Find all Groups (Layer 5) linked to this Impl
        groups = edges[(edges['Source'] == impl) & (edges['Type'] == 'offers_group')]['Target'].tolist()
        
        # Find all Signatures (Layer 5/6) linked to this Impl
        sigs = edges[(edges['Source'] == impl) & (edges['Type'] == 'offers_sig_alg')]['Target'].tolist()

        # --- SIMULATION RULES ---
        if "gmssl" in impl.lower():
            # TLCP Logic: Usually a fixed 1-to-1-to-1 mapping in your setup
            # We "collapse" the surface to the known static path
            path = f"{impl} -> [SM2_SM4_SM3]"
            simulation_results.append({"Implementation": impl, "Combination": path, "Complexity": "Low (Static)"})
        
        else:
            # TLS 1.3 Logic: Calculate the Cartesian Product (All possible combinations)
            # This represents the "Negotiation Surface"
            combinations = list(itertools.product(groups, suites, sigs))
            for combo in combinations:
                path = f"{impl} -> [{' / '.join(combo)}]"
                simulation_results.append({"Implementation": impl, "Combination": path, "Complexity": "High (Ephemeral)"})

    return pd.DataFrame(simulation_results)

# Run the simulation
df_sim = generate_combinations_from_graph('nodes.csv', 'edges.csv')
print(df_sim)