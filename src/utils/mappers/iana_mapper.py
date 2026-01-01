import yaml
import os

class IANAMapper:
    def __init__(self):
        """
        Initializes the mapper by loading the IANA hex mappings from the 
        standardized YAML directory.
        """
        # Path Logic:
        # __file__ is src/utils/mapper.py
        # parent 1 is src/utils/
        # parent 2 is src/
        # parent 3 is project_root/
        current_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))
        
        # Target: project_root/yaml/standard/iana_hex_mapping.yaml
        yaml_path = os.path.join(project_root, 'yaml', 'standard', 'iana_hex_mapping.yaml')
        
        self.mapping = {}
        try:
            if os.path.exists(yaml_path):
                with open(yaml_path, 'r', encoding='utf-8') as f:
                    self.mapping = yaml.safe_load(f)
            else:
                print(f"[!] Warning: Mapping file not found at: {yaml_path}")
        except Exception as e:
            print(f"[!] Error loading IANA mapping YAML: {e}")

    def get_name(self, category, hex_val):
        """
        Translates a hex string to a human-readable name.
        
        Args:
            category (str): 'cipher_suites', 'supported_groups', or 'signature_algorithms'
            hex_val (str): The hex code extracted from the packet (e.g., '0x1301')
            
        Returns:
            str: The mapped name if found, otherwise the original hex_val.
        """
        if not hex_val:
            return "Unknown"
        
        # Clean the input: ensure it is a string, lowercase, and stripped of whitespace
        clean_hex = str(hex_val).lower().strip()
        
        # Access the specific category in the YAML
        category_map = self.mapping.get(category, {})
        
        # Return the mapped name; if not found, return the original hex_val as a fallback
        return category_map.get(clean_hex, hex_val)

# Instantiate as a singleton for easy import across the project
mapper = IANAMapper()