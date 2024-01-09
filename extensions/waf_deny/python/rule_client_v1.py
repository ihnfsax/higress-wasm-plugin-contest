import os
import sys
import re
import rule_serializer_v1
import requests

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python rule_client_v1.py <plugin_ip:plugin_port> <path_to_yaml_rules_dir>")
        sys.exit(1)

    plugin_address = sys.argv[1]
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$'
    if not re.match(pattern, plugin_address):
        print("Error: invalid plugin address: " + plugin_address)
        sys.exit(1)

    rules_dir = sys.argv[2]
    if not os.path.isdir(rules_dir):
        print(f"Error: {rules_dir} is not a directory")
        print("Usage: python rule_client_v1.py <plugin_ip:plugin_port> <path_to_yaml_rules_dir>")
        sys.exit(1)

    rule_serializer = rule_serializer_v1.RuleSerializer(rules_dir)
    serialized_rules = rule_serializer.get_serialized_rules().SerializeToString()

    headers = {
        'Content-Type': 'application/protobuf',
        'Content-Length': str(len(serialized_rules)),
        'identity': 'waf_deny_wasm'
    }

    response = requests.post("http://" + plugin_address,
                             data=serialized_rules, headers=headers)

    print(response.text)
