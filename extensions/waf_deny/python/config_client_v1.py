import os
import sys
import re
import json
from jsonschema import validate
import requests

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python config_client_v1.py <plugin_ip:plugin_port> <path_to_json_schema> <path_to_plugin_config>")
        sys.exit(1)

    plugin_address = sys.argv[1]
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$'
    if not re.match(pattern, plugin_address):
        print("Error: invalid plugin address: " + plugin_address)
        sys.exit(1)

    json_schema_path = sys.argv[2]
    if (not os.path.isfile(json_schema_path)) or (
            not json_schema_path.endswith('.json')):
        print("Error: invalid json schema path: " + json_schema_path)
        sys.exit(1)

    plugin_config_path = sys.argv[3]
    if (not os.path.isfile(plugin_config_path)) or (
            not plugin_config_path.endswith('.json')):
        print("Error: invalid plugin config path: " + plugin_config_path)
        sys.exit(1)

    with open(json_schema_path) as schema_file:
        schema = json.load(schema_file)

    with open(plugin_config_path) as config_file:
        plugin_config = json.load(config_file)

    try:
        validate(instance=plugin_config, schema=schema)
        print("Plugin configuration is valid.")
    except jsonschema.exceptions.ValidationError as e:
        print("Error: plugin configuration is not valid.")
        print(e)
        sys.exit(1)

    json_data = json.dumps(plugin_config).encode('utf-8')

    headers = {
        'Content-Type': 'application/json',
        'Content-Length': str(len(json_data)),
        'identity': 'waf_deny_wasm'
    }

    response = requests.post("http://" + plugin_address,
                             data=json_data, headers=headers)

    print(response.text)
