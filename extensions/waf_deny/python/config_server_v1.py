import os
import sys
import re
import json
from jsonschema import validate
from http.server import BaseHTTPRequestHandler, HTTPServer


KEEP_RUNNING = True


def keep_running():
    return KEEP_RUNNING


class WafRequestHandler(BaseHTTPRequestHandler):
    def __set_response(self, content_type, content_length):
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', content_length)
        self.end_headers()

    def do_GET(self):
        h = self.headers.get('identity')
        if h == 'waf_deny_wasm':
            print("Received GET request from WAF Deny WASM plugin.")
            body = json.dumps(
                self.server.plugin_config).encode('utf-8')
            self.__set_response('application/json', str(len(body)))
            self.wfile.write(body)
        else:
            if (h):
                print("Error: invalid authority: " + h)
            else:
                print("Error: missing authority header.")
            self.send_response(404)
            self.end_headers()

        print("Exiting...")
        global KEEP_RUNNING
        KEEP_RUNNING = False


class WafHTTPServer(HTTPServer):
    def __init__(self, server_address, plugin_config,
                 handler_class=WafRequestHandler):
        super().__init__(server_address, handler_class)
        self.plugin_config = plugin_config


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python config_server_v1.py <server_ip:server_port> <path_to_json_schema> <path_to_plugin_config>")
        sys.exit(1)

    server_address = sys.argv[1]
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$'
    if not re.match(pattern, server_address):
        print("Error: invalid server address: " + server_address)
        sys.exit(1)
    ip, port = server_address.split(':')
    server_address = (ip, int(port))

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

    httpd = WafHTTPServer(server_address, plugin_config, WafRequestHandler)
    print('Starting config server on {}:{}'.format(
        server_address[0], server_address[1]))
    while keep_running():
        httpd.handle_request()
