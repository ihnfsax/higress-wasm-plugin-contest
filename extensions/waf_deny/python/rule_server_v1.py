import os
import sys
import re
import rule_serializer_v1
from http.server import BaseHTTPRequestHandler, HTTPServer


KEEP_RUNNING = True


def keep_running():
    return KEEP_RUNNING


class WafRequestHandler(BaseHTTPRequestHandler):
    def _set_response(self, content_type, content_length):
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', content_length)
        self.end_headers()

    def do_GET(self):
        h = self.headers.get('identity')
        if h == 'waf_deny_wasm':
            print("Received GET request from WAF Deny WASM plugin.")
            self._set_response('application/protobuf',
                               len(self.server.serialized_rules))
            self.wfile.write(self.server.serialized_rules)
        else:
            if (h):
                print("Error: invalid identity: " + h)
            else:
                print("Error: missing identity header.")
            self.send_response(404)
            self.end_headers()

        print("Exiting...")
        global KEEP_RUNNING
        KEEP_RUNNING = False


class WafHTTPServer(HTTPServer):
    def __init__(self, server_address, serialized_rules,
                 handler_class=WafRequestHandler):
        super().__init__(server_address, handler_class)
        self.serialized_rules = serialized_rules


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python rule_server_v1.py <server_ip:server_port> <path_to_yaml_rules_dir>")
        sys.exit(1)

    server_address = sys.argv[1]
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$'
    if not re.match(pattern, server_address):
        print("Error: invalid server address: " + server_address)
        sys.exit(1)
    ip, port = server_address.split(':')
    server_address = (ip, int(port))

    rules_dir = sys.argv[2]
    if not os.path.isdir(rules_dir):
        print(f"Error: {rules_dir} is not a directory")
        print("Usage: python rule_server_v1.py <server_ip:server_port> <path_to_yaml_rules_dir>")
        sys.exit(1)

    rule_serializer = rule_serializer_v1.RuleSerializer(rules_dir)
    serialized_rules = rule_serializer.get_serialized_rules().SerializeToString()

    httpd = WafHTTPServer(server_address, serialized_rules, WafRequestHandler)
    print('Starting rule server on {}:{}'.format(
        server_address[0], server_address[1]))
    while keep_running():
        httpd.handle_request()
