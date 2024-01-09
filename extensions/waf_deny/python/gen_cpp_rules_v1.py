import os
import sys
import yaml
from openapi_schema_validator import validate


class CPPRuleGenerator:
    def __init__(self, rules_dir):
        self.rules_dir = rules_dir
        if self.rules_dir[-1] != '/':
            self.rules_dir += '/'
        self.version = "v1"
        self.schema_file = "rule_schema.yaml"
        self.metadata = {}
        self.rules = {}

    # Generate rules.cc
    def gen_cpp_rules(self, cpp_filename):
        if not os.path.isfile(self.rules_dir + self.schema_file):
            print(
                f"Error: {self.rules_dir} does not contain " + self.schema_file)
            sys.exit(1)
        with open(self.rules_dir + self.schema_file, 'r') as file:
            schema_data = yaml.safe_load(file)
            for version in schema_data["versions"]:
                if version["name"] == self.version:
                    self.schema = version["schema"]["openAPIV3Schema"]
                    break
        if self.schema == None:
            print(f"Error: version {self.version} is not found in schema file")
            sys.exit(1)
        self.__traverse_rules_dir()
        self.__dump_cpp_source(cpp_filename)

    # Traverse rules_dir and load yaml files
    def __traverse_rules_dir(self):
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                filename = root[len(self.rules_dir):]
                if len(filename) > 0:
                    filename += "/"
                filename += file
                if (file.endswith('.yml') or file.endswith(
                        '.yaml')) and file != self.schema_file:
                    file_path = os.path.join(root, file)
                    print(f'Loading yaml file: {file_path}...', end="")
                    with open(file_path, 'r') as f:
                        yaml_data = yaml.safe_load(f)
                    print(f' Validating...', end="")
                    validate(yaml_data, self.schema)
                    print(f' Processing...', end="")
                    self.__read_yaml(filename, yaml_data)
                    print(f' Done')

    # Read yaml file and store data
    def __read_yaml(self, filename, yaml_data):
        self.metadata[filename] = {}
        if "version" in yaml_data:
            self.metadata[filename]["version"] = yaml_data["version"]
        if "kind" in yaml_data:
            self.metadata[filename]["kind"] = yaml_data["kind"]
        for rule in yaml_data["rules"]:
            if rule["id"] in self.rules:
                print(
                    f"Error: [{filename}] rule id {rule['id']} is duplicated")
                sys.exit(1)
            self.rules[rule["id"]] = rule
            self.rules[rule["id"]]["filename"] = filename

    # Convert python object to cpp string
    def __to_cpp_string(self, hint, text, standard=False):
        if text is None:
            return "{}"
        if type(text) is str:
            if standard:
                text = text.replace(" ", "")
                text = text.lower()
            for c in ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j']:
                if ")" + c + "\"" not in text:
                    return "R\"" + c + "(" + text + ")" + c + "\""
            print(
                f"Error: [{hint}] avaialble c++ raw string d-char-sequences are used out: {text}")
            sys.exit(1)
        elif type(text) is int:
            return str(text)
        elif type(text) is list:
            return "{" + ",".join([self.__to_cpp_string(hint, x, standard)
                                  for x in text]) + "}"

    # Dump cpp source file
    def __dump_cpp_source(self, cpp_filename):
        print("Sort rules by id...")
        rule_ids = list(self.rules.keys())
        rule_ids.sort()
        self.rules = {i: self.rules[i] for i in rule_ids}
        print(f"Dumping cpp rules to {cpp_filename}...")
        with open(cpp_filename, 'w') as f:
            f.write(
                """// This file is generated by gen_cpp_rules_v1.py

#include "extensions/waf_deny/static_rules.h"

#ifdef NULL_PLUGIN

namespace proxy_wasm {
namespace null_plugin {
namespace waf_deny {

#endif

""")
            # Write metadata
            f.write(
                "WafMetadataSet metadata = {")
            for k, v in self.metadata.items():
                f.write(
                    """
  {{
    {0},
    {{
      .version = {1},
      .kind = {2}
    }}
  }},""".format(self.__to_cpp_string(k, k),
                        self.__to_cpp_string(k, v["version"]),
                        self.__to_cpp_string(k, v["kind"])))
            f.write("\n};\n\n")

            # Write rules
            f.write("WafStaticRuleSet static_rules = {")
            for k, v in self.rules.items():
                assert v["id"] == k
                f.write("""
  {{
    .id = {0},
    .payload = {1},
    .match_type = {2},
    .action = {3},
    .placeholders = {4},
    .transformations = {5},
    .tags = {6},
    .filename = {7}
  }},""".format(self.__to_cpp_string(k, v["id"]),
                    self.__to_cpp_string(k, v["payload"]),
                    self.__to_cpp_string(k, v["matchType"], True),
                    self.__to_cpp_string(k, v["action"], True),
                    self.__to_cpp_string(k, v["placeholders"], True),
                    self.__to_cpp_string(
                    k, v["transformations"], True),
                    self.__to_cpp_string(k, v.get("tags")),
                    self.__to_cpp_string(k, v["filename"])))
            f.write("\n};\n\n")
            print(f"Dumping data file to {cpp_filename}...")
            self.__dump_data(f)
            f.write("""
#ifdef NULL_PLUGIN

}  // namespace waf_deny
}  // namespace null_plugin
}  // namespace proxy_wasm

#endif
                    """)
        os.system("clang-format --style=file -i {}".format(cpp_filename))

    # Dump content of data file to cpp source file
    def __dump_data(self, cpp_f):
        cpp_f.write(
            "WafRuleDataSet rule_data = {")
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                filename = root[len(self.rules_dir):]
                if len(filename) > 0:
                    filename += "/"
                filename += file
                if file.endswith('.data'):
                    file_path = os.path.join(root, file)
                    data_lines = ""
                    with open(file_path, 'r') as f:
                        while True:
                            line = f.readline()
                            if not line:
                                break
                            if line.startswith('#') or line == "\n":
                                continue
                            data_lines += line
                    cpp_f.write("""
  {{
    {0},
    {1}
  }},""".format(self.__to_cpp_string(filename, filename),
                        self.__to_cpp_string(filename, data_lines)))
        cpp_f.write("\n};\n\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python gen_cpp_rules_v1.py <path_to_yaml_rules_dir>")
        sys.exit(1)

    rules_dir = sys.argv[1]
    if not os.path.isdir(rules_dir):
        print(f"Error: {rules_dir} is not a directory")
        print("Usage: python gen_cpp_rules_v1.py <path_to_yaml_rules_dir>")
        sys.exit(1)

    cpp_rule_generator = CPPRuleGenerator(rules_dir)
    cpp_rule_generator.gen_cpp_rules("static_rules.cc")