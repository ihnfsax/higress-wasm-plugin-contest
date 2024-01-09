import os
import sys
import yaml
import rules_message_pb2
from openapi_schema_validator import validate


class RuleSerializer:
    def __init__(self, rules_dir):
        self.rules_dir = rules_dir
        if self.rules_dir[-1] != '/':
            self.rules_dir += '/'
        self.version = "v1"
        self.schema_file = "rule_schema.yaml"
        self.rule_message = rules_message_pb2.RulesMessage()
        self.rules = {}

    def get_serialized_rules(self):
        self.__load_schema()
        self.__traverse_rules_dir()
        return self.rule_message

    def __load_schema(self):
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

    def __traverse_rules_dir(self):
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                filename = root[len(self.rules_dir):]
                if len(filename) > 0:
                    filename += "/"
                filename += file
                file_path = os.path.join(root, file)
                if (file.endswith('.yml') or file.endswith(
                        '.yaml')) and file != self.schema_file:
                    print(f'Loading yaml file: {file_path}...', end="")
                    with open(file_path, 'r') as f:
                        yaml_data = yaml.safe_load(f)
                    print(f' Validating...', end="")
                    validate(yaml_data, self.schema)
                    print(f' Processing...', end="")
                    self.__read_yaml(filename, yaml_data)
                    print(f' Done')
                if file.endswith('.data'):
                    print(f'Loading data file: {file_path}...', end="")
                    with open(file_path, 'r') as f:
                        data = f.read()
                    print(f' Processing...', end="")
                    self.__read_data(filename, data)
                    print(f' Done')
        rule_ids = list(self.rules.keys())
        rule_ids.sort()
        self.rules = {i: self.rules[i] for i in rule_ids}
        for rule in self.rules.values():
            new_rule = self.rule_message.static_rules.add()
            new_rule.id = rule["id"]
            new_rule.payload = rule["payload"]
            new_rule.match_type = rule["matchType"]
            new_rule.action = rule["action"]
            new_rule.filename = rule["filename"]
            for ph in rule["placeholders"]:
                new_rule.placeholders.append(ph)
            for tf in rule["transformations"]:
                new_rule.transformations.append(tf)
            if "tags" in rule:
                for tg in rule["tags"]:
                    new_rule.tags.append(tg)

    # Read yaml file to protobuf message
    def __read_yaml(self, filename, yaml_data):
        new_metadata = self.rule_message.metadata.add()
        new_metadata.filename = filename
        if "version" in yaml_data:
            new_metadata.version = yaml_data["version"]
        if "kind" in yaml_data:
            new_metadata.kind = yaml_data["kind"]
        for yaml_rule in yaml_data["rules"]:
            if yaml_rule["id"] in self.rules:
                print(
                    f"Error: [{filename}] rule id {yaml_rule['id']} is duplicated")
                sys.exit(1)
            self.rules[yaml_rule["id"]] = yaml_rule
            self.rules[yaml_rule["id"]]["filename"] = filename

    # Read data file to protobuf message
    def __read_data(self, filename, data):
        rule_data = self.rule_message.rule_data.add()
        rule_data.filename = filename
        rule_data.data = data


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python rule_serializer_v1.py <path_to_yaml_rules_dir>")
        sys.exit(1)

    rules_dir = sys.argv[1]
    if not os.path.isdir(rules_dir):
        print(f"Error: {rules_dir} is not a directory")
        print("Usage: python rule_serializer_v1.py <path_to_yaml_rules_dir>")
        sys.exit(1)

    rule_serializer = RuleSerializer(rules_dir)
    proto_data = rule_serializer.get_serialized_rules()
