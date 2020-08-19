#!/usr/bin/env python3
import unittest
import json
import jsonschema
from policies.policies import validate_json
from policies import policies_operations
from xacml import parser
from bson.objectid import ObjectId
from policy_storage import Policy_Storage
from utils import ClassEncoder
import requests

class TestPDP(unittest.TestCase):
    def test_pdp_parse_request_xacml(self):
        with open('standards/request_template.json') as json_file:
            data = json.load(json_file)

        subject, action, resource = parser.load_request(data)

        resource_id = resource.attributes[0]['Value']
        user_name = subject.attributes[0]['Value']

        self.assertEqual(isinstance(resource_id, str), True, "Resource id should be a string")
        self.assertEqual(isinstance(user_name, str), True, "User name should be a string")

    def test_pdp_parse_request_xacml_multiple_resources(self):
        with open('standards/request_template.json') as json_file:
            data = json.load(json_file)

        data["Request"]["Resource"].append({"Attribute":[{"AttributeId":"resource-id","Value":"20248583","DataType":"string","IncludeInResult":"True"}]})
        subject, action, resource = parser.load_request(data)

        resource_id = resource.attributes[0]['Value']
        user_name = subject.attributes[0]['Value']

        self.assertEqual(isinstance(resource_id, list), True, "Resource id should be a list")
        self.assertEqual(isinstance(user_name, str), True, "User name should be a string")

    def test_pdp_validate_access_policies_true(self):
        self.assertEqual(policies_operations.validate_access_policies("20248583", "admin"), True, "Validate access policies 1 should be true")

    def test_pdp_validate_access_policies_resourceid_false(self):
        self.assertEqual(policies_operations.validate_access_policies("202485839", "admin"), False, "Validate access policies 2 should be false")

    def test_pdp_validate_access_policies_resourceid_true_user_name_false(self):
        self.assertEqual(policies_operations.validate_access_policies("20248583", "test"), False, "Validate access policies 3 should be false")

    def test_pdp_validate_schema_permit(self):
        with open('standards/request_template.json') as json_file:
            data = json.load(json_file)
        
        headers = {'Accept': 'application/json'}

        r = requests.get('http://0.0.0.0:5567/policy/validate', headers=headers, json=data)
        result = r.json()

        # Validate XACML JSON response against schema
        with open("standards/response.schema.json", "r") as f:
            schema = json.load(f)
        validation = jsonschema.validate(result, schema)
        
        self.assertEqual(validation, None, "Schema validation should return None for the response to be a valid JSON XACML")

    def test_pdp_validate_schema_deny(self):
        with open('standards/request_template.json') as json_file:
            data = json.load(json_file)

        headers = {'Accept': 'application/json'}

        data["Request"]["Resource"][0]["Attribute"][0]["Value"] = "202485839"

        r = requests.get('http://0.0.0.0:5567/policy/validate', headers=headers, json=data)
        result = r.json()

        # Validate XACML JSON response against schema
        with open("standards/response.schema.json", "r") as f:
            schema = json.load(f)
        validation = jsonschema.validate(result, schema)
        
        self.assertEqual(validation, None, "Schema validation should return None for the response to be a valid JSON XACML")

    def test_pdp_validate_all_functionality_permit(self):
        with open('standards/request_template.json') as json_file:
            data = json.load(json_file)
        
        headers = {'Accept': 'application/json'}

        r = requests.get('http://0.0.0.0:5567/policy/validate', headers=headers, json=data)
        result = r.json()

        self.assertEqual(result['Response'][0]['Decision'], "Permit", "This flow should be a decision Permit")

    def test_pdp_validate_all_functionality_deny(self):
        with open('standards/request_template.json') as json_file:
            data = json.load(json_file)

        headers = {'Accept': 'application/json'}

        data["Request"]["Resource"][0]["Attribute"][0]["Value"] = "202485839"

        r = requests.get('http://0.0.0.0:5567/policy/validate', headers=headers, json=data)
        result = r.json()

        self.assertEqual(result['Response'][0]['Decision'], "Deny", "This flow should be a decision Deny")

if __name__ == '__main__':
    unittest.main()
