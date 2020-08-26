#!/usr/bin/env python3
import unittest
import json
from policies.policies import validate_json
from policies import policies_operations
from xacml import parser
from bson.objectid import ObjectId
from policy_storage import Policy_Storage
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
        with open('standards/request_template.json') as json_file:
            data = json.load(json_file)

        subject, action, resource = parser.load_request(data)

        resource_id = resource.attributes[0]['Value']
        dict_values = {}

        for i in range(0, len(subject.attributes)):
            dict_values[subject.attributes[i]['AttributeId']] = subject.attributes[i]['Value']

        self.assertEqual(policies_operations.validate_complete_policies(resource_id, dict_values), True, "Validate access policies 1 should be true")

    def test_pdp_validate_access_policies_resourceid_false(self):
        with open('standards/request_template.json') as json_file:
            data = json.load(json_file)

        subject, action, resource = parser.load_request(data)

        resource_id = "173"
        dict_values = {}

        for i in range(0, len(subject.attributes)):
            dict_values[subject.attributes[i]['AttributeId']] = subject.attributes[i]['Value']

        self.assertEqual(policies_operations.validate_complete_policies(resource_id, dict_values), False, "Validate access policies 2 should be false")

    def test_pdp_validate_access_policies_resourceid_true_user_name_false(self):
        with open('standards/request_template.json') as json_file:
            data = json.load(json_file)

        subject, action, resource = parser.load_request(data)

        resource_id = resource.attributes[0]['Value']
        dict_values = {}

        for i in range(0, len(subject.attributes)):
            dict_values[subject.attributes[i]['AttributeId']] = subject.attributes[i]['Value']
        
        dict_values['user_name'] = "test"

        self.assertEqual(policies_operations.validate_complete_policies(resource_id, dict_values), False, "Validate access policies 3 should be false")

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

    def test_pdp_policy_rule_with_conditions_false(self):
        with open('standards/request_template.json') as json_file:
            data = json.load(json_file)

        subject, action, resource = parser.load_request(data)

        resource_id = "123456"
        dict_values = {}

        for i in range(0, len(subject.attributes)):
            dict_values[subject.attributes[i]['AttributeId']] = subject.attributes[i]['Value']

        self.assertEqual(policies_operations.validate_complete_policies(resource_id, dict_values), False, "Validate conditional policy rule should be false")

    def test_pdp_policy_rule_with_conditions_true(self):
        with open('standards/request_template.json') as json_file:
            data = json.load(json_file)

        subject, action, resource = parser.load_request(data)

        resource_id = "123456"
        dict_values = {}

        for i in range(0, len(subject.attributes)):
            dict_values[subject.attributes[i]['AttributeId']] = subject.attributes[i]['Value']

        dict_values['attemps'] = 5

        self.assertEqual(policies_operations.validate_complete_policies(resource_id, dict_values), True, "Validate conditional policy rule should be true")

if __name__ == '__main__':
    unittest.main()
