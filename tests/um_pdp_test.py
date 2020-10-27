#!/usr/bin/env python3
import sys
sys.path.append('../src/')
import unittest
import mock
import json
import jsonschema
from policies.validator import validate_json
from policies import policies_operations
from xacml import parser, decision, forwarder, response_handler
from bson.objectid import ObjectId
from policy_storage import Policy_Storage
from utils import ClassEncoder
from models import response
from handlers.scim_handler import ScimHandler
import requests

def mocked_validate_policies(*args, **kwargs):
    class MockResponse:
        def __init__(self):
            if str(args[0]) == "20248583" and args[1] == "view" and args[2]['userName'] != "test":
                self.response = True
            elif str(args[0]) == "20248583" and args[1] == "view" and args[2]['userName'] == "test":
                self.response = False
            elif str(args[0]) == "20248583" and args[1] == "edit" and args[2]['userName'] == "test":
                self.response = False
            elif str(args[0]) == "20248583" and args[1] == "edit" and args[2]['userName'] == "test":
                self.response = False
            elif str(args[0]) == "173":
                self.response = False
            elif str(args[0]) == "123456" and args[1] == "view" and args[2]['attemps'] != 5:
                self.response = False
            elif str(args[0]) == "123456" and args[1] == "view" and args[2]['attemps'] == 5:
                self.response = True
        def response(self):
            return self.response
    return MockResponse().response

def mocked_validate_policies_decisions(*args, **kwargs):
    class MockResponse:
        def __init__(self):
            if str(args[0]) == "6666666" and args[1] == "view" and args[2] == "delegate" and args[3]['userName'] == "test" and args[3]['timezone'] == "Europe/Lisbon":
                self.response = {0:[None, "http://localhost:5568/policy/validate"]}
            else:
                self.response = {1:[True, None]}
        def response(self):
            return self.response
    return MockResponse().response

def mocked_final_response(*args, **kwargs):
    class MockResponse:
        def __init__(self):
            if args[0] == {0: [None, "http://localhost:5568/policy/validate"]} and type(args[1]) == list and type(args[2]) == list and type(args[3]) == list and type(args[4]) == str:
                r = response.Response(decision.PERMIT)
                status = 200
                self.response = json.dumps(r, cls=ClassEncoder), status
            else:
                r = response.Response(decision.DENY, "fail_to_permit", "obligation-id", "You cannot access this resource")
                status = 401
                self.response = json.dumps(r, cls=ClassEncoder), status
        def response(self):
            return self.response
    return MockResponse().response

def mocked_request_policy(*args, **kwargs):
    class MockResponse:
        def __init__(self):
                subject, action, resource = parser.load_request(kwargs.get('json'))

                resource_id = resource.attributes[0]['Value']

                if resource_id == "20248583":
                    r = response.Response(decision.PERMIT)
                    status = 200
                    self.response = json.dumps(r, cls=ClassEncoder), status
                elif resource_id == "202485839":
                    r = response.Response(decision.DENY, "fail_to_permit", "obligation-id", "You cannot access this resource")
                    status = 401
                    self.response = json.dumps(r, cls=ClassEncoder), status
        def response(self):
                return self.response
    return MockResponse().response

def mocked_modify_auth_server(*args, **kwargs):
    class MockResponse:
        def __init__(self):
                if str(args[0]) == "https://test.10.0.2.15.nip.io":
                    self.response = True
                elif str(args[0]) == "https://test.eoepca.io":
                    self.response = False
        def response(self):
                return self.response
    return MockResponse().response

class TestPDP(unittest.TestCase):
    def test_pdp_parse_request_xacml(self):
        with open('../tests/examples/request_template.json') as json_file:
            data = json.load(json_file)

        subject, action, resource = parser.load_request(data)

        resource_id = resource.attributes[0]['Value']
        user_name = subject.attributes[0]['Value']

        self.assertEqual(isinstance(resource_id, str), True, "Resource id should be a string")
        self.assertEqual(isinstance(user_name, str), True, "User name should be a string")

    def test_pdp_parse_request_xacml_multiple_resources(self):
        with open('../tests/examples/request_template.json') as json_file:
            data = json.load(json_file)

        data["Request"]["Resource"].append({"Attribute":[{"AttributeId":"resource-id","Value":"20248583","DataType":"string","IncludeInResult":"True"}]})
        subject, action, resource = parser.load_request(data)

        resource_id = resource.attributes[0]['Value']
        user_name = subject.attributes[0]['Value']

        self.assertEqual(isinstance(resource_id, list), True, "Resource id should be a list")
        self.assertEqual(isinstance(user_name, str), True, "User name should be a string")

    @mock.patch('policies.policies_operations.validate_complete_policies', side_effect=mocked_validate_policies)
    def test_pdp_validate_access_policies_true(self, mock_access_policies_true,raise_for_status=None):
        with open('../tests/examples/request_template.json') as json_file:
            data = json.load(json_file)

        subject, action, resource = parser.load_request(data)

        resource_id = resource.attributes[0]['Value']
        action = action.attributes[0]['Value']
        dict_values = {}

        for i in range(0, len(subject.attributes)):
            dict_values[subject.attributes[i]['AttributeId']] = subject.attributes[i]['Value']

        mock_resp = mock.Mock()
        mock_resp.raise_for_status = mock.Mock()
        if raise_for_status:
            mock_resp.raise_for_status.side_effect = raise_for_status

        j = policies_operations.validate_complete_policies(resource_id, action, dict_values)

        self.assertEqual(j, True, "Validate access policies 1 should be true")

    @mock.patch('policies.policies_operations.validate_complete_policies', side_effect=mocked_validate_policies)
    def test_pdp_validate_access_policies_resourceid_false(self, mock_access_policies_resourceid_false,raise_for_status=None):
        with open('../tests/examples/request_template.json') as json_file:
            data = json.load(json_file)

        subject, action, resource = parser.load_request(data)

        resource_id = "173"
        action = action.attributes[0]['Value']
        dict_values = {}

        for i in range(0, len(subject.attributes)):
            dict_values[subject.attributes[i]['AttributeId']] = subject.attributes[i]['Value']

        mock_resp = mock.Mock()
        mock_resp.raise_for_status = mock.Mock()
        if raise_for_status:
            mock_resp.raise_for_status.side_effect = raise_for_status

        j = policies_operations.validate_complete_policies(resource_id, action, dict_values)

        self.assertEqual(j, False, "Validate access policies 2 should be false")

    @mock.patch('policies.policies_operations.validate_complete_policies', side_effect=mocked_validate_policies)
    def test_pdp_validate_access_policies_resourceid_true_user_name_false(self, mock_access_policies_resourceid_true_user_name_false,raise_for_status=None):
        with open('../tests/examples/request_template.json') as json_file:
            data = json.load(json_file)

        subject, action, resource = parser.load_request(data)

        resource_id = resource.attributes[0]['Value']
        action = action.attributes[0]['Value']
        dict_values = {}

        for i in range(0, len(subject.attributes)):
            dict_values[subject.attributes[i]['AttributeId']] = subject.attributes[i]['Value']
        
        dict_values['userName'] = "test"

        mock_resp = mock.Mock()
        mock_resp.raise_for_status = mock.Mock()
        if raise_for_status:
            mock_resp.raise_for_status.side_effect = raise_for_status

        j = policies_operations.validate_complete_policies(resource_id, action, dict_values)

        self.assertEqual(j, False, "Validate access policies 3 should be false")

    @mock.patch('policies.policies_operations.validate_complete_policies', side_effect=mocked_validate_policies)
    def test_pdp_validate_access_policies_action_false(self, mock_access_policies_resourceid_true_user_name_false,raise_for_status=None):
        with open('../tests/examples/request_template.json') as json_file:
            data = json.load(json_file)

        subject, action, resource = parser.load_request(data)

        resource_id = resource.attributes[0]['Value']
        action = "edit"
        dict_values = {}

        for i in range(0, len(subject.attributes)):
            dict_values[subject.attributes[i]['AttributeId']] = subject.attributes[i]['Value']
        
        dict_values['userName'] = "test"

        mock_resp = mock.Mock()
        mock_resp.raise_for_status = mock.Mock()
        if raise_for_status:
            mock_resp.raise_for_status.side_effect = raise_for_status

        j = policies_operations.validate_complete_policies(resource_id, action, dict_values)

        self.assertEqual(j, False, "Validate access policies 3 should be false")

    @mock.patch('requests.get', side_effect=mocked_request_policy)
    def test_pdp_validate_schema_permit(self, mock_schema_permit, raise_for_status=None):
        with open('../tests/examples/request_template.json') as json_file:
            data = json.load(json_file)
        
        headers = {'Accept': 'application/json'}

        r = requests.get('http://0.0.0.0:5567/policy/validate', headers=headers, json=data)
        if isinstance(r, tuple):
            result = r[0]
            result = json.loads(result)
        else: 
            result = r.json()

        # Validate XACML JSON response against schema
        with open("../src/standards/response.schema.json", "r") as f:
            schema = json.load(f)
        validation = jsonschema.validate(result, schema)
        
        self.assertEqual(validation, None, "Schema validation should return None for the response to be a valid JSON XACML")

    @mock.patch('requests.get', side_effect=mocked_request_policy)
    def test_pdp_validate_schema_deny(self,  mock_schema_deny, raise_for_status=None):
        with open('../tests/examples/request_template.json') as json_file:
            data = json.load(json_file)

        headers = {'Accept': 'application/json'}

        data["Request"]["Resource"][0]["Attribute"][0]["Value"] = "202485839"

        r = requests.get('http://0.0.0.0:5567/policy/validate', headers=headers, json=data)
        if isinstance(r, tuple):
            result = r[0]
            result = json.loads(result)
        else: 
            result = r.json()

        self.assertEqual(result, {'Response': [{'Decision': 'Deny', 'Status': {'StatusCode': {'Value': 'urn:oasis:names:tc:xacml:1.0:status:ok'}}, 'Obligations': [{'Id': 'fail_to_permit', 'AttributeAssignment': [{'AttributeId': 'obligation-id', 'Value': 'You cannot access this resource', 'DataType': 'http://www.w3.org/2001/XMLSchema#string'}]}]}]}, "Valid Deny Schema")

    @mock.patch('policies.policies_operations.validate_complete_policies', side_effect=mocked_validate_policies)
    def test_pdp_validate_rule_with_conditions_false(self, mock_validate_rule_with_conditions_false, raise_for_status=None):
        with open('../tests/examples/request_template.json') as json_file:
            data = json.load(json_file)

        subject, action, resource = parser.load_request(data)

        resource_id = "123456"
        action = action.attributes[0]['Value']
        dict_values = {}

        for i in range(0, len(subject.attributes)):
            dict_values[subject.attributes[i]['AttributeId']] = subject.attributes[i]['Value']

        mock_resp = mock.Mock()
        mock_resp.raise_for_status = mock.Mock()
        if raise_for_status:
            mock_resp.raise_for_status.side_effect = raise_for_status

        j = policies_operations.validate_complete_policies(resource_id, action, dict_values)

        self.assertEqual(j, False, "Validate conditional policy rule should be false")

    @mock.patch('policies.policies_operations.validate_complete_policies', side_effect=mocked_validate_policies)
    def test_pdp_validate_rule_with_conditions_true(self, mock_validate_rule_with_conditions_true, raise_for_status=None):
        with open('../tests/examples/request_template.json') as json_file:
            data = json.load(json_file)

        subject, action, resource = parser.load_request(data)

        resource_id = "123456"
        action = action.attributes[0]['Value']
        dict_values = {}

        for i in range(0, len(subject.attributes)):
            dict_values[subject.attributes[i]['AttributeId']] = subject.attributes[i]['Value']

        dict_values['attemps'] = 5

        mock_resp = mock.Mock()
        mock_resp.raise_for_status = mock.Mock()
        if raise_for_status:
            mock_resp.raise_for_status.side_effect = raise_for_status

        j = policies_operations.validate_complete_policies(resource_id, action, dict_values)

        self.assertEqual(j, True, "Validate conditional policy rule should be true")

    @mock.patch('policies.policies_operations.validate_complete_policies', side_effect=mocked_validate_policies_decisions)
    def test_pdp_validate_delegation_policies(self, mock_validate_rule_with_conditions_false, raise_for_status=None):
        with open('../tests/examples/request_template_delegation.json') as json_file:
            data = json.load(json_file)

        subject, action_rsrc, resource = parser.load_request(data)

        resource_id = resource.attributes[0]['Value']
        action = action_rsrc.attributes[0]['Value']
        dict_values = {}

        for i in range(0, len(subject.attributes)):
            dict_values[subject.attributes[i]['AttributeId']] = subject.attributes[i]['Value']

        mock_resp = mock.Mock()
        mock_resp.raise_for_status = mock.Mock()
        if raise_for_status:
            mock_resp.raise_for_status.side_effect = raise_for_status

        decisions = policies_operations.validate_complete_policies(resource_id, action, dict_values)

        self.assertEqual(type(decisions), dict, "Should return a dictionary with the result decisions")

    @mock.patch('xacml.response_handler.generate_response', side_effect=mocked_final_response)
    def test_pdp_delegation_forwarder_final_response(self, mock_validate_rule_with_conditions_false, raise_for_status=None):
        with open('../tests/examples/request_template_delegation.json') as json_file:
            data = json.load(json_file)

        subject, action_rsrc, resource = parser.load_request(data)

        resource_id = resource.attributes[0]['Value']
        action = action_rsrc.attributes[0]['Value']
        dict_values = {}

        decision = {
            0: [None, "http://localhost:5568/policy/validate"]
        }

        for i in range(0, len(subject.attributes)):
            dict_values[subject.attributes[i]['AttributeId']] = subject.attributes[i]['Value']

        mock_resp = mock.Mock()
        mock_resp.raise_for_status = mock.Mock()
        if raise_for_status:
            mock_resp.raise_for_status.side_effect = raise_for_status

        resp, status = response_handler.generate_response(decision, subject.attributes, action_rsrc.attributes, resource.attributes, "http://localhost:5567/policy/validate")

        self.assertEqual(status, 200, "Request was successfully forwarded to external pdp")

    @mock.patch('handlers.scim_handler.ScimHandler.modifyAuthServerUrl', side_effect=mocked_modify_auth_server)
    def test_pdp_validate_valid_issuer(self, mock_validate_valid_issuer, raise_for_status=None):
        with open('../tests/examples/request_template_issuer.json') as json_file:
            data = json.load(json_file)

        subject, action, resource = parser.load_request(data)

        issuer = subject.attributes[0]['Issuer']

        mock_resp = mock.Mock()
        mock_resp.raise_for_status = mock.Mock()
        if raise_for_status:
            mock_resp.raise_for_status.side_effect = raise_for_status

        handler_status_issuer = ScimHandler.get_instance().modifyAuthServerUrl(issuer)

        self.assertEqual(handler_status_issuer, True, "Validate issuer should be true")

    @mock.patch('handlers.scim_handler.ScimHandler.modifyAuthServerUrl', side_effect=mocked_modify_auth_server)
    def test_pdp_validate_invalid_issuer(self, mock_validate_invalid_issuer, raise_for_status=None):
        with open('../tests/examples/request_template_issuer.json') as json_file:
            data = json.load(json_file)

        subject, action, resource = parser.load_request(data)

        subject.attributes[0]['Issuer'] = "https://test.eoepca.io"

        mock_resp = mock.Mock()
        mock_resp.raise_for_status = mock.Mock()
        if raise_for_status:
            mock_resp.raise_for_status.side_effect = raise_for_status

        handler_status_issuer = ScimHandler.get_instance().modifyAuthServerUrl(subject.attributes[0]['Issuer'])

        self.assertEqual(handler_status_issuer, False, "Validate issuer should be false")


if __name__ == '__main__':
    unittest.main()
