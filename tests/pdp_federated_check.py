import unittest
import subprocess
import os
import requests
import json
import sys
sys.path.append('../src/')
import base64
import time
import traceback
import urllib
import logging
import datetime
from jwkest.jws import JWS
from jwkest.jwk import RSAKey, import_rsa_key_from_file, load_jwks_from_url, import_rsa_key
from jwkest.jwk import load_jwks
from Crypto.PublicKey import RSA
from WellKnownHandler import WellKnownHandler, TYPE_SCIM, TYPE_OIDC, KEY_SCIM_USER_ENDPOINT, KEY_OIDC_TOKEN_ENDPOINT, KEY_OIDC_REGISTRATION_ENDPOINT, KEY_OIDC_SUPPORTED_AUTH_METHODS_TOKEN_ENDPOINT, TYPE_UMA_V2, KEY_UMA_V2_PERMISSION_ENDPOINT
from eoepca_uma import rpt, resource
from policies.validator import validate_json
from policies import policies_operations
from xacml import parser, decision, forwarder, response_handler
from bson.objectid import ObjectId
from policy_storage import Policy_Storage
from utils import ClassEncoder
from models import response
from handlers.scim_handler import ScimHandler

class PDPFederatedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.g_config = {}
        with open("../src/config/config.json") as j:
            cls.g_config = json.load(j)

        wkh = WellKnownHandler(cls.g_config["auth_server_url"], secure=False)
        cls.__TOKEN_ENDPOINT = wkh.get(TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT)

        _rsajwk = RSAKey(kid="RSA1", key=import_rsa_key_from_file("../src/private.pem"))
        _payload = { 
                    "iss": cls.g_config["client_id"],
                    "sub": cls.g_config["client_id"],
                    "aud": cls.__TOKEN_ENDPOINT,
                    "user_name": "admin",
                    "jti": datetime.datetime.today().strftime('%Y%m%d%s'),
                    "exp": int(time.time())+3600,
                    "isOperator": False
                }
        _jws = JWS(_payload, alg="RS256")

        cls.jwt = _jws.sign_compact(keys=[_rsajwk])

        cls.scopes = 'protected_access'
        cls.PDP_HOST = "http://"+cls.g_config["host"]
        cls.PDP_PORT = cls.g_config["port"]
        cls.UID = cls.g_config["client_id"]
       
    def getJWT(self):
        return self.jwt

    def createTestFederatedPolicy(self, id_token="filler", resource_id="test_resource_0000", delegate="http://localhost:5567/policy/validate"):
        name = "Default Ownership Policy of " + str(resource_id)
        description = "This is the default ownership policy for created resources through PEP"
        policy_cfg = { "resource_id": str(resource_id), "action": "view", "delegate": str(delegate), "rules": [{ "AND": [ {"EQUAL": {"userName" : "admin" } }] }] }
        scopes = ["protected_access"]
        payload = {"name": name, "description": description, "config": policy_cfg, "scopes": scopes}
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+str(id_token) }
        pol = requests.post(self.PDP_HOST+":"+self.PDP_PORT+"/policy/", headers=headers, json=payload, verify=False)
        if pol.status_code == 200:
            return 200, pol.text.replace("New Policy with ID: ", "")
        return 500, None
    
    #This test case assumes v0.3 of the PDP engine
    def test_resource(self):
        #Use a JWT token as id_token
        id_token = self.getJWT()

        #Mock resource ID
        resource_id = "20248592"
        #Insert
        delegate = "http://localhost:6667/policy/validate"

        #Create default policy
        status, self.policyID = self.createTestFederatedPolicy(id_token, resource_id, delegate)
        self.assertEqual(status, 200)
        print("Create policy: Policy created with id: "+self.policyID)
        del status
        print("=======================")
        print("")
        
        with open('../tests/examples/request_template_delegation.json') as json_file:
            data = json.load(json_file)

        subject, action, resource = parser.load_request(data)

        resource_id = resource.attributes[0]['Value']
        action = action.attributes[0]['Value']

        dict_values = {}

        for i in range(0, len(subject.attributes)):
            dict_values[subject.attributes[i]['AttributeId']] = subject.attributes[i]['Value']

        print("Checking policy for delegation decision signature")
        j = policies_operations.validate_complete_policies(resource_id, action, dict_values)
        self.assertEqual(j[0][0], None)
        self.assertEqual(str(j[0][1]), delegate)
        del j
        print("=======================")
        print("")

if __name__ == '__main__':
    unittest.main()