import unittest
import subprocess
import os
import requests
import json
import sys
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

class PDPResourceTest(unittest.TestCase):
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

    def createTestPolicy(self, id_token="filler", resource_id="test_resource_0000"):
        name = "Default Ownership Policy of " + str(resource_id)
        description = "This is the default ownership policy for created resources through PEP"
        policy_cfg = { "resource_id": str(resource_id), "action": "view", "rules": [{ "AND": [ {"EQUAL": {"id" : self.UID } }] }] }
        scopes = ["protected_access"]
        payload = {"name": name, "description": description, "config": policy_cfg, "scopes": scopes}
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+str(id_token) }
        pol = requests.post(self.PDP_HOST+":"+self.PDP_PORT+"/policy/", headers=headers, json=payload, verify=False)
        if pol.status_code == 200:
            return 200, pol.text.replace("New Policy with ID: ", "")
        return 500, None

    def getPolicy(self, id_token="filler"):
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+id_token }
        res = requests.get(self.PDP_HOST+":"+self.PDP_PORT+"/policy/"+self.policyID, headers=headers, verify=False)
        if res.status_code == 401:
            return 401, res.headers["Error"]
        if res.status_code == 200:
            return 200, res.json()
        if res.status_code == 404:
            return 404, res.headers["Error"]
        return 500, None

    def deletePolicy(self, id_token="filler"):
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+id_token }
        res = requests.delete(self.PDP_HOST+":"+self.PDP_PORT+"/policy/"+self.policyID, headers=headers, verify=False)
        if res.status_code == 401:
            return 401, res.headers["Error"]
        if res.status_code == 204:
            return 204, None
        return 500, None

    def updatePolicy(self, id_token="filler", resource_id=""):
        headers = { 'content-type': "application/json", "cache-control": "no-cache", "Authorization": "Bearer "+id_token }
        name = "Default Ownership Policy of " + str(resource_id)
        description = "MODIFIED"
        policy_cfg = { "resource_id": str(resource_id), "action": "view", "rules": [{ "OR": [ {"EQUAL": {"id" : self.UID } }, {"EQUAL": {"user_name" : "admin"} }] }] }
        scopes = ["protected_access"]
        payload = {"name": name, "description": description, "config": policy_cfg, "scopes": scopes}
        res = requests.put(self.PDP_HOST+":"+self.PDP_PORT+"/policy/"+self.policyID, headers=headers, json=payload, verify=False)
        if res.status_code == 401:
            return 401, res.headers["Error"]
        if res.status_code == 200:
            return 200, None
        return 500, None

    #This test case assumes v0.3 of the PDP engine
    def test_resource(self):
        #Use a JWT token as id_token
        id_token = self.getJWT()

        #Mock resource ID
        resource_id = "test_resource_id_0001"

        #Create default policy
        status, self.policyID = self.createTestPolicy(id_token, resource_id)
        self.assertEqual(status, 200)
        print("Create policy: Policy created with id: "+self.policyID)
        del status
        print("=======================")
        print("")

        #Get created policy
        status, reply = self.getPolicy(id_token)
        self.assertEqual(status, 200)
        #And we check if the returned id matches the id we got on creation
        #The reply message is in JSON format
        self.assertEqual(reply["_id"], self.policyID)
        print("Get policy: Policy found.")
        print(reply)
        del status, reply
        print("=======================")
        print("")
        
        #Modify created policy
        #Changes description to "MODIFIED" and adds user "admin" as ownership
        status, _ = self.updatePolicy(id_token, resource_id)
        self.assertEqual(status, 200)
        #Get policy to check if modification actually was successfull
        status, reply = self.getPolicy(id_token)
        self.assertEqual(reply["_id"], self.policyID)
        self.assertEqual(reply["description"], "MODIFIED")
        print("Update policy: Policy properly modified, ownership changed")
        print(reply)
        del status, reply
        print("=======================")
        print("")

        # Delete created policy
        status, reply = self.deletePolicy(id_token)
        self.assertEqual(status, 204)
        del status, reply

        #Get policy to make sure it was deleted
        status, _ = self.getPolicy(id_token)
        self.assertEqual(status, 401)
        print("Delete policy: Policy deleted.")
        del status
        print("=======================")
        print("")

if __name__ == '__main__':
    unittest.main()