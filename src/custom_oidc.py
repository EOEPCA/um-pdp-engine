#!/usr/bin/env pythonfrom jwkest.jws import JWS
from base64 import b64encode
from WellKnownHandler import TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT, KEY_OIDC_USERINFO_ENDPOINT, TYPE_SCIM, KEY_SCIM_USER_ENDPOINT
from eoepca_scim import EOEPCA_Scim, ENDPOINT_AUTH_CLIENT_POST
from WellKnownHandler import WellKnownHandler
from requests import post, get
import logging
import base64
import json
from jwt_verification.signature_verification import JWT_Verification
from jwkest.jws import JWS
from jwkest.jwk import SYMKey, KEYS
from jwkest.jwk import RSAKey, import_rsa_key_from_file, load_jwks_from_url, import_rsa_key
from jwkest.jwk import load_jwks
from jwkest.jwk import rsa_load


class OIDCHandler:

    def __init__(self, server_url: str, client_id: str, client_secret: str, redirect_uri: str, scopes, verify_ssl: bool = False):
        self.client_id = client_id
        self.client_secret = client_secret
        self.verify_ssl = verify_ssl
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self.server_url=server_url
        self.wkh = WellKnownHandler(server_url, secure=False)

    def register_client(self):
        # Generate client dynamically if one is not configured.
        if not self.client_id or not self.client_secret:
            print ("NOTICE: Client not found, generating one... ")
            scim_client = EOEPCA_Scim(self.server_url)
            new_client = scim_client.registerClient("PDP Dynamic Client",
                                        grantTypes = ["client_credentials"],
                                        redirectURIs = [""],
                                        logoutURI = "", 
                                        responseTypes = ["code","token","id_token"],
                                        scopes = ['openid', 'uma_protection', 'permission'],
                                        token_endpoint_auth_method = ENDPOINT_AUTH_CLIENT_POST)
            print("NEW CLIENT created with ID '"+new_client["client_id"]+"', since no client config was found on config.json or environment")

            self.client_id = new_client["client_id"]
            self.client_secret = new_client["client_secret"]
            return self.client_id, self.client_secret


    def verify_JWT_token(self, token, key):
        try:
            header = str(token).split(".")[0]
            paddedHeader = header + '=' * (4 - len(header) % 4)
            decodedHeader = base64.b64decode(paddedHeader)
            #to remove byte-code
            decodedHeader_format = decodedHeader.decode('utf-8')
            decoded_str_header = json.loads(decodedHeader_format)

            payload = str(token).split(".")[1]
            paddedPayload = payload + '=' * (4 - len(payload) % 4)
            decoded = base64.b64decode(paddedPayload)
            #to remove byte-code
            decoded = decoded.decode('utf-8')
            decoded_str = json.loads(decoded)

            user_value = None
            if decoded_str.get(key):                   
                user_value = decoded_str[key]
            elif decoded_str.get("pct_claims"):      
                if decoded_str.get("pct_claims").get(key):
                    user_value = decoded_str['pct_claims'][key]
            if isinstance(user_value, list) and len(user_value) != 0 and user_value[0]:
                user_value = user_value[0]
            if user_value is None:
                raise Exception

            return user_value
        except Exception as e:
            print("Authenticated RPT Resource. No Valid JWT id token passed! " +str(e))
            return None



    def verify_OAuth_token(self, token):
        headers = { 'content-type': "application/json", 'Authorization' : 'Bearer '+token}
        msg = "Host unreachable"
        status = 401
        url = self.wkh.get(TYPE_OIDC, KEY_OIDC_USERINFO_ENDPOINT )
        try:
            res = get(url, headers=headers, verify=False)
            status = res.status_code
            msg = res.text
            user = (res.json())
            return user['sub']
        except:
            print("OIDC Handler: Get User Unique Identifier: Exception occured!")
            status = 500
            return status, {}


    def get_terms_from_JWT(self, token):
        try:
            header = str(token).split(".")[0]
            paddedHeader = header + '=' * (4 - len(header) % 4)
            decodedHeader = base64.b64decode(paddedHeader)
            #to remove byte-code
            decodedHeader_format = decodedHeader.decode('utf-8')
            decoded_str_header = json.loads(decodedHeader_format)

            payload = str(token).split(".")[1]
            paddedPayload = payload + '=' * (4 - len(payload) % 4)
            decoded = base64.b64decode(paddedPayload)
            #to remove byte-code
            decoded = decoded.decode('utf-8')
            decoded_str = json.loads(decoded)
            terms = None
            if decoded_str.get("TermsConditions"): 
                terms = decoded_str["TermsConditions"]
            else:
                raise Exception

            return terms
        except Exception as e:
            print("Authenticated RPT Resource. No Valid JWT id token passed! Terms&Conditions needed " +str(e))
            return None

    def get_terms_from_OAuth_token(self, token):
        headers = { 'content-type': "application/json", 'Authorization' : 'Bearer '+token}
        msg = "Host unreachable"
        status = 401
        url = self.wkh.get(TYPE_OIDC, KEY_OIDC_USERINFO_ENDPOINT )
        try:
            res = get(url, headers=headers, verify=False)
            status = res.status_code
            msg = res.text
            user = (res.json())
            return user['TermsConditions']
        except:
            print("OIDC Handler: Get User Unique Identifier: Exception occured!")
            status = 500
            return status, {}