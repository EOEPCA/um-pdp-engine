#!/usr/bin/env python3

from base64 import b64encode
from WellKnownHandler import TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT, KEY_OIDC_USERINFO_ENDPOINT, TYPE_SCIM, KEY_SCIM_USER_ENDPOINT
from eoepca_scim import EOEPCA_Scim, ENDPOINT_AUTH_CLIENT_POST
from WellKnownHandler import WellKnownHandler
from requests import post, get
import logging
import base64
import json

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


    def verify_jwt_token(self, token):
        try:
            payload = str(token).split(".")[1]
            padded_payload = payload + '=' * (4 - len(payload) % 4)
            decoded = base64.b64decode(padded_payload)
            user_inum = json.loads(decoded)["sub"]
            return user_inum
        except:
            print("Authenticated RPT Policy. No Valid JWT id token passed!")
            return None

    def verify_oauth_token(self, token):
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
            print("Invalid OAuth token!")
            return None


