#!/usr/bin/env python3

from base64 import b64encode
from WellKnownHandler import TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT
from eoepca_scim import EOEPCA_Scim, ENDPOINT_AUTH_CLIENT_POST
from WellKnownHandler import WellKnownHandler
from requests import post
import logging

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
            print(self.client_id)
            print(self.client_secret)
            return self.client_id, self.client_secret

    def verify_OAuth_token(self, token):
        headers = { 'content-type': "application/x-www-form-urlencoded", 'Authorization' : 'Bearer '+token}
        msg = "Host unreachable"
        status = 401
        print('ehh')
        url = self.wkh.get(TYPE_SCIM, KEY_SCIM_USER_ENDPOINT)
        try:
            logging.info("verifying!")
            print('verifying')
            print(url)
            res = requests.get(url, headers=headers, verify=False)
            status = res.status_code
            msg = res.text
            logging.info(msg)
            print(msg)
            print("SCIM Handler: Get User attributes reply code: " + str(status))
            user = (res.json())
            return status, user
        except:
            print("SCIM Handler: Get User attributes: Exception occured!")
            print(traceback.format_exc())
            status = 500
            return status, {}


