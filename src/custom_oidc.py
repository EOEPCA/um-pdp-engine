#!/usr/bin/env python3

from base64 import b64encode
from WellKnownHandler import TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT
from eoepca_scim import EOEPCA_Scim, ENDPOINT_AUTH_CLIENT_POST

from requests import post

class OIDCHandler:

    def __init__(self, server_url: str, client_id: str, client_secret: str, redirect_uri: str, scopes, verify_ssl: bool = False):
        self.client_id = client_id
        self.client_secret = client_secret
        self.verify_ssl = verify_ssl
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self.wkh = wkh
        g_wkh = WellKnownHandler(server_url, secure=False)

    def register_client(self):
        # Generate client dynamically if one is not configured.
        if not client_id or not client_secret:
            print ("NOTICE: Client not found, generating one... ")
            scim_client = EOEPCA_Scim(g_config["auth_server_url"])
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

    def get_new_pat(self):
        """
        Returns a new PAT
        """
        token_endpoint = self.wkh.get(TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT)
        headers = {"content-type": "application/x-www-form-urlencoded", 'cache-control': "no-cache"}
        payload = "grant_type=client_credentials&client_id="+self.client_id+"&client_secret="+self.client_secret+"&scope="+" ".join(self.scopes).replace(" ","%20")+"&redirect_uri="+self.redirect_uri
        response = post(token_endpoint, data=payload, headers=headers, verify = self.verify_ssl)
        
        try:
            access_token = response.json()["access_token"]
        except Exception as e:
            print("Error while getting access_token: "+str(response.text))
            exit(-1)
        
        return access_token
            
