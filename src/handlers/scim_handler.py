from WellKnownHandler import WellKnownHandler, TYPE_OIDC, TYPE_SCIM, KEY_OIDC_TOKEN_ENDPOINT, KEY_SCIM_USER_ENDPOINT, KEY_OIDC_USERINFO_ENDPOINT, KEY_OIDC_CLIENTINFO_ENDPOINT
from eoepca_scim import EOEPCA_Scim, ENDPOINT_AUTH_CLIENT_PRIVATE_KEY_JWT
from requests import post, get
import base64
from jwkest.jws import JWS
from jwkest.jwk import RSAKey, import_rsa_key_from_file, load_jwks_from_url, import_rsa_key
from jwkest.jwk import load_jwks
from Crypto.PublicKey import RSA
import datetime
import time
import logging
import os.path

class ScimHandler:
    __instance__ = None
    __eoepca_scim_instance = None
    __scim_client = None
    __wkh = None
    __verify_ssl = None
    logging.getLogger().setLevel(logging.INFO)

    def __init__(self):
       """ Constructor.
       """
       if ScimHandler.__instance__ is None:
           ScimHandler.__instance__ = self
       else:
           raise Exception("SCIM Handler: You cannot create another ScimHandler class")

    @staticmethod
    def get_instance():
       """ Static method to fetch the current instance.
       """
       if not ScimHandler.__instance__:
           ScimHandler()
       return ScimHandler.__instance__

    @staticmethod
    def registerScimClient(auth_server_url: str, client_id: str = None, client_secret: str = None, verify_ssl: bool = False):
        if not ScimHandler.__eoepca_scim_instance:
            if(os.path.isfile('./private.pem')):
                print("SCIM Handler: private key found, initiating...")
                ScimHandler.__eoepca_scim_instance = EOEPCA_Scim(host=auth_server_url, clientID=client_id, clientSecret=client_secret, jks_path="./private.pem")
            else:
                ScimHandler.__eoepca_scim_instance = EOEPCA_Scim(host=auth_server_url, clientID=client_id, clientSecret=client_secret)
            if not client_id or not client_secret:
                grantTypes = ["client_credentials", "urn:ietf:params:oauth:grant-type:uma-ticket", "password", "implicit"]
                scopes = ["openid", "oxd", "uma_protection", "permission"]
                ScimHandler.__scim_client = ScimHandler.__eoepca_scim_instance.registerClient("PDP Dynamic Client", grantTypes = grantTypes, redirectURIs = [""], logoutURI = "", responseTypes = ["code","token","id_token"], scopes = scopes, token_endpoint_auth_method = ENDPOINT_AUTH_CLIENT_PRIVATE_KEY_JWT, useJWT=1)
                print("SCIM Handler: created new PDP client: " + ScimHandler.__scim_client["client_id"] )
            else:
                ScimHandler.__scim_client = {"client_id": client_id, "client_secret": client_secret}
            ScimHandler.__wkh = WellKnownHandler(auth_server_url, secure=False)
            ScimHandler.__verify_ssl = verify_ssl
        return ScimHandler.__scim_client
    
    def getUserAttributes(self, userId: str):
        print("SCIM Handler: Get User attributes for user " + str(userId))
        if not ScimHandler.__scim_client:
            raise Exception("SCIM Handler: Client not initialized! Please register new client first.")
        # headers = { 'content-type': "application/x-www-form-urlencoded", 'Authorization' : 'Bearer '+ScimHandler.__getRPT(userId)}
        # msg = "Host unreachable"
        # status = 404
        # query = "userName eq \"" + userId +"\""
        # payload = { 'filter' : query }
        # url = ScimHandler.__wkh.get(TYPE_SCIM, KEY_SCIM_USER_ENDPOINT)
        try:
            #data = ScimHandler.__eoepca_scim_instance.getUserAttributes(userId)
            return 200, ScimHandler.__eoepca_scim_instance.getUserAttributes(userId)
            # res = get(url, headers=headers, params=payload, verify=False)
            # status = res.status_code
            # msg = res.text
            # print("SCIM Handler: Get User attributes reply code: " + str(status))
            # user = (res.json())['Resources']
            # self.authRetries = 3
            # return status, user[0]
        except Exception as e:
            print("SCIM Handler: Get User attributes: Exception occured!")
            print(str(e))
            status = 500
            return status, {}

    def __getRPT(userId):
        headers = { 'content-type': "application/x-www-form-urlencoded", 'Authorization' : 'Bearer '}
        query = "userName eq \"" + userId +"\""
        payload = { 'filter' : query }
        url = ScimHandler.__wkh.get(TYPE_SCIM, KEY_SCIM_USER_ENDPOINT)
        res = get(url, headers=headers, params=payload, verify=False)
        ticket = res.headers["WWW-Authenticate"].split("ticket=")[1]
        headers = { 'content-type': "application/x-www-form-urlencoded", 'cache-control': "no-cache" }
        _rsajwk = RSAKey(kid="RSA1", key=import_rsa_key_from_file("private.pem"))
        _payload = { 
                    "iss": ScimHandler.__scim_client["client_id"],
                    "sub": ScimHandler.__scim_client["client_id"],
                    "aud": ScimHandler.__wkh.get(TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT),
                    "jti": datetime.datetime.today().strftime('%Y%m%d%s'),
                    "exp": int(time.time())+3600
                }
        _jws = JWS(_payload, alg="RS256")
        jwt = _jws.sign_compact(keys=[_rsajwk])
        print(jwt)
        payload = {'grant_type' : "urn:ietf:params:oauth:grant-type:uma-ticket", 'client_id' : ScimHandler.__scim_client["client_id"], 'client_assertion_type': "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", 'ticket': ticket, 'client_assertion': jwt }
        res = post(ScimHandler.__wkh.get(TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT), data=payload, headers=headers, verify=False)
        rpt = res.json()["access_token"]
        print("RPT" + str(rpt))
        return rpt