from WellKnownHandler import WellKnownHandler, TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT
from eoepca_scim import EOEPCA_Scim, ENDPOINT_AUTH_CLIENT_POST
from requests import post
from base64 import b64encode

class ScimHandler:
   __instance__ = None
   __eoepca_scim_instance = None
   __scim_client = None
   __wkh = None
   __verify_ssl = None

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
    def registerScimClient(self, auth_server_url: str, client_id: str = None, client_secret: str = None, verify_ssl: bool = False):
        if not ScimHandler.__eoepca_scim_instance:
            ScimHandler.__eoepca_scim_instance = EOEPCA_Scim(host=auth_server_url, clientID=client_id, clientSecret=client_secret)
            if not client_id and not client_secret:
                ScimHandler.__scim_client = ScimHandler.__eoepca_scim_instance.registerClient("PDP Dynamic Client",
                                    grantTypes = ["client_credentials"],
                                    redirectURIs = [""],
                                    logoutURI = "", 
                                    responseTypes = ["code","token","id_token"],
                                    scopes = ['openid', 'uma_protection', 'permission'],
                                    token_endpoint_auth_method = ENDPOINT_AUTH_CLIENT_POST)
                print("SCIM Handler: created new PDP client: " + ScimHandler.__scim_client["client_id"] )
            else:
                ScimHandler.__scim_client = {"client_id": client_id, "client_secret": client_secret}
            ScimHandler.__wkh = WellKnownHandler(auth_server_url, secure=False)
            ScimHandler.__verify_ssl = verify_ssl
        return ScimHandler.__scim_client

    @staticmethod
    def get_pat(self):
        if not ScimHandler.__scim_client:
            raise Exception("SCIM Handler: Client not initialized! Please register new client first.")
        token_endpoint = self.wkh.get(TYPE_OIDC, KEY_OIDC_TOKEN_ENDPOINT)
        headers = {"content-type": "application/x-www-form-urlencoded", 'cache-control': "no-cache"}
        payload = ("grant_type=client_credentials&client_id="
                    +ScimHandler.__scim_client["client_id"]
                    +"&client_secret="
                    +ScimHandler.__scim_client["client_secret"]
                    +"&scope=openid%20uma_protection%20permission&redirect_uri=")
        response = post(token_endpoint, data=payload, headers=headers, verify = ScimHandler.__verify_ssl)
        try:
            access_token = response.json()["access_token"]
        except Exception as e:
            print("Error while getting access_token: "+str(response.text))
            exit(-1)
        
        return access_token
                    
