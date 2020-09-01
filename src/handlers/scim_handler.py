from WellKnownHandler import WellKnownHandler, TYPE_OIDC, TYPE_SCIM, KEY_OIDC_TOKEN_ENDPOINT, KEY_SCIM_USER_ENDPOINT, KEY_OIDC_USERINFO_ENDPOINT, KEY_OIDC_CLIENTINFO_ENDPOINT
from eoepca_scim import EOEPCA_Scim, ENDPOINT_AUTH_CLIENT_PRIVATE_KEY_JWT
from requests import post, get
import base64
import os.path

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
    def registerScimClient(auth_server_url: str, client_id: str = None, client_secret: str = None, verify_ssl: bool = False):
        """ Static method to dynamically register a PDP client, using the EOEPCA_Scim library.
        """
        if not ScimHandler.__eoepca_scim_instance:
            if(os.path.isfile('./private.pem')):
                print("SCIM Handler: private key found, initiating...")
                ScimHandler.__eoepca_scim_instance = EOEPCA_Scim(host=auth_server_url, clientID=client_id, clientSecret=client_secret, jks_path="./private.pem")
            else:
                ScimHandler.__eoepca_scim_instance = EOEPCA_Scim(host=auth_server_url, clientID=client_id, clientSecret=client_secret)
            if not client_id or not client_secret:
                grantTypes = ["client_credentials", "urn:ietf:params:oauth:grant-type:uma-ticket", "password", "implicit"]
                scopes = ["public_access"]
                ScimHandler.__scim_client = ScimHandler.__eoepca_scim_instance.registerClient("PDP Dynamic Client", grantTypes = grantTypes, redirectURIs = [""], logoutURI = "", responseTypes = ["code","token","id_token"], scopes = scopes, token_endpoint_auth_method = ENDPOINT_AUTH_CLIENT_PRIVATE_KEY_JWT, useJWT=1)
                print("SCIM Handler: created new PDP client: " + ScimHandler.__scim_client["client_id"] )
            else:
                ScimHandler.__scim_client = {"client_id": client_id, "client_secret": client_secret}
            ScimHandler.__wkh = WellKnownHandler(auth_server_url, secure=False)
            ScimHandler.__verify_ssl = verify_ssl
        return ScimHandler.__scim_client
    
    def getUserAttributes(self, userId: str):
        """ Method to retrieve a user's attributes. It uses the EOEPCA_Scim library to handle UMA authorization flow.
        """
        print("SCIM Handler: Get User attributes for user " + str(userId))
        if not ScimHandler.__scim_client:
            raise Exception("SCIM Handler: Client not initialized! Please register new client first.")
        try:
            userAttributes = ScimHandler.__eoepca_scim_instance.getUserAttributes(userId)
            if not userAttributes:
                return 500, "SCIM Handler: PDP Client not found on Authorization Server"
            if userAttributes == "0":
                return 500, "SCIM Handler: Authorization error when retrieving user attributes"
            return 200, ScimHandler.__eoepca_scim_instance.getUserAttributes(userId)
        except Exception as e:
            print("SCIM Handler: Get User attributes: Exception occured!")
            print(str(e))
            status = 500
            return status, {}