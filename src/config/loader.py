import os

from handlers.scim_handler import ScimHandler
from policy_storage import PolicyStorage
from custom_oidc import OIDCHandler
from config import config_parser


#env vars definition
env_vars = [
    'PDP_AUTH_SERVER_URL',        
    'PDP_PREFIX',
    'PDP_HOST',           
    'PDP_PORT',             
    'PDP_CHECK_SSL_CERTS',         
    'PDP_DEBUG_MODE'
    ]

use_env_var = True

for env_var in env_vars:
    if env_var not in os.environ:
        use_env_var = False

#We need to load to load the config to check if a client_id is specified, otherwise we risk duplicating the client when restarting the container
#Order of check is:
# 1- OS Variables (making sure the above check for other variables was positive)
# 2- Config file
os_var_client = False
cfg_client = False
g_config = config_parser.load_config()
if "PDP_CLIENT_ID" in os.environ and "PDP_CLIENT_SECRET" in os.environ and use_env_var:
    print("Client found in environment, using: "+os.environ["client_id"])
    os_var_client = True
elif "client_id" in g_config and "client_secret" in g_config:
    print("Client found in config, using: "+g_config["client_id"])
    cfg_client = True
elif use_env_var:
    g_config = {}

# Global config objects
if use_env_var is True:
    for env_var in env_vars:
        env_var_config = env_var.replace('PDP_', '')

        if "true" in os.environ[env_var].replace('"', ''):
            g_config[env_var_config.lower()] = True
        elif "false" in os.environ[env_var].replace('"', ''):
            g_config[env_var_config.lower()] = False
        else:
            g_config[env_var_config.lower()] = os.environ[env_var].replace('"', '')

def initial_setup():
    oidc_client = OIDCHandler(g_config['auth_server_url'],
                            client_id= None,
                            client_secret= None,
                            redirect_uri = "",
                            scopes = ['openid', 'uma_protection', 'permission'],
                            verify_ssl = g_config['check_ssl_certs'])

    if os_var_client:
        ScimHandler.register_scim_client(auth_server_url = os.environ["PDP_AUTH_SERVER_URL"], client_id = os.environ["PDP_CLIENT_ID"], client_secret = os.environ["PDP_CLIENT_SECRET"], verify_ssl = os.environ["PDP_CHECK_SSL_CERTS"])    
    elif cfg_client:
        ScimHandler.register_scim_client(auth_server_url = g_config["auth_server_url"], client_id = g_config["client_id"], client_secret = g_config["client_secret"], verify_ssl = g_config["check_ssl_certs"])
    else:
        print ("NOTICE: Client not found, generating one... ")
        new_client = ScimHandler.register_scim_client(auth_server_url = g_config["auth_server_url"], verify_ssl=g_config["check_ssl_certs"])
        g_config["client_id"] = new_client["client_id"]
        g_config["client_secret"] = new_client["client_secret"]
        config_parser.save_config(g_config)
        os.environ["PEP_CLIENT_ID"] = new_client["client_id"]
        os.environ["PEP_CLIENT_SECRET"] = new_client["client_secret"]
    return oidc_client, g_config
