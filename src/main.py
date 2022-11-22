#!/usr/bin/env python3
import json
import os
import re
import socket

from random import choice
from string import ascii_lowercase
from flask import Flask
from flask_swagger_ui import get_swaggerui_blueprint

from policy_storage import Policy_Storage
from config import config_parser
from policies.validator import policy_validator_bp
from policies.manager import policy_manager_bp
from handlers.scim_handler import ScimHandler
from custom_oidc import OIDCHandler

import logging
from handlers.log_handler import LogHandler

log_handler = LogHandler
dir_path = os.path.dirname(os.path.realpath(__file__))
log_handler.load_config("PDP", dir_path+"/config/log_config.yaml")
logger = logging.getLogger("PDP_ENGINE")


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
    logger.info("Client found in environment, using: "+os.environ["client_id"])
    os_var_client = True
elif "client_id" in g_config and "client_secret" in g_config:
    logger.info("Client found in config, using: "+g_config["client_id"])
    #use_env_var = False
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

oidc_client = OIDCHandler(g_config['auth_server_url'],
                            client_id= None,
                            client_secret= None,
                            redirect_uri = "",
                            scopes = ['openid', 'uma_protection', 'permission'],
                            verify_ssl = g_config['check_ssl_certs'])

if os_var_client:
    ScimHandler.registerScimClient(auth_server_url = os.environ["PDP_AUTH_SERVER_URL"], client_id = os.environ["PDP_CLIENT_ID"], client_secret = os.environ["PDP_CLIENT_SECRET"], verify_ssl = os.environ["PDP_CHECK_SSL_CERTS"])    
elif cfg_client:
    ScimHandler.registerScimClient(auth_server_url = g_config["auth_server_url"], client_id = g_config["client_id"], client_secret = g_config["client_secret"], verify_ssl = g_config["check_ssl_certs"])
else:
    logger.info("NOTICE: Client not found, generating one... ")
    new_client = ScimHandler.registerScimClient(auth_server_url = g_config["auth_server_url"], verify_ssl=g_config["check_ssl_certs"])
    g_config["client_id"] = new_client["client_id"]
    g_config["client_secret"] = new_client["client_secret"]
    config_parser.save_config(g_config)
    os.environ["PEP_CLIENT_ID"] = new_client["client_id"]
    os.environ["PEP_CLIENT_SECRET"] = new_client["client_secret"]

app = Flask(__name__)
app.secret_key = ''.join(choice(ascii_lowercase) for i in range(30)) # Random key

# SWAGGER initiation
SWAGGER_URL = '/swagger-ui'  # URL for exposing Swagger UI (without trailing '/')
API_URL = "" # Our local swagger resource for PDP. Not used here as 'spec' parameter is used in config
SWAGGER_SPEC = json.load(open(dir_path+"./static/swagger_pdp_ui.json"))
SWAGGER_APP_NAME = "Policy Decision Point Interfaces"

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={  # Swagger UI config overrides
        'app_name': SWAGGER_APP_NAME,
        'spec': SWAGGER_SPEC
    },
)

# Register api blueprints (module endpoints)
app.register_blueprint(policy_validator_bp, url_prefix="/policy")
app.register_blueprint(policy_manager_bp(oidc_client))
app.register_blueprint(swaggerui_blueprint)

app.run(
    debug=g_config["debug_mode"],
    port=g_config["port"],
    host=g_config["host"]
)


        