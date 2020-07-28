#!/usr/bin/env python3
import time
from policy_storage import Policy_Storage
from flask import Flask
from random import choice
from string import ascii_lowercase
import json
from policies.policies import policy_bp
from config import config_parser
import os
import sys

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

g_config = {}
# Global config objects
if use_env_var is False:
    g_config = config_parser.load_config()

else:
    for env_var in env_vars:
        env_var_config = env_var.replace('PDP_', '')

        if "true" in os.environ[env_var].replace('"', ''):
            g_config[env_var_config.lower()] = True
        elif "false" in os.environ[env_var].replace('"', ''):
            g_config[env_var_config.lower()] = False
        else:
            g_config[env_var_config.lower()] = os.environ[env_var].replace('"', '')


#example rule policy a:
a= {
    "resource_id": "20248583",
    "rules": [{
        "OR": [
                {"EQUAL": {"user_name" : "mami"} },
                {"EQUAL": {"user_name" : "admin"} }
        ]
    }]
}
#example rule policy a:
b= {
    "resource_id": "202485830",
    "rules": [{
        "AND": [
                {"EQUAL": {"user_name" : "admin"} }
        ]
    }]
}
#instance
mongo = Policy_Storage()
#register policy:
mongo.insert_policy(name='Policy1', description= '', config= a, scopes=[''])
#register policy:
mongo.insert_policy(name='Policy2', description= '', config= b, scopes=[''])


app = Flask(__name__)
app.secret_key = ''.join(choice(ascii_lowercase) for i in range(30)) # Random key

# Register api blueprints (module endpoints)
app.register_blueprint(policy_bp, url_prefix="/policy")

app.run(
    debug=g_config["debug_mode"],
    port=g_config["port"],
    host=g_config["host"]
)
