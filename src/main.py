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
mongo = Policy_Storage('mongodb')
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

@app.route("/policies/<policy_id>", methods=["GET", "PUT", "POST", "DELETE"])
def policy_operation(policy_id):
    print("Processing " + request.method + " policy request...")
    response = Response()
    mongo = Policy_Storage() 
    #add policy is outside of rpt validation, as it only requires a client pat to register a new policy
    try:
        if request.method == "POST":
            if request.is_json:
                data = request.get_json()
                if data.get("name") and data.get("description") and data.get("config"):
                    return mongo.insert_policy(data.get("name"), data.get("description"), data.get("config"), data.get("scopes"))
                else:
                    response.status_code = 500
                    response.headers["Error"] = "Invalid data or incorrect policy name passed on URL called for policy creation!"
                    return response

        elif request.method == "GET":
            if request.is_json:
                data = request.get_json()
                if data.get("resource_id"):
                    return mongo.get_policy_from_resource_id(resource_id)
                elif data.get("_id"):
                    return mongo.get_policy_from_id(resource_id)
            #update resource
        elif request.method == "PUT":
            if request.is_json:
                data = request.get_json()
                if data.get("_id"):
                    return mongo.update_policy(data.get("_id"), data.get())
                else:
                    response.status_code = 500
                    response.headers["Error"] = "Invalid data or incorrect policy name passed on URL called for policy creation!"
                    return response


        elif request.method == "DELETE":
                    mongo.delete_policy(resource_id)
                    response.status_code = 204
                    return response
    except Exception as e:
        print("Error while creating resource: "+str(e))
        response.status_code = 500
        response.headers["Error"] = str(e)
        return response

    
        