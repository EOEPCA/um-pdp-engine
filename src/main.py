#!/usr/bin/env python3
import time
import json
import os
import sys
import re
import base64
import logging

from random import choice
from string import ascii_lowercase
from flask import Flask, request, Response
from requests import get, post, put, delete

from policy_storage import Policy_Storage
from config import config_parser
from policies.policies import policy_bp
from policies.policies_operations import validate_policy_language
from handlers.scim_handler import ScimHandler
from custom_oidc import OIDCHandler
from WellKnownHandler import WellKnownHandler
from WellKnownHandler import TYPE_UMA_V2, KEY_UMA_V2_RESOURCE_REGISTRATION_ENDPOINT, KEY_UMA_V2_PERMISSION_ENDPOINT, KEY_UMA_V2_INTROSPECTION_ENDPOINT
from eoepca_uma import rpt as class_rpt


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
client_id, client_secret=oidc_client.register_client()

if os_var_client:
    ScimHandler.registerScimClient(auth_server_url = os.environ["PDP_AUTH_SERVER_URL"], client_id = os.environ["PDP_CLIENT_ID"], client_secret = os.environ["PDP_CLIENT_SECRET"], verify_ssl = os.environ["PDP_CHECK_SSL_CERTS"])    
elif cfg_client:
    ScimHandler.registerScimClient(auth_server_url = g_config["auth_server_url"], client_id = g_config["client_id"], client_secret = g_config["client_secret"], verify_ssl = g_config["check_ssl_certs"])
else:
    print ("NOTICE: Client not found, generating one... ")
    new_client = ScimHandler.registerScimClient(auth_server_url = g_config["auth_server_url"], verify_ssl=g_config["check_ssl_certs"])
    g_config["client_id"] = new_client["client_id"]
    g_config["client_secret"] = new_client["client_secret"]
    config_parser.save_config(g_config)
    os.environ["PEP_CLIENT_ID"] = new_client["client_id"]
    os.environ["PEP_CLIENT_SECRET"] = new_client["client_secret"]

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
#example rule policy b:
b= {
    "resource_id": "202485830",
    "rules": [{
        "AND": [
                {"EQUAL": {"user_name" : "admin"} }
        ]
    }]
}

c= {
    "resource_id": "123456",
    "rules" : [
        {
          "AND": [{
            "EQUAL" : {"user_name" : "admin" }
          }]
        },
        {
          "AND": [{
          "NOT" : {
            "OR" : [
                    {"GREATER": {"num_acces" : 10} },
                    {"GREATEREQUAL" : {"attemps" : 18 }}
            ]
          },
            "EQUAL" : {"company" : "Deimos" }
          }]
        },
        { 
          "LESSEQUAL" : {"system_load" : 90 }
        }
      ]
}

d= {
        "resource_id": "1234567",
        "rules" : [
            {
                "AND": [{
                "EQUAL" : {"userName" : "admin" }
                }]
            },
            {
                "AND": [{
                    "NOT" : {
                        "OR" : [
                                {"EQUAL": {"emails" : [{'value': 'mamuniz@test.com', 'primary': False}]} },
                                {"EQUAL" : {"nickName" : "Mami" }}
                            ]
                    },
                    "EQUAL" : {"displayName" : "Default Admin User" }
                }]
            },
            {
                "EQUAL" : {"groups" : [{'value': '60B7', 'display': 'Gluu Manager Group', 'type': 'direct', 'ref': 'https://test.10.0.2.15.nip.io/identity/restv1/scim/v2/Groups/60B7'}] }
            }
        ]
    }

#instance
mongo = Policy_Storage('mongodb')
#register example policy:
mongo.insert_policy(name='Policy1', description= '',ownership_id= '55b8f51f-4634-4bb0-a1dd-070ec5869d70', config= a, scopes=[''])
#register example policy:
mongo.insert_policy(name='Policy2', description= '',ownership_id= '55b8f51f-4634-4bb0-a1dd-070ec5869d70', config= b, scopes=[''])
#register example policy:
mongo.insert_policy(name='Policy30', description= '',ownership_id= '55b8f51f-4634-4bb0-a1dd-070ec5869d70', config= c, scopes=[''])
mongo.insert_policy(name='Policy31', description= '',ownership_id= '55b8f51f-4634-4bb0-a1dd-070ec5869d70', config= d, scopes=[''])


app = Flask(__name__)
app.secret_key = ''.join(choice(ascii_lowercase) for i in range(30)) # Random key

# Register api blueprints (module endpoints)
app.register_blueprint(policy_bp, url_prefix="/policy")


@app.route("/policy/", methods=[ "PUT", "POST"])
def policy_insert():
    '''
    PUT/POST will create or insert a policy in the repository
    This endpoint will check the headers of the request to retrieve a token
    Mandatory parameters:
        - endpoint: <DOMAIN>/policy
        - headers(JWT_id_token/OAuth_access_token): to verify the user credentials
        - body(policy_data_model): As a dicionary/json it must have at least the name, description, config and scope keys to add it
    '''
    print("Processing " + request.method + " policy request...")
    response = Response()
    mongo = Policy_Storage('mongodb') 
    uid= None
    try:
        head = str(request.headers)
        headers_alone = head.split()
        #Retrieve the token from the headers
        for i in headers_alone:
            if 'Bearer' in str(i):
                aux=headers_alone.index('Bearer')
                inputToken = headers_alone[aux+1]           
        token = inputToken
        if token:
            #Compares between JWT id_token and OAuth access token to retrieve the UUID
            if len(str(token))>40:
                uid=oidc_client.verify_JWT_token(token)
            else:
                uid=oidc_client.verify_OAuth_token(token)
        else:
            return 'NO TOKEN FOUND'
    except Exception as e:
        print("Error While passing the token: "+str(uid))
        response.status_code = 500
        response.headers["Error"] = str(e)
        return response 
    #Insert once is authorized
    try:
        #If the user is authorized it must find his UUID
        if uid:
            if request.is_json:
                data = request.get_json()
                if data.get("name") and data.get("config"):
                    policy_structure = data.get("config")
                    result_format = validate_policy_language(policy_structure['rules'])
                    if result_format is True:
                        #Insert in database the body parameters
                        return mongo.insert_policy(data.get("name"), data.get("description"), uid ,data.get("config"), data.get("scopes"))
                    else:
                        response.status_code = 500
                        response.headers["Error"] = "Invalid policy structure"
                        return response
                else:
                    response.status_code = 500
                    response.headers["Error"] = "Invalid data or incorrect policy name passed on URL called for policy creation!"
                    return response
        else: 
            response.status_code = 401
            response.headers["Error"] = 'Could not get the UID for the user'
            return response
    except Exception as e:
        print("Error while creating resource: "+str(e))
        response.status_code = 500
        response.headers["Error"] = str(e)
        return response
        
@app.route("/policy/<policy_id>", methods=["GET", "PUT", "POST", "DELETE"])
def policy_operation(policy_id):
    '''
    PUT/POST will update a policy in the repository by its _id
    GET will return the policy by its _id or by specifying the resource_id on the body
    DELETE will delete the policy by its _id
    This endpoint will check the headers of the request to retrieve a token
    To operate against any policy the UUID of the user must match with the one associated to the policy
    Mandatory parameters:
        - endpoint: <DOMAIN>/policy/<policy_id>    <-   The policy_id can be specify with both formats: [policy_id/ObjectId(policy_id)]
        - headers(JWT_id_token/OAuth_access_token): to verify the user credentials
        - body(policy_data_model): Only for the GET/PUT/POST, As a dicionary/json.
    '''
    print("Processing " + request.method + " policy request...")
    response = Response()
    mongo = Policy_Storage('mongodb')
    uid= None
    try:
        a = str(request.headers)
        headers_alone = a.split()
        for i in headers_alone:
            #Retrieve the token from the headers
            if 'Bearer' in str(i):
                aux=headers_alone.index('Bearer')
                inputToken = headers_alone[aux+1]           
        token = inputToken
        if token: 
            #Compares between JWT id_token and OAuth access token to retrieve the UUID
            if len(str(token))>40:
                uid=oidc_client.verify_JWT_token(token)
            else:
                uid=oidc_client.verify_OAuth_token(token)
        else:
            return 'NO TOKEN FOUND'
    except Exception as e:
        print("Error While passing the token: "+str(uid))
        response.status_code = 500
        response.headers["Error"] = str(e)
        return response
    #once Authorized performs operations against the policy
    try:
        #If UUID exists and policy requested has same UUID
        if uid and mongo.verify_uid(policy_id, uid):
            #Updates policy
            if request.method == "POST" or request.method == 'PUT':
                if request.is_json:
                    data = request.get_json()
                    if data.get("name") and data.get("config"):
                        policy_structure = data.get("config")
                        result_format = validate_policy_language(policy_structure['rules'])
                        if result_format is True:
                            return mongo.update_policy(policy_id, data)
                        else:
                            response.status_code = 500
                            response.headers["Error"] = "Invalid policy structure"
                            return response
                    else:
                        response.status_code = 500
                        response.headers["Error"] = "Invalid data or incorrect policy name passed on URL called for policy creation!"
                        return response
            #return policy or list of policies if the resource_id is in the body
            elif request.method == "GET":
                if request.data:
                    data = request.get_json()
                    if data.get("resource_id"):
                        list_of_policies={}
                        a= mongo.get_policy_from_resource_id(data.get("resource_id"))
                        list_of_policies['policies'] = a
                        for n in list_of_policies['policies']:
                            if '_id' in n:
                                n['_id'] = str(n['_id'])
                        return json.dumps(list_of_policies)  
                else:
                    a= mongo.get_policy_from_id(policy_id)
                    a['_id'] = str(a['_id'])
                    return json.dumps(a)
            #Deletes a policy by its _id
            elif request.method == "DELETE":
                mongo.delete_policy(policy_id)
                response.status_code = 204
                response.text = 'DELETED'
                return response
            else:
                return ''
        else:
            response.status_code = 401
            response.headers["Error"] = "Can not operate. No UID valid for that Policy: { policy_id: "+policy_id+", UUID: "+uid+"}"
            return response
    except Exception as e:
        print("Error while creating resource: "+str(e))
        response.status_code = 500
        response.headers["Error"] = str(e)
        return response

app.run(
    debug=g_config["debug_mode"],
    port=g_config["port"],
    host=g_config["host"]
)


        