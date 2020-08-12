#!/usr/bin/env python3
import time
from policy_storage import Policy_Storage
from flask import Flask
from random import choice
from string import ascii_lowercase
import json
from policies.policies import policy_bp
from config import config_parser
from flask import Flask, request, Response
from requests import get, post, put, delete
import os
import re
import sys
import base64
from custom_oidc import OIDCHandler
from WellKnownHandler import WellKnownHandler
from WellKnownHandler import TYPE_UMA_V2, KEY_UMA_V2_RESOURCE_REGISTRATION_ENDPOINT, KEY_UMA_V2_PERMISSION_ENDPOINT, KEY_UMA_V2_INTROSPECTION_ENDPOINT
from eoepca_uma import rpt as class_rpt
import logging
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

oidc_client = OIDCHandler(g_config['auth_server_url'],
                            client_id= None,
                            client_secret= None,
                            redirect_uri = "",
                            scopes = ['openid', 'uma_protection', 'permission'],
                            verify_ssl = g_config['check_ssl_certs'])
client_id, client_secret=oidc_client.register_client()

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
#instance
mongo = Policy_Storage('mongodb')
#register example policy:
mongo.insert_policy(name='Policy1', description= '',ownership_id= '55b8f51f-4634-4bb0-a1dd-070ec5869d70', config= a, scopes=[''])
#register example policy:
mongo.insert_policy(name='Policy2', description= '',ownership_id= '55b8f51f-4634-4bb0-a1dd-070ec5869d70', config= b, scopes=[''])


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
                    #Insert in database the body parameters
                    return mongo.insert_policy(data.get("name"), data.get("description"), uid ,data.get("config"), data.get("scopes"))
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
                        return mongo.update_policy(policy_id, data)
                    else:
                        response.status_code = 500
                        response.headers["Error"] = "Invalid data or incorrect policy name passed on URL called for policy creation!"
                        return response
            #return policy or list of policies if the resource_id is in the body
            elif request.method == "GET":
                if request.data:
                    data = request.get_json()
                    f= open("out.txt","w+")
                    f.write(str(data))
                    f.write('----')
                    if data.get("resource_id"):
                        list_of_policies={}
                        a= mongo.get_policy_from_resource_id(data.get("resource_id"))
                        f.write(str(a))
                        list_of_policies['policies'] = a
                        for n in list_of_policies['policies']:
                            f.write(str(n))
                            if '_id' in n:
                                n['_id'] = str(n['_id'])
                                f.write(str(n))
                        f.write('return:')
                        fwrite(str(list_of_policies))
                        return json.dumps(list_of_policies)
                    f.close()   
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


        