import json

from flask import Blueprint, request, Response
from policies import validator
from policies.policies_operations import validate_policy_language
from policy_storage import Policy_Storage
import logging

def policy_manager_bp(oidc_client):
    policy_manager_bp = Blueprint('policy_manager_bp', __name__)    

    @policy_manager_bp.route('/acceptance_validation/', methods=["GET"])
    def validate_TC():
        print("Processing " + request.method + " policy request...")
        response = Response()
        uid= None
        try:
            a = str(request.headers)
            headers_alone = a.split()
            inputToken = None
            for i in headers_alone:
                #Retrieve the token from the headers
                if 'Bearer' in str(i):
                    aux=headers_alone.index('Bearer')
                    inputToken = headers_alone[aux+1]           
            token = inputToken
            #Authorized
            if token and request.get_json():
                data = request.get_json()
                #Decision values: True, False
                decision = validator.return_terms_decision(oidc_client, token, data.get("resource_id"))
                if decision == True:
                    response.status_code = 200
                    response.text = str(decision)
                else: 
                    response.status_code = 403
                    response.headers["Error"] = "Forbidden Resource " + str(data.get("resource_id"))
                return response
            #No Authorized
            else:
                response.status_code = 401
                response.headers["Error"] = "NO TOKEN FOUND OR NOT RESOURCE IN DATA: "+ str(token) +" and "+ str(request.get_json())
                return response
                
        except Exception as e:
            print("Error While passing the token: "+str(uid))
            response.status_code = 500
            response.headers["Error"] = str(e)
            return response


    @policy_manager_bp.route("/policy/", methods=["PUT", "POST", "GET"])
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
            token = None
            for i in headers_alone:
                if 'Bearer' in str(i):
                    aux=headers_alone.index('Bearer')
                    token = headers_alone[aux+1]           
            if token:
                #Compares between JWT id_token and OAuth access token to retrieve the UUID
                if len(str(token))>40:
                    uid=oidc_client.verify_JWT_token(token,"sub")
                else:
                    uid=oidc_client.verify_OAuth_token(token)
            else:
                response.status_code = 401
                response.headers["Error"] = "NO TOKEN FOUND"
                return response
        except Exception as e:
            print("Error While passing the token: "+str(uid))
            response.status_code = 500
            response.headers["Error"] = str(e)
            return response 
        #Insert once is authorized
        try:
            #If the user is authorized it must find his UUID
            if uid:
                if request.method == "GET":
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
            print("Error while creating policy: "+str(e))
            response.status_code = 500
            response.headers["Error"] = str(e)
            return response

    @policy_manager_bp.route("/terms/", methods=["PUT", "POST", "GET"])
    def term_insert():
        '''
        PUT/POST will create or insert a term & condition in the repository
        This endpoint will check the headers of the request to retrieve a token
        Mandatory parameters:
            - endpoint: <DOMAIN>/terms
            - headers(JWT_id_token/OAuth_access_token): to verify the user credentials
            - body(terms_data_model): As a dicionary/json it must have at least the name, description, config and scope keys to add it
        '''
        print("Processing " + request.method + " terms request...")
        response = Response()
        mongo = Policy_Storage('mongodb') 
        uid= None
        try:
            head = str(request.headers)
            headers_alone = head.split()
            #Retrieve the token from the headers
            token = None
            for i in headers_alone:
                if 'Bearer' in str(i):
                    aux=headers_alone.index('Bearer')
                    token = headers_alone[aux+1]           
            if token:
                #Compares between JWT id_token and OAuth access token to retrieve the UUID
                if len(str(token))>40:
                    uid=oidc_client.verify_JWT_token(token,"sub")
                else:
                    uid=oidc_client.verify_OAuth_token(token)
            else:
                response.status_code = 401
                response.headers["Error"] = "NO TOKEN FOUND"
                return response
        except Exception as e:
            print("Error While passing the token: "+str(uid))
            response.status_code = 500
            response.headers["Error"] = str(e)
            return response 
        #Insert once is authorized
        try:
            #If the user is authorized it must find his UUID
            if uid:
                if request.method == "GET":
                    terms = mongo.get_all_terms()
                    for i, term in enumerate(terms):
                        if '_id' in term:
                            terms[i]['_id'] = str(terms[i]['_id'])
                    return json.dumps(terms) 
                else:
                    data = request.get_json()
                    if data is None:
                        response.status_code = 500
                        response.headers["Error"] = "Terms & condition json data missing"
                        return response
                    if data.get("term_id") and data.get("term_description"):
                        return mongo.insert_term(data.get("term_id"), data.get("term_description"))
                    response.status_code = 500
                    response.headers["Error"] = "Invalid data or incorrect term & condition name passed on URL called for terms & conditions creation!"
                    return response
            else: 
                response.status_code = 401
                response.headers["Error"] = 'Could not get the UID for the user'
                return response
        except Exception as e:
            print("Error while creating term & condition: "+str(e))
            response.status_code = 500
            response.headers["Error"] = str(e)
            return response
            
    @policy_manager_bp.route("/policy/<policy_id>", methods=["GET", "PUT", "POST", "DELETE"])
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
                    uid=oidc_client.verify_JWT_token(token,"sub")
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
            
    @policy_manager_bp.route("/terms/<term_id>", methods=["GET", "PUT", "POST", "DELETE"])
    def terms_operation(term_id):
        '''
        PUT/POST will update a term & condition in the repository by its _id
        GET will return the term & condition by its _id or by specifying the term_id on the body
        DELETE will delete the policy by its _id
        This endpoint will check the headers of the request to retrieve a token
        To operate against any terms & conditions the UUID of the user must match with the one associated to the term & condition
        Mandatory parameters:
            - endpoint: <DOMAIN>/terms/<term_id>    <-   The term_id can be specify with both formats: [policy_id/ObjectId(term_id)]
            - headers(JWT_id_token/OAuth_access_token): to verify the user credentials
            - body(terms_data_model): Only for the GET/PUT/POST, As a dicionary/json.
        '''
        print("Processing " + request.method + " terms request...")
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
                    uid=oidc_client.verify_JWT_token(token,"sub")
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
            if uid:
                #Updates terms & condition
                if request.method == "POST" or request.method == 'PUT':
                    if request.is_json:
                        data = request.get_json()
                        if data.get("term_id") and data.get("term_description"):
                            return mongo.update_term(term_id, data)
                        else:
                            response.status_code = 500
                            response.headers["Error"] = "Invalid data or incorrect term & condition name passed on URL called for terms & conditions creation!"
                            return response
                #return term & condition based on _id
                elif request.method == "GET":
                    term = mongo.get_term_from_id(term_id)
                    term['_id'] = str(term['_id'])
                    return json.dumps(term)
                #Deletes a term & condition by its _id
                elif request.method == "DELETE":
                    mongo.delete_term(term_id)
                    response.status_code = 204
                    response.text = 'DELETED'
                    return response
                else:
                    return ''
            else:
                response.status_code = 401
                response.headers["Error"] = "Could not get the UID for the user"
                return response
        except Exception as e:
            print("Error while creating resource: "+str(e))
            response.status_code = 500
            response.headers["Error"] = str(e)
            return response

    return policy_manager_bp
