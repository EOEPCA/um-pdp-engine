from flask import Blueprint, request, Response, jsonify
import json
import os

from handlers.scim_handler import ScimHandler
from policies import policies_operations
from models import response
from xacml import parser, decision, forwarder, response_handler
from utils import ClassEncoder
from config import config_parser

policy_validator_bp = Blueprint('policy_validator_bp', __name__)


def validate_auth_server_url():
    env_var_auth_server_url = 'PDP_AUTH_SERVER_URL'      
    g_config = config_parser.load_config()

    if env_var_auth_server_url not in os.environ:
        return g_config["auth_server_url"]
    else:
        g_config["auth_server_url"] = str(os.environ["PDP_AUTH_SERVER_URL"])
        config_parser.save_config(g_config)
        return g_config["auth_server_url"]

def validate_json(json_data):
    try:
        if isinstance(json_data, dict):
            json_data_string = json.dumps(json_data)
            json.loads(json_data_string)
        else:
            json.loads(json_data)
    except (ValueError, TypeError) as err:
        return False
    return True

@policy_validator_bp.route('/validate')
def validate_resource():
    xacml = request.json
    if not validate_json(xacml):
        print ("Invalid xacml received")
        return "Valid JSON data is required", 400
    
    subject, action_rsrc, resource = parser.load_request(xacml)
    resource_id = resource.attributes[0]['Value']
    user_name = subject.attributes[0]['Value']
    action = action_rsrc.attributes[0]['Value']

    #To be expanded when implementing more complex policies

    if "Issuer" in subject.attributes[0].keys():
        issuer = subject.attributes[0]['Issuer']
    else:
        issuer = None

    handler_status_issuer = None

    if issuer is not None:
        handler_status_issuer, handler_issuer_message = ScimHandler.get_instance().modifyAuthServerUrl(issuer)

    #For now it serves only as a check if the user attributes were reachable on the AS
    #handler_user_attributes uses this schema: https://gluu.org/docs/gluu-server/4.1/api-guide/scim-api/#/definitions/User

    # Call to be used later in development
    try:
        if handler_status_issuer == 200 or (issuer is None):
            handler_status, handler_user_attributes = ScimHandler.get_instance().getUserAttributes(user_name)
            if not isinstance(handler_user_attributes, dict):
                print(handler_user_attributes)
                handler_user_attributes = {}
                for i in range(0, len(subject.attributes)):
                    handler_user_attributes[subject.attributes[i]['AttributeId']] = subject.attributes[i]['Value']

            if issuer is None:
                handler_user_attributes['issuer'] = validate_auth_server_url()
            else:
                handler_user_attributes['issuer'] = issuer
        else:
            handler_user_attributes = {}
            raise Exception()
    except Exception as e:
        print("Error While retrieving the user attributes")
    # Pending: Complete when xacml receives several resources
    if isinstance(resource_id, list):
        for resource_from_list in resource.attributes[0]['Value']:
            result_validation, delegate_addr = policies_operations.validate_complete_policies(resource_from_list, action, handler_user_attributes)
            if result_validation:
                break
    else:
        decisions = policies_operations.validate_complete_policies(resource_id, action, handler_user_attributes)

    resp, status = response_handler.generate_response(decisions, subject.attributes, action_rsrc.attributes, resource.attributes, request.base_url)
    
    return json.dumps(resp, cls=ClassEncoder), status

    
