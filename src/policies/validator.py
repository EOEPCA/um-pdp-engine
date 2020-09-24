from flask import Blueprint, request, Response, jsonify
import json

from handlers.scim_handler import ScimHandler
from policies import policies_operations
from models import response
from xacml import parser, decision
from utils import ClassEncoder

policy_validator_bp = Blueprint('policy_validator_bp', __name__)

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
        return "Valid JSON data is required"
    
    subject, action, resource = parser.load_request(xacml)

    resource_id = resource.attributes[0]['Value']
    user_name = subject.attributes[0]['Value']
    action = action.attributes[0]['Value']
    
    #To be expanded when implementing more complex policies
    #For now it serves only as a check if the user attributes were reachable on the AS
    #handler_user_attributes uses this schema: https://gluu.org/docs/gluu-server/4.1/api-guide/scim-api/#/definitions/User

    # Call to be used later in development
    try:
        handler_status, handler_user_attributes = ScimHandler.get_instance().getUserAttributes(user_name)
    except Exception as e:
        print("Error While retrieving the user attributes")

    if not isinstance(handler_user_attributes, dict):
        handler_user_attributes = {}

        for i in range(0, len(subject.attributes)):
            handler_user_attributes[subject.attributes[i]['AttributeId']] = subject.attributes[i]['Value']

    # Pending: Complete when xacml receives several resources
    if isinstance(resource_id, list):
        for resource_from_list in resource.attributes[0]['Value']:
            result_validation = policies_operations.validate_complete_policies(resource_from_list, action, handler_user_attributes)
            if result_validation:
                break
    else:
        result_validation = policies_operations.validate_complete_policies(resource_id, action, handler_user_attributes)

    if result_validation:
        r = response.Response(decision.PERMIT)
        status = 200
    else:
        r = response.Response(decision.DENY, "fail_to_permit", "obligation-id", "You cannot access this resource")
        status = 401
    
    return json.dumps(r, cls=ClassEncoder), status

    