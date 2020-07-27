from flask import Blueprint, request, Response, jsonify
import json
from policies import policies_operations

from xacml import parser

policy_bp = Blueprint('policy_bp', __name__)

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

@policy_bp.route('/validate')
def validate_resource():
    xacml = request.json
    if not validate_json(xacml):
        return "Valid JSON data is required"
    
    subject, action, resource = parser.load_request(xacml)

    resource_id = resource.attributes[0]['Value']
    user_name = subject.attributes[0]['Value']

    # Pending: Complete when xacml receives several resources
    if isinstance(resource_id, list):
        for resource_from_list in resource.attributes[0]['Value']:
            result_validation = policies_operations.validate_access_policies(resource_from_list, user_name)
            if result_validation:
                break
    else:
        result_validation = policies_operations.validate_access_policies(resource_id, user_name)

    response = {'Response':[]}
    if result_validation:
        response["Response"].append({'Decision': "Permit"})
    else:
        response["Response"].append({'Decision': "Deny"})

    return jsonify(response)

    
