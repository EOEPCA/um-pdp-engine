from flask import Blueprint, request
import json

from xacml import parser

resource_bp = Blueprint('resource_bp', __name__)

def validate_json(json_data):
    try:
        json.loads(json_data)
    except (ValueError, TypeError) as err:
        return False
    return True


@resource_bp.route('/validate')
def validate_resource():
    xacml = request.json
    if not validate_json(xacml):
        return "Valid JSON data is required"
    
    subject, action, resource = parser.load_request(xacml)

    
