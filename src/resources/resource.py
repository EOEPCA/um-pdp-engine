from flask import Blueprint

resource_bp = Blueprint('resource_bp', __name__)

@resource_bp.route('/validate')
def validate_resource():
    return "This is an example app"