import json

from models.action import Action
from models.resource import Resource
from models.subject import Subject


def load_request(xacml):
    xacml = json.load(xacml)

    user_attrs = xacml["Request"]["AccessSubject"][0]["Attribute"]
    subject = Subject()
    for attr in user_attrs:
        subject.add_attribute(attr["AttributeId"], attr["Value"], attr["DataType"], attr["IncludeInResult"])
    
    action_attrs = xacml["Request"]["Action"][0]["Attribute"]
    action = Action()
    for attr in action_attrs:
        action.add_attribute(attr["AttributeId"], attr["Value"])
    
    resource_attrs = xacml["Request"]["Resource"][0]["Attribute"]
    resource = Resource()
    for attr in resource_attrs:
        resource.add_attribute(attr["AttributeId"], attr["Value"], attr["DataType"], attr["IncludeInResult"])
    return subject, action, resource