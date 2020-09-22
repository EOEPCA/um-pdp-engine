import json

from models.action import Action
from models.resource import Resource
from models.subject import Subject


def load_request(xacml):
    if not isinstance(xacml, dict):
        xacml = json.load(xacml)

    user_attrs = xacml["Request"]["AccessSubject"][0]["Attribute"]
    subject = Subject()
    for attr in user_attrs:
        if "Issuer" in attr.keys():
            subject.add_attribute(attr["AttributeId"], attr["Value"], attr["Issuer"], attr["DataType"], attr["IncludeInResult"])
        else:
            subject.add_attribute(attr["AttributeId"], attr["Value"], None, attr["DataType"], attr["IncludeInResult"])
    
    action_attrs = xacml["Request"]["Action"][0]["Attribute"]
    action = Action()
    for attr in action_attrs:
        action.add_attribute(attr["AttributeId"], attr["Value"])


    resource = Resource()
    if len(xacml["Request"]["Resource"]) == 1:
        resource_attrs = xacml["Request"]["Resource"][0]["Attribute"]
        for attr in resource_attrs:
            resource.add_attribute(attr["AttributeId"], attr["Value"], attr["DataType"], attr["IncludeInResult"])
    else:
        resource_ids = []
        resource_values = []
        resource_data_types = []
        resource_include_results = []

        for i in range(0, len(xacml["Request"]["Resource"])):
            resource_attrs = xacml["Request"]["Resource"][i]["Attribute"]
            for attr in resource_attrs:
                resource_ids.append(attr["AttributeId"])
                resource_values.append(attr["Value"])
                resource_data_types.append(attr["DataType"])
                resource_include_results.append(attr["IncludeInResult"])
                
        resource.add_attribute(resource_ids, resource_values, resource_data_types, resource_include_results)

    return subject, action, resource
