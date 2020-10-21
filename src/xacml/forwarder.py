import requests
import json

import models.request as xacml_request
from utils import ClassEncoder

def delegate(subject, action, resource, delegate_addr):
    request = xacml_request.Request(subject.attributes, action_rsrc.attributes, resource.attributes, delegate_addr)
    r = requests.get(delegate_addr, data=json.dumps(request, cls=ClassEncoder))
    if r.status_code == 200:
        print("Request successfully delegated to: "+delegate_addr):
    else:
        print("Problem forwarding request to: "+delegate_addr" status received: "+r.status_code)
