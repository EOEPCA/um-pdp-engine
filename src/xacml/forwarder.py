import requests
import json

import models.request as xacml_request
from utils import ClassEncoder

def delegate(subject, action, resource, delegate_addr, own_url):
    request = xacml_request.Request(subject, action, resource, own_url)
    xacml_json = json.dumps(request, cls=ClassEncoder)
    try:
        r = requests.get(delegate_addr, json=xacml_json)
    except requests.exceptions.ConnectionError:
        print("Error trying to connect to external PDP")
        return 500
    if r.status_code == 200 or r.status_code == 401:
        print("Request successfully delegated to: "+delegate_addr)
        return r.status_code
    print("Problem forwarding request to: "+delegate_addr+" status received: "+str(r.status_code))
    return r.status_code
