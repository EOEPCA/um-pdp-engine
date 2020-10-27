from xacml import decision, forwarder
from models import response


def _final_response(status):
    if 401 in status:
        return response.Response(decision.DENY, "fail_to_permit", "obligation-id", "You cannot access this resource"), 401
    if 400 in status:
        return response.Response(decision.DENY, "fail_to_permit", "obligation-id", "Please ensure you submit a JSON xacml request"), 400
    return response.Response(decision.PERMIT), 200
    

def generate_response(decisions, subject_attr, action_attr, resource_attr, this_pdp_url):
    overall_status = []
    response = {
        True: 200,
        False: 401
    }

    for result in decisions.values():
        # result[0] = decision; decision[1] = delegation address if present
        if result[0] == None: # delegation
            overall_status.append(forwarder.delegate(subject_attr, action_attr, resource_attr, result[1], this_pdp_url))
        else:
            overall_status.append(response[result[0]])
    
    return _final_response(overall_status)
