#!/usr/bin/python3

import argparse
import sys
from policy_storage import Policy_Storage

custom_mongo = Policy_Storage('mongodb') 

def list_policies(user,resource,policy):
    result = []
    if policy is not None:
        result = custom_mongo.get_policy_from_id(policy)
    else:
        result=custom_mongo.get_all_policies()
        if user is not None:
            result = list(filter(lambda x: x["ownership_id"] == user,result))
        if resource is not None:
            result = list(filter(lambda x: x["resource_id"] == resource,result))
    return result
    
def remove_policies(user,resource,policy,all):
    if policy is not None:
        return custom_mongo.delete_policy(policy)
    if all:
        query = []
        if user is not None:
            query.insert({"ownership_id": user})
        if resource is not None:
            query.insert({"resource_id": resource})
        return custom_mongo.remove_policy_by_query(query)
    else:
        return "No action taken (missing --all flag?)"


parser = argparse.ArgumentParser(description='Operational management of policies.')
parser.add_argument('action', metavar='action', type=str,
                    help='Operation to perform: list/remove')
parser.add_argument('-u',
                       '--user',
                       help='Filter action by user ID')
parser.add_argument('-r',
                       '--resource',
                       help='Filter action by resource ID')
parser.add_argument('-p',
                       '--policy',
                       help='Filter action by Policy ID')

parser.add_argument('-a',
                       '--all',
                       action='store_true',
                       help='Apply action to all policies.')


args = vars(parser.parse_args())

if args["action"] == "list":
    result = list_policies(args['user'],args['resource'],args['policy'])
elif args["action"] == "remove": 
    if args["policy"] is not None:
        args["all"] = False
    result = remove_policies(args['user'],args['resource'],args['policy'],args['all'])
else:
    print("Allowed actions are 'remove' or 'list'")
    sys.exit(-1)
    
print(result)
