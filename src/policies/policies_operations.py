import json
#from policy_storage.py import Policy_Storage

def validate_access_policies(resource_id, user_name):
    #mongo = Policy_Storage()
    #data = mongo.get_policy_from_resource_id(str(resource_id))

    #---------------- Once the mongo is used, comment/remove the whole part of using the json file --------------- 
    #file = "standards/policy_template_ownership.json"
    file = "standards/policy_template_access_list.json"
    operations = ['AND', 'OR']

    with open(file) as json_file:
        data = json.load(json_file)

    # ------------------------------------------------------------------------------------------------------------
    
    if data['resource_id'] == resource_id:
        for operation in operations:
            if operation in data['rules'][0].keys():
                exist_operation = operation
                break

        if len(data['rules'][0][exist_operation]) == 1:
            if data['rules'][0][exist_operation][0]['EQUAL']['user_name'] == user_name:
                return True
        else:
            for i in range(0, len(data['rules'][0][exist_operation])):
               if data['rules'][0][exist_operation][i]['EQUAL']['user_name'] == user_name:
                   return True
    return False




