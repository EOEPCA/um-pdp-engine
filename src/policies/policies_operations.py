import json
#from policy_storage.py import Policy_Storage

def validate_access_policies(resource_id, user_name):
    #mongo = Policy_Storage()
    #data = mongo.get_policy_from_resource_id(str(resource_id))
    
    operations = ['AND', 'OR']

    if isinstance(data, list):
        for i in range(0, len(data)):
            if data[i]['config']['resource_id'] == resource_id:
                for operation in operations:
                    if operation in data[i]['config']['rules'][0].keys():
                        exist_operation = operation
                        break

                if len(data[i]['config']['rules'][0][exist_operation]) == 1:
                    if data[i]['config']['rules'][0][exist_operation][0]['EQUAL']['user_name'] == user_name:
                        return True
                else:
                    for j in range(0, len(data[i]['config']['rules'][0][exist_operation])):
                        if data[i]['config']['rules'][0][exist_operation][j]['EQUAL']['user_name'] == user_name:
                            return True
    return False



