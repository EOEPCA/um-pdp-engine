import json
from policy_storage import Policy_Storage


def validate_access_policies(resource_id, user_name):
    mongo = Policy_Storage('mongodb')
    data = mongo.get_policy_from_resource_id(str(resource_id))
    
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

def validate_policy_language(policy):
    operation = ['AND', 'OR', 'XOR', 'NOT', 'LESS', 'LESSEQUAL', 'GREATER', 'GREATEREQUAL', 'EQUAL']

    for i in range(0, len(policy)):
        keys_dict = []
        for key in policy[i].keys(): 
            keys_dict.append(key)

        for key in keys_dict:
            if key in operation:
                if isinstance(policy[i][key], list):
                    result = validate_policy_language(policy[i][key])
                    if result == False:
                        return False
                
                if key == "NOT" and isinstance(policy[i][key], dict):
                    for keys in policy[i][key]:
                        if keys in operation:
                            result = validate_policy_language(policy[i][key][keys])
                            if result == False:
                                return False
                        else:
                            return False
            else:
                return False
    return True

def validate_complete_policies(resource_id, action, dict_request_values):
    mongo = Policy_Storage('mongodb')
    data = mongo.get_policy_from_resource_id(str(resource_id))
    decisions = {}
    if isinstance(data, list):
        for i in range(0, len(data)):
            try:
                if data[i]['config']['resource_id'] == resource_id and data[i]['config']['action'] == action and "delegate" not in data[i]['config']:
                    result = validate_all_acces_policies(data[i]['config']['rules'], dict_request_values)
                    decisions[i] = [result, None]
                elif "delegate" in data[i]['config']:
                    decisions[i] = [None, data[i]['config']['delegate']]
            except KeyError:
                decisions[i] = [False, None]
    if len(decisions) == 0:
+        decisions[0] = [False, None]
    return decisions

def validate_all_acces_policies(data, dict_request_values):
    policy = data
    aux_list = []
    aux_list_result = []

    for i in range(0, len(policy)):
        for key in policy[i].keys():
            aux_list.append(key)
            operations = []
            values_operations = []
            list_values = []
            values_operations = []
            if isinstance(policy[i][key], list):
                for j in range(0, len(policy[i][key])):
                    for k, v in policy[i][key][j].items():
                        aux_dict = {}
                        aux_dict[k] = v
                        aux = []
                        aux = validate_multiples_conditions(aux_dict, dict_request_values)
                        values_operations = values_operations + aux
                list_values = conditions_validator(key, values_operations)
                aux_list_result = aux_list_result + list_values
            else:
                operations.append(key)
                values_operations.append(policy[i][key])
                list_values = validate_operations(operations, values_operations, dict_request_values)
                aux_list_result = aux_list_result + list_values
    permit_acces = True
    for i in range(0, len(aux_list)):
        if aux_list_result[i] is False:
            permit_acces = False
    return permit_acces

def validate_operations(operations, values_operations, dict_request_values):
    list_values = []

    for i in range(0, len(operations)):
        for key in values_operations[i].keys():
            if key in dict_request_values:
                if operations[i] == 'LESS':
                    if dict_request_values[key] < values_operations[i][key]:
                        list_values.append(True)
                    else:
                        list_values.append(False)
                elif operations[i] == 'LESSEQUAL':
                    if dict_request_values[key] <= values_operations[i][key]:
                        list_values.append(True)
                    else:
                        list_values.append(False)
                elif operations[i] == 'GREATER':
                    if dict_request_values[key] > values_operations[i][key]:
                        list_values.append(True)
                    else:
                        list_values.append(False)
                elif operations[i] == 'GREATEREQUAL':
                    if dict_request_values[key] >= values_operations[i][key]:
                        list_values.append(True)
                    else:
                        list_values.append(False)
                elif operations[i] == 'EQUAL':
                    if key == 'emails' or key == 'groups':
                        valid = False
                        for row in range(0, len(dict_request_values[key])):
                            if dict_request_values[key][row]['value'] == values_operations[i][key][row]['value']:
                                valid = True
                                break

                        if valid is True:
                            list_values.append(True)
                        else:
                            list_values.append(False)
                    else:
                        if dict_request_values[key] == values_operations[i][key]:
                            list_values.append(True)
                        else:
                            list_values.append(False)
            else:
                a = False
                for k in dict_request_values:
                    if 'User' in str(k):
                        try:
                            a = dict_request_values[k][key]
                        except KeyError:
                            pass
                list_values.append(a)
    return list_values

def validate_multiples_conditions(policy_row, dict_request_values):
    operations = []
    operations_conditions = []
    values_operations = []
    list_values = []
    
    for key3 in policy_row.keys():
        if ('AND' == key3) or ('NOT' == key3) or ('OR' == key3) or ('XOR' == key3):
            operations_conditions.append(key3)
        if isinstance(policy_row[key3], list):
            operations = []
            values_operations = []
            list_values = []
            for i in range(0, len(policy_row[key3])):
                for key2 in policy_row[key3][i].keys():
                    if ('AND' != key2) and ('NOT' != key2) and ('OR' != key2) and ('XOR' != key2):
                        operations.append(key2)
                        values_operations.append(policy_row[key3][i][key2])
                        aux_list_result = validate_operations(operations, values_operations, dict_request_values)
                        list_values = conditions_validator(operations_conditions[0], aux_list_result)
                    else:
                        operations_conditions.append(key2)
                        list_values = validate_multiples_conditions(policy_row[key3][i][key2], dict_request_values)
            return list_values           
        else:
            list_values = []
            for key in policy_row.keys():
                if ('AND' != key) and ('NOT' != key) and ('OR' != key) and ('XOR' != key):
                    aux = []
                    operations.append(key)
                    values_operations.append(policy_row[key])
                    aux = validate_operations(operations, values_operations, dict_request_values)
                    list_values = list_values + aux
                else:
                    aux_list_result = []
                    aux = []
                    aux_list_result = validate_multiples_conditions(policy_row[key], dict_request_values)
                    aux = conditions_validator(operations_conditions[0], aux_list_result)
                    list_values = list_values + aux
            return list_values

def conditions_validator(key, values):
    aux_list_result = []

    if key == 'AND':
        istrue = True
        for k in range(0, len(values)):
            if values[k] is False:
                istrue = False
        aux_list_result.append(istrue)
    elif key == 'OR':
        istrue = False
        for k in range(0, len(values)):
            if values[k] is True:
                istrue = True
        aux_list_result.append(istrue)
    elif key == 'XOR':
        count = 0
        for k in range(0, len(values)):
            if values[k] is True:
                count = count + 1
        
        if count == 1:
            aux_list_result.append(True)
        else:
            aux_list_result.append(False)
    elif key == 'NOT':
        for k in range(0, len(values)):
            if values[k] is True:
                aux_list_result.append(False)
            else:
                aux_list_result.append(True)
    
    return aux_list_result



