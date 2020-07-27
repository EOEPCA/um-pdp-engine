#!/usr/bin/env python3
import time
from policy_storage import Policy_Storage

def main():
    #example rule policy a:
    a= {
        "resource_id": "20248583",
        "rules": [{
            "OR": [
                    {"EQUAL": {"user_name" : "mami"} },
                    {"EQUAL": {"user_name" : "admin"} }
            ]
        }]
    }
    #example rule policy a:
    b= {
        "resource_id": "202485830",
        "rules": [{
            "AND": [
                    {"EQUAL": {"user_name" : "admin"} }
            ]
        }]
    }
    #instance
    mongo = Policy_Storage()
    #register policy:
    mongo.insert_policy(name='name1', description= 'description very descriptive', config= a, scopes=['private'])
    #register policy:
    mongo.insert_policy('name2', 'description very descriptive', a, ['public', 'Authenticated'])
    #register policy:
    mongo.insert_policy('name3', 'description very descriptive', a, ['public', 'Authenticated'])
    #get the list of policies associated to the resource_id:
    list_of_policies = mongo.get_policy_from_resource_id('20248583')
    #find the id for a known policy name (this will probably be private)
    policy_id = mongo.get_id_from_name('name3')
    #return the policy in dict format with the policy_id as input
    policy_to_modify = mongo.get_policy_from_id(policy_id)
    #change the values of the policy retrieved above
    n['name'] = 'new_name'
    n['description'] = 'new description'
    n['config']= b
    #updates the policy by the _id given
    mongo.update_policy(n['_id'], n)
    #delete the policy matched by id
    myId=mongo.get_id_from_name('name2')
    mongo.delete_policy(myId)
    #infinite loop for the container to keep running in testing environment
    while True: 
        time.sleep(1000)
if __name__ == "__main__":
    main()