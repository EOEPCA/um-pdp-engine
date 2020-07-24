#!/usr/bin/env python3
import pymongo
import json

class Policy_Storage:

    def __init__(self, **kwargs):
        self.modified = []
        self.__dict__.update(kwargs)
        self.myclient = pymongo.MongoClient('localhost', 27017)
        self.db = self.myclient["policy_db"]

    def create_policy_json(self, name: str, description:str, id:str, policyCFG: list, scopes: list):
        '''
        Creates a template of policy to insert in the database
        '''
        plcy= {
            "name" : name,
            "description" : description,
            "id" : id,
            "policyCFG" : policyCFG,
            "scopes" : scopes
        }
        y = json.dumps(plcy)
        return plcy
        

    def get_policy_from_resource_id(self,resource_id):
        '''
            Finds the policy, attached to a resource by a resource_id given
            Returns the policy in json format
        '''
        
        col= self.db['policies']
        myquery = { "resource_id": resource_id }
        found=col.find_one(myquery)
        if found:
            return found
        else: return None

    def get_policy_from_id(self, id):
        '''
            Finds the policy by its id
            Returns the policy in json format
        '''
        
        col= self.db['policies']
        myquery = { "id": id }
        found=col.find_one(myquery)
        if found:
            return found
        else: return None


    def policy_exists(self, id):
        '''
            Check the existence of the resource inside the database
            Return boolean result
        '''
        col = self.db['policies']  
        myquery = { "id": id }
        if col.find_one(myquery): return True
        else: return False

    def insert_policy(self, name: str, description: str, id: str,cfg: list, scopes:list ):
        '''
            Generates a document with:
                -NAME: Name generic for the policy
                -DESCRIPTION: Custom description for the policy pourpose
                -ID: Unique ID for the policy
                -POLICY_CFG: Custom rules for the policy configuration
                -SCOPES: List of scopes for the policy
            Check the existence of the policy to be registered on the database
            If alredy registered will update the values
            If not registered will add it and return the query result
        '''
        dblist = self.myclient.list_database_names()
        # Check if the database alredy exists
        if "policy_db" in dblist:
            col = self.db['policies']
            myres = self.create_policy_json(name,description, id, cfg, scopes)
            # Check if the resource is alredy registered in the collection
            x=None
            if self.policy_exists(id):
                x= self.update_policy(myres)
            # Add the resource since it doesn't exist on the database
            else:
                x = col.insert_one(myres)
            return x
        else:
            col = self.db['policies']
            myres = self.create_policy_json(name,description, id, cfg, scopes)
            print(type(myres))
            print(myres)
            x = col.insert_one(myres)
            return x

    def delete_policy(self, id):
        '''
            Check the existence of the resource inside the database
            And deletes the document
        '''
        if self.policy_exists(id):
            col = self.db['policies']
            myquery = { "id": id }
            a= col.delete_one(myquery)
    
    def update_policy(self, dict_data):
        '''
        Find the resource in the database by id, add or modify the changed values for the resource.
        '''
        id=dict_data['id']
        col = self.db['policies']
        myquery= {'id': id}
        new_val= {"$set": dict_data}
        x = col.update_many(myquery, new_val)
        return


a = Policy_Storage()
a.insert_policy('juan', '', '19283737171-30', ['hola'] ,['scopeAuthentico'])
a.insert_policy('alvivo', '', '19283737171-313', ['hola'] ,['scopeAuthentico2'])
n=a.get_policy_from_id('19283737171-313')
print(n)
a.delete_policy('19283737171-300')