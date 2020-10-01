#!/usr/bin/env python3
import pymongo
import json
from bson.objectid import ObjectId

class MongoHandler:

    def __init__(self, **kwargs):
        self.modified = []
        self.__dict__.update(kwargs)
        
        self.myclient = pymongo.MongoClient('localhost', 27017)
        self.db = self.myclient["policy_db"]

    @classmethod
    def create_policy_json(self, name: str, description:str, ownership_id: str, policy_cfg: list, scopes: list):
        '''
        Creates a template of policy to insert in the database
        '''
        plcy= {
            "name" : name,
            "description" : description,
            "ownership_id" : ownership_id,
            "config" : policy_cfg,
            "scopes" : scopes
        }
        y = json.dumps(plcy)
        return plcy

    def get_id_from_name(self, name:str):
        col= self.db['policies']
        myquery={'name': name}
        found=col.find_one(myquery)
        if found:
            return found['_id']
        else: 
            return None

    @classmethod
    def parse_id(self, _id):
        my_id=None
        if 'ObjectId' in str(_id):
            if type(_id) == str:
                a=_id[_id.find("(")+1:_id.find(")")]
                my_id = ObjectId(str(a))
            else:
                my_id = _id
        else:
            my_id = ObjectId(_id)
        return my_id

    def get_policy_from_resource_id(self,resource_id):
        '''
            Finds the policy, attached to a resource by a resource_id given
            Returns the policy in json format
            Returns a list of policies to the resource_id asociado
        '''
        result= []
        col= self.db['policies']
        myquery = { "config.resource_id": resource_id }
        found=col.find(myquery)
        if found:
            for i in found:
                result.append(i)
            return result
        else: 
            return None

    def get_policy_from_id(self, _id):
        '''
            Finds the policy by its id
            Returns the policy in json format
        '''
        col= self.db['policies']
        my_id=self.parse_id(_id)
        myquery= {'_id': my_id}
        found=col.find_one(myquery)
        if found:
            return found
        else: 
            return None


    def policy_exists(self, _id=None, name=None):
        '''
            Check the existence of the resource inside the database by looking for the id or the name
            Input:  
                -_id: Search the _id inside the database
                -name:
            Return boolean result
        '''
        col = self.db['policies']  
        if _id is not None:
            if self.get_policy_from_id(_id) is not None: 
                return True
            else: 
                return False
        elif name is not None:
            myquery = { "name": name }
            if col.find_one(myquery): 
                return True
            else: 
                return False
        else:
            return False
            
    def verify_uid(self, policy_id, uid):
        col = self.db['policies']
        try:
            myquery = {"_id": ObjectId(policy_id), "ownership_id": uid }
            a= col.find_one(myquery)
            if a:                
                return True
            else: 
                return False
        except:
            print('no policy with that UID associated')
            return False

    def insert_policy(self, name:str, description:str, ownership_id: str, config: dict, scopes: list):
        '''
            Generates a document with json format (name: str, description: str, id: str,cfg: dict, scopes:list ): 
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
            myres = self.create_policy_json(name,description, ownership_id, config, scopes)
            x=None
            if self.policy_exists(name=name):
                my_id = self.get_id_from_name(name)
                x= self.update_policy(my_id, myres)
                return x
            # Add the resource since it doesn't exist on the database
            else:
                x = col.insert_one(myres)
                return 'New Policy with ID: ' + str(x.inserted_id)
        else:
            col = self.db['policies']
            myres = self.create_policy_json(name,description, ownership_id, config, scopes)
            x = col.insert_one(myres)
            return 'New Policy with ID: ' + str(x.inserted_id)

    def delete_policy(self, _id):
        '''
            Check the existence of the resource inside the database
            And deletes the document
        '''
        if self.policy_exists(_id=_id):
            col = self.db['policies']
            my_id=self.parse_id(_id)
            myquery = { "_id": my_id }
            a= col.delete_one(myquery)
    
    def update_policy(self, _id, dict_data):
        '''
        Find the resource in the database by id, add or modify the changed values for the resource.
        '''
        col = self.db['policies']
        my_id = self.parse_id(_id)
        if self.policy_exists(_id=_id):
            myquery= {'_id': my_id}
            new_val= {"$set": dict_data}
            x = col.update_many(myquery, new_val)
            if x.modified_count == 1:
                return 'Updated'
            elif x.modified_count == 0:
                return 'No changes made'
            return str(x.modified_count)
        else:
            return print('Can not update the policy, it does not exist')
             
