#!/usr/bin/env python3
import pymongo
import json
from bson.objectid import ObjectId
from custom_mongo import Mongo_Handler
class Policy_Storage:

    def __init__(self, database:str):
        self.current_db=None
        self.available_db = ['mongodb']
        if database in self.available_db:
            if 'mongo' in database:
                self.current_db = Mongo_Handler()
        

    def get_policy_from_resource_id(self,resource_id):
        '''
            Finds the policy, attached to a resource by a resource_id given
            Returns the policy in json format
            Returns a list of policies to the resource_id asociado
        '''
        return self.current_db.get_policy_from_resource_id(resource_id)

    def get_policy_from_id(self, _id):
        '''
            Finds the policy by its id
            Returns the policy in json format
        '''
        return self.current_db.get_policy_from_id(_id)


    def policy_exists(self, _id=None, name=None):
        '''
            Check the existence of the resource inside the database by looking for the id or the name
            Input:  
                -_id: Search the _id inside the database
                -name:
            Return boolean result
        '''
        return self.current_db.policy_exists(_id, name)


    def insert_policy(self, name:str, description:str, config: dict, scopes: list):
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
        return self.current_db.insert_policy(name,description,config,scopes)

    def delete_policy(self, _id):
        '''
            Check the existence of the resource inside the database
            And deletes the document
        '''
        self.current_db.delete_policy(_id)
    
    def update_policy(self, _id, dict_data):
        '''
        Find the resource in the database by id, add or modify the changed values for the resource.
        '''
        return self.current_db.update_policy(_id,dict_data)
