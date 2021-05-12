import pymongo
from pymongo import MongoClient
from ..src.custom_mongo import Mongo_Handler
import unittest
import mock

def mocked_mongo(*args, **kwargs):
    class MockResponse:
        def __init__(self):
            a=dict(policies= '')
            self.response = dict(policy_db= a)
        def response(self):
            return self.response
    return MockResponse().response


def mocked_list_dbs(*args, **kwargs):
    class MockResponse:
        def __init__(self):
            self.response = ['policy_db','other_db']
    return MockResponse().response

def mocked_find_id(*args, **kwargs):
    class MockResponse:
        def __init__(self):
            self.response=''
            if '5f22e074c6189d2a53c55d4e' in str(args[0]):
                b = ['////someScopes////']
                a= {
                    "resource_id": "202485830",
                    "rules": [{
                        "AND": [
                                {"EQUAL": {"user_name" : "admin"} }
                        ]
                    }]
                }
                self.response = {'_id': 'ObjectID(5f22e074c6189d2a53c55d4e)', 'name':'b','description':'blah', 'config': a,  'scopes':b}
    resp=MockResponse()
    return resp.response



def mocked_insert_mongo(*args, **kwargs):
    class MockResponse:
        def __init__(self):
            self.response = {'name': args[0], 'description': args[1], 'config': args[2], 'scopes': args[3]}
        def response(self):
            return self.response
    return MockResponse().response

class Mongo_Unit_Test(unittest.TestCase):
    # First, mock has to simulate http response, therefore a patch of get and post methods from requests library will be needed.
    
    @mock.patch('pymongo.MongoClient', side_effect=mocked_mongo)
    def test_mongo(self, mock_test,raise_for_status=None):
        mock_resp = mock.Mock()
        mock_resp.raise_for_status = mock.Mock()
        if raise_for_status:
            mock_resp.raise_for_status.side_effect = raise_for_status
        mongo = Mongo_Handler()
        self.assertEqual(str(mongo)[:-16], '<src.custom_mongo.Mongo_Handler object at')
    
   
    @mock.patch('pymongo.collection.Collection.find_one', side_effect=mocked_find_id)
    def test_find_mongo(self, mock_find_test,raise_for_status=None):
        mock_resp = mock.Mock()
        mock_resp.raise_for_status = mock.Mock()
        if raise_for_status:
            mock_resp.raise_for_status.side_effect = raise_for_status
        mongo = Mongo_Handler()
        a=mongo.get_policy_from_id('5f22e074c6189d2a53c55d4e')
        self.assertEqual(a, {'_id': 'ObjectID(5f22e074c6189d2a53c55d4e)', 'name': 'b', 'description': 'blah', 'config': {'resource_id': '202485830', 'rules': [{'AND': [{'EQUAL': {'user_name': 'admin'}}]}]}, 'scopes': ['////someScopes////']})

   
    @mock.patch('src.custom_mongo.Mongo_Handler.insert_policy', side_effect=mocked_insert_mongo)
    def test_insert_mongo(self, mock_insert_test,raise_for_status=None):
        mock_resp = mock.Mock()
        mock_resp.raise_for_status = mock.Mock()
        if raise_for_status:
            mock_resp.raise_for_status.side_effect = raise_for_status
        mongo = Mongo_Handler()
        b= {
            "resource_id": "202485830",
            "rules": [{
                "AND": [
                        {"EQUAL": {"user_name" : "admin"} }
                ]
            }]
        }
        c=['////someScopes////']
        j=mongo.insert_policy('a','b',b,c)
        self.assertEqual(j,{'name': 'a', 'description': 'b', 'config': {'resource_id': '202485830', 'rules': [{'AND': [{'EQUAL': {'user_name': 'admin'}}]}]}, 'scopes': ['////someScopes////']})
