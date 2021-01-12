import requests
import json
import unittest

class PDPResourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.g_config = {}
        with open("../src/config/config.json") as j:
            cls.g_config = json.load(j)

        cls.PDP_HOST = "http://"+cls.g_config["host"]
        cls.PDP_PORT = cls.g_config["port"]
    
    #This test case assumes v0.3 of the PDP engine
    def test_resource(self):
        reply = requests.get(self.PDP_HOST+":"+self.PDP_PORT+"/swagger-ui")
        self.assertEqual(200, reply.status_code)
        print("=================")
        print("Get Web Page: 200 OK!")
        print("=================")
        page = reply.text
        page_title = page[page.find("<title>")+7: page.find('</title>')]
        print("Get Page Title found: " + page_title)
        self.assertEqual("Policy Decision Point Interfaces", page_title)
        print("Get Page: OK!")

if __name__ == '__main__':
    unittest.main()