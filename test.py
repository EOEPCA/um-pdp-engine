import requests
#data will equal the mongo database of policies
#each key of the user_ownership dict would be the ownership_id of the users, and the value will be the list of resource_id the user owns
print("-------------------------------------------------------------------------------------")
print("Insert default policies as data: ")
print("-------------------------------------------------------------------------------------")
input("...")
print("\n")

data = {
    "user_ownership": {
        "userA": [
            "12345"
        ],
        "userB": [
            "12345",
            "67890"
        ],
        "userC": [
            "67890"
        ]
    }
}
#PUSH the policies data (PEP should automatically do this when registering resources)
headers = {'Accept': 'application/json'}
r = requests.put('http://127.0.0.1:8181/v1/data/myapi/res', headers=headers, json=data)
print("PUT Request, data inserted: "+str(r))
#GET Just to check the retrieval of policies
r = requests.get('http://127.0.0.1:8181/v1/data/myapi/res')
print("GET Request, data: "+ str(r))
print(r.text)
print("\n")
input("...")
print("-------------------------------------------------------------------------------------")
print("Insertion of ownership rule, that will allow access only to the owner of the resource")
print("The rules should be defined when deployinig OPA already but can be added new rules")
print("-------------------------------------------------------------------------------------")
input("...")
print("\n")
#PUSH the first rule, this should be defined within the source of the pdp and being pushed when staritng the OPA container its possible to add rules in execution time
with open('./policies.rego', 'rb') as f:
    data = f.read()
headers = {'Content-Type': 'text/plain'}
r = requests.put('http://127.0.0.1:8181/v1/policies/myapi', headers=headers, data=data)
print("PUT Request of the Rule: "+ str(r))
#Testing the first validation query
inputA = {
    "input":{
        "sub": "userA",
        "res_id": "12345"
    }
}
inputB= {
    "input":{
        "sub": "userB",
        "res_id": "67890"
    }
}
inputC= {
    "input": {
        "sub": "userC",
        "res_id": "12345"
    }
}
print("\n")
input("...")
print("-------------------------------------------------------------------------------------")
print("Check validation endpoint with input: "+ str(inputA))
print("Expected result: true")
print("-------------------------------------------------------------------------------------")
input("...")
print("\n")
headers = {'Accept': 'application/json'}
r = requests.post('http://127.0.0.1:8181/v1/data/myapi/policy/allow', headers=headers, json=inputA)
print("Validation response: "+str(r))
print(r.text)
print("\n")
input("...")
print("-------------------------------------------------------------------------------------")
print("Check validation endpoint with input: "+ str(inputB))
print("Expected result: true")
print("-------------------------------------------------------------------------------------")
input("...")
print("\n")
r = requests.post('http://127.0.0.1:8181/v1/data/myapi/policy/allow', headers=headers, json=inputB)
print("Validation Response: "+str(r))
print(r.text)
print("\n")
input("...")
print("-------------------------------------------------------------------------------------")
print("Check validation endpoint with input: "+ str(inputC))
print("Expected result: false")
print("-------------------------------------------------------------------------------------")
input("...")
r = requests.post('http://127.0.0.1:8181/v1/data/myapi/policy/allow', headers=headers, json=inputC)
print("Validation response: "+str(r))
print(r.text)
