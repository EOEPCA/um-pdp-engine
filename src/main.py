#!/usr/bin/env python3
from flask import Flask
from random import choice
from string import ascii_lowercase
import json

from policies.policies import policy_bp
from config import config_parser
#from policy_storage.py import Policy_Storage

#file_policy_1 = "standards/policy_template_ownership.json"
#file_policy_2 = "standards/policy_template_access_list.json"

#mongo = Policy_Storage()

#with open(file_policy_1) as json_file_1:
#    data1 = json.load(json_file_1)
#    mongo.insert_policy(data1)

#with open(file_policy_2) as json_file_2:
#    data2 = json.load(json_file_2)
#    mongo.insert_policy(data2)

config = config_parser.load_config()

app = Flask(__name__)
app.secret_key = ''.join(choice(ascii_lowercase) for i in range(30)) # Random key

# Register api blueprints (module endpoints)
app.register_blueprint(policy_bp, url_prefix="/policy")

app.run(
    debug=config["debug_mode"],
    port=config["port"],
    host=config["host"]
)
