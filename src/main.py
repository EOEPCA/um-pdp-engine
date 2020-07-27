#!/usr/bin/env python3
from flask import Flask
from random import choice
from string import ascii_lowercase
import json

from policies.policies import policy_bp
from config import config_parser

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
