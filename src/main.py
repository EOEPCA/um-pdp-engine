#!/usr/bin/env python3
from random import choice
from string import ascii_lowercase
from flask import Flask

from config import loader
from policies.validator import policy_validator_bp
from policies.manager import policy_manager_bp

oidc_client, g_config = loader.initial_setup()

app = Flask(__name__)
app.secret_key = ''.join(choice(ascii_lowercase) for i in range(30)) # Random key

# Register api blueprints (module endpoints)
app.register_blueprint(policy_validator_bp, url_prefix="/policy")
app.register_blueprint(policy_manager_bp(oidc_client))


app.run(
    debug=g_config["debug_mode"],
    port=g_config["port"],
    host=g_config["host"]
)


        