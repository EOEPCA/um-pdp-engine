#!/usr/bin/env python3
from flask import Flask
from random import choice
from string import ascii_lowercase

from resources.resources import resource_bp
from config import config_parser

config = config_parser.load_config()

app = Flask(__name__)
app.secret_key = ''.join(choice(ascii_lowercase) for i in range(30)) # Random key

# Register api blueprints (module endpoints)
app.register_blueprint(resource_bp, url_prefix="/resource")


app.run(
    debug=config["debug_mode"],
    port=config["port"],
    host=config["host"]
)
