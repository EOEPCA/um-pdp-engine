from json import load, dump

CONFIG_FILE = "config/config.json"

def load_config() -> dict:
    """
    Parses and returns the config file

    Returns: dict
    """
    config = {}
    with open(CONFIG_FILE) as j:
        config = load(j)

    return config


def save_config(data: dict):
    """
    Saves updated config file
    """
    with open(CONFIG_FILE, 'w') as j:
        dump(data,j)
