import json
from locale import getdefaultlocale


def get_locale():
    __lang = getdefaultlocale()[0].split('_')[0].lower()
    return str(__lang)


def lang_from_path(path):
    with open(path, 'r') as f:
        try:
            return json.load(f)
        except Exception as e:
        	pass
    return None
