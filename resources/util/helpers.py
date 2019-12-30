from os import path
from time import strftime, localtime, time
from pyfiglet import Figlet

def lang_exists(file):
    return path.isfile(file) is True


def get_param_value(buf, p, c):
    if isinstance(p, dict):
        parent = buf.get(p)
        if isinstance(parent, dict):
            return parent.get(child)
        elif isinstance(parent, list):
            s = ", "
            s.join(parent)
            return s
        else:
            return parent
    else:
        return None


def version():
    version = {'major': 2, 'minor': 6}
    s = '.'
    return s.join(['%s' % v for (k, v) in version.items()])

def gettime():
	return strftime('%b %e, %Y %T', localtime(time()))

def figlet_text(s, font='slant'):
	f = Figlet(font=font)
	return f.renderText(s)
