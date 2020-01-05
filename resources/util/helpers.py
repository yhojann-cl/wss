import re

from os import path
from time import strftime, localtime, time
from pyfiglet import Figlet


class Helper(object):
    """
    Helper class for common runtime
    """
    def __init__(self):
        pass

    def langexists(self, file):
        return path.isfile(file) is True

    def getlang(self, buf, p, c=''):
        if isinstance(buf, dict):
            parent = buf.get(p)
            if isinstance(parent, dict):
                return parent.get(c)
            elif isinstance(parent, list):
                s = ""
                for _s in parent:
                    s += _s + '\n'
                return s
            else:
                return parent
        else:
            return None

    def version(self):
        version = {'major': 2, 'minor': 6}
        s = '.'
        return s.join(['%s' % v for (k, v) in version.items()])

    def dtos(self, args):
        s = ', '
        return s.join(['%s' % v for v in args.keys()])

    def gettime(self):
        return strftime('%b %e, %Y %T', localtime(time()))

    def ftext(self, s, font='slant'):
        f = Figlet(font=font)
        return f.renderText(s)

    def formatter(self, fmt, args):
        return fmt.format(*args)

    def ip_validate(self, mask):
        r = re.match(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$', mask)
        if r:
            return r.group()
        else:
            return None

    def port_validate(self, mask):
        r = re.match(r'^\d{4}$', mask)
        if r:
            return r.group()
        else:
            return None