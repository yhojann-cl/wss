import re
import socket

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
        if mask is None:
            return None
        else:
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

    def resolve_dns(self, address):
        if self.ip_validate(address) is not None:
            return [address]
        else:
            response = []
            try:
                dns = socket.gethostbyname_ex(address)
                for record in dns:
                    if (isinstance(record, list) and (len(record) > 0)):
                        response += record
                    else:
                        response.append(record)
                response = list(filter(lambda v: isinstance(v, str), response))
                
                return response
            except Exception as e:
                return [address]

    def hostname_validate(self, host):
        if host is None:
            return None
        elif not isinstance(host, str):
            return None
        else:
            if host.count('.') >= 1:
                return host
            else:
                return None
