from os import path
from time import strftime, localtime, time
from pyfiglet import Figlet


def lang_exists(file):
    return path.isfile(file) is True


def get_lang_value(buf, p, c):
    if isinstance(buf, dict):
        parent = buf.get(p)
        if isinstance(parent, dict):
            return parent.get(c)
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


def dtos(args):
    s = ', '
    return s.join(['%s' % v for v in args.keys()])


def gettime():
    return strftime('%b %e, %Y %T', localtime(time()))


def figlet_text(s, font='slant'):
    f = Figlet(font=font)
    return f.renderText(s)


def formatter(fmt, args):
    return fmt.format(*args)
