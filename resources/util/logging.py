from enum import Enum


class LogLevel(Enum):
    """
		Define log level for stdout
	"""
    NORMAL = 0
    ALERT = 1
    DANGER = 2
    INFO = 3
    CLI = 4


class Logging(object):

    __fmt = '\033[%d;1m%s\033[0m'
    __colors = {
        'yellow': 33,
        'red': 31,
        'green': 32,
        'black': 30,
        'blue': 34,
        'cyan': 36,
        'd-underline': 21,
        'underline': 4,
        'focused': 5,
        'stroked': 9,
        'italic': 3,
        'normal': 1
    }

    @staticmethod
    def log(s, lvl):

        string = Logging.__build_str(s, lvl)
        print('{0}'.format(string), end='\n', flush=True)

    @staticmethod
    def __build_str(s, level):
        if isinstance(level, LogLevel):
            if level == LogLevel.NORMAL:
                return Logging.__fmt % (Logging.__colors.get('normal'), s)
            if level == LogLevel.ALERT:
                return Logging.__fmt % (Logging.__colors.get('yellow'), s)
            if level == LogLevel.DANGER:
                return Logging.__fmt % (Logging.__colors.get('red'), s)
            if level == LogLevel.INFO:
                return Logging.__fmt % (Logging.__colors.get('blue'), s)
            if level == LogLevel.CLI:
            	return Logging.__fmt % (Logging.__colors.get('green'), s)
        else:
            return s