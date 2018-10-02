

from binsleuth.core import Operation

class Config(object):
    """
    Python config file for project. If no config file is present then this then
    framework will default to this
    """

    operations = [Operation]
