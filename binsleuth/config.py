

from binsleuth.operations.bufferoverflow import BufferOverflowOperation
from binsleuth.operations.filemetadata import  FileMetaData

class Config(object):
    """
    Python config file for project. If no config file is present then this then
    framework will default to this
    """
    operations = [FileMetaData, BufferOverflowOperation]

    """
    Can be a single string value or an array of string values
    representing file paths

    """
    file  = "./examples/CADET_00001"