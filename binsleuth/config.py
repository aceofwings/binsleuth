from binsleuth.operations.bufferoverflow import BufferOverflowOperation
from binsleuth.operations.filemetadata import  FileMetaData
from binsleuth.operations.cfg import ControlFlowGraph

class Config(object):
    """
    Python config file for project. If no config file is present then this then
    framework will default to this
    """

    operations = [ControlFlowGraph]

    """
    Can be a single string value or an array of string values
    representing file paths

    """
    file  = "./examples/fauxware"
