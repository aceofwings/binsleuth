from binsleuth.operations.bufferoverflow import BufferOverflowOperation
from binsleuth.operations.filemetadata import  FileMetaData
from binsleuth.operations.cfg import ControlFlowGraph
from binsleuth.operations.staticanalysis import StaticOperation
from binsleuth.operations.cve import CVEChecker

class Config(object):
    """
    Python config file for project. If no config file is present then this then
    framework will default to this
    """

    operations = [FileMetaData, ControlFlowGraph, BufferOverflowOperation, CVEChecker,ControlFlowGraph]

    """
    Can be a single string value or an array of string values
    representing file paths

    """
    file  = "./examples/fauxware"

    timeframe = 1

    function_graph_location = "function_graphs"

    loop_graph_location = ""

    """ Location of templates used by template engine """
    report_dir = './reports'


    """ Generate html reports """
    generate_reports = True
