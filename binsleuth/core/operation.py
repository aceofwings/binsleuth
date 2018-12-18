import logging
from binsleuth.core.report import Report, ReportObj

logger = logging.getLogger(__name__)

class Operation(object):
    """
    An operation  defines the neccessary functions needed to be implemented for the engine to run
    the defined  functionality
    """
    #Any project settings that will be used by the engine when establishing the simulation_manager for
    #the operation
    project_settings = {}
    #The name of the operation to show up on report
    operation_name = "Default Operation Name"
    #Used by the engine to key track of unique operations. Must be unique from all other operations
    obj_name  = "Default Object Name"

    def __init__(self,project,**kwargs):
        self.project = project
        self.sm = project.factory.simulation_manager(save_unconstrained=True,**kwargs)

    def run(self):
        """
        Engine calls this. Put custom functionality in here.
        """
        pass


    def report_obj(self):
        """
        The object which the engine will use to render results. The object should consist of only data from the operation.
        """
        return ReportObj(self)

class OperationSet(object):
    """
    responsible for holding operations and keeping track of this start and finished
    states
    """
    pass
