import logging

logger = logging.getLogger(__name__)

class Operation(object):

    project_settings = {}

    def __init__(self,project,**kwargs):
        self.project = project
        self.sm = project.factory.simulation_manager(save_unconstrained=True,**kwargs)

    def run(self):
        pass


class OperationSet(object):
    """
    responsible for holding operations and keeping track of this start and finished
    states
    """
    pass
