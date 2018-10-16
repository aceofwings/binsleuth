import logging

logger = logging.getLogger(__name__)

class Operation(object):

    project_settings = {}

    def __init__(self,project,**kwargs):
        self.project = project
        self.sm = project.factory.simulation_manager(save_unconstrained=True,**kwargs)

    def run(self):
        logger.info("Finding Buffer overflow")

        while len(self.sm.unconstrained) == 0:
            self.sm.step()

        unconstrainedState = self.sm.unconstrained[0]
        crashing_input = unconstrainedState.posix.dumps(0)
        logger.info("BufferOverflow found " + crashing_input)


class OperationSet(object):
    """
    responsible for holding operations and keeping track of this start and finished
    states
    """
    pass
