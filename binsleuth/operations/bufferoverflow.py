from binsleuth.core.operation import Operation
import logging

logger = logging.getLogger(__name__)

class BufferOverflowOperation(Operation):

    project_settings = {}


    def __init__(self,project,config,**kwargs):
        self.sm = project.factory.simulation_manager(save_unconstrained=True,**kwargs)

    def run(self):
        logger.info("Finding Buffer overflow")

        while len(self.sm.unconstrained) == 0:
            self.sm.step()

        unconstrainedState = self.sm.unconstrained[0]
        crashing_input = unconstrainedState.posix.dumps(0)
        logger.info("BufferOverflow found " + crashing_input)
