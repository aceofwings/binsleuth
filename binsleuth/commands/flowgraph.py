from binsleuth.basecommand import BaseCommand
from binsleuth.core.engine import Engine
from binsleuth.config import Config
from binsleuth.operations.cfg import ControlFlowGraph
import angr
import logging

logger =  logging.getLogger(__name__)

class FlowGraphCommand(BaseCommand):

    def __init__(self,args):
        super(FlowGraphCommand,self).__init__(args)
        self.config = Config()

    def run(self,arguments):
        super(FlowGraphCommand,self).run(arguments)
        if  arguments.file is not None:
            self.config.file = arguments.file

        Engine(self.config).run()

    def extend_argparse(self,parser):
        """
        Overide to add extra arguments(see arparse docs)
        Extend the arparser with your own custom commands
        Parameters:
        argparser - the commands argumentparser
        """
        super(FlowGraphCommand,self).extend_argparse(parser)
