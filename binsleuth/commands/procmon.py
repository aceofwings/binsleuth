from binsleuth.basecommand import BaseCommand
from binsleuth.core.engine import Engine
from binsleuth.config import Config
from binsleuth.operations.proc import ProccessMonitor
import angr
import logging

logger =  logging.getLogger(__name__)

class ProcMonCommand(BaseCommand):

    description = "Dynamically Monitor the process"

    def __init__(self,args):
        super(ProcMonCommand,self).__init__(args)
        self.config = Config()

    def run(self,arguments):
        super(ProcMonCommand,self).run(arguments)
        if  arguments.file is not None:
            self.config.file = arguments.file

        md = Engine.build_operation(self.config, ProccessMonitor)
        md.run()

    def extend_argparse(self,parser):
        """
        Overide to add extra arguments(see arparse docs)
        Extend the arparser with your own custom commands
        Parameters:
        argparser - the commands argumentparser
        """
        super(ProcMonCommand,self).extend_argparse(parser)
        parser.add_argument('--file', '-f', default=None,help='file to which to run the command with')
