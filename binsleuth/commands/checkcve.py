from binsleuth.basecommand import BaseCommand
from binsleuth.core.engine import Engine
from binsleuth.config import Config
from binsleuth.operations.cve import CVEChecker
import angr
import logging

logger = logging.getLogger(__name__)


class CheckCVECommand(BaseCommand):

    def __init__(self,args):
        super(CheckCVECommand,self).__init__(args)
        self.config = Config()

    def run(self,arguments):
        super(CheckCVECommand,self).run(arguments)
        if  arguments.file is not None:
            self.config.file = arguments.file

        check = Engine.build_operation(self.config,CVEChecker)
        check.run()

    def extend_argparse(self,parser):
        """
        Overide to add extra arguments(see arparse docs)
        Extend the arparser with your own custom commands
        Parameters:
        argparser - the commands argumentparser
        """
        super(CheckCVECommand,self).extend_argparse(parser)
        parser.add_arguement('--file', '-f', default=None, help='file to which to run the command with')
