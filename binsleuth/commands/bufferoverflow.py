from binsleuth.basecommand import BaseCommand
from binsleuth.core.engine import Engine
from binsleuth.config import Config
import angr
import logging

logger =  logging.getLogger(__name__)

class BufferOverflowCommand(BaseCommand):

    def __init__(self,args):
        super(BufferOverflowCommand,self).__init__(args)
        self.config = Config()

    def run(self,arguments):
        super(BufferOverflowCommand,self).run(arguments)
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
        super(BufferOverflowCommand,self).extend_argparse(parser)
        parser.add_argument('--file', '-f', default=None,help='file to which to run the command with')
