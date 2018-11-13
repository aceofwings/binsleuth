from binsleuth.basecommand import BaseCommand
from binsleuth.core.engine import Engine
from binsleuth.config import Config
from binsleuth.operations.staticanalysis import StaticOperation
import angr
import logging

logger =  logging.getLogger(__name__)

class StaticCommand(BaseCommand):


    description = "Perform Static Analysis on a file"

    def __init__(self,args):
        super().__init__(args)
        self.config = Config()

    def run(self,arguments):
        super().run(arguments)
        if  arguments.file is not None:
            self.config.file = arguments.file

        md = Engine.build_operation(self.config, StaticOperation)
        md.run()

    def extend_argparse(self,parser):
        """
        Overide to add extra arguments(see arparse docs)
        Extend the arparser with your own custom commands
        Parameters:
        argparser - the commands argumentparser
        """
        super().extend_argparse(parser)
        parser.add_argument('--file', '-f', default=None,help='file to which to run the command with')
