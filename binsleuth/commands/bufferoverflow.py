from binsleuth.basecommand import BaseCommand
from binsleuth.core.operation import Operation
import angr
import logging

logger =  logging.getLogger(__name__)

class BufferOverflowCommand(BaseCommand):


    def run(self,arguments):
        super(BufferOverflowCommand,self).run(arguments)
        project  = angr.Project("./examples/CADET_00001")
        Operation(project,**self.options).run()

    def extend_argparse(self,parser):
        """
        Overide to add extra arguments(see arparse docs)
        Extend the arparser with your own custom commands
        Parameters:
        argparser - the commands argumentparser
        """
        super(BufferOverflowCommand,self).extend_argparse(parser)
