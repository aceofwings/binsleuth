from binsleuth.basecommand import BaseCommand


class ExampleCommand(BaseCommand):


    def run(self,arguments):
        print("running")

    def extend_argparse(self,parser):
        """
        Overide to add extra arguments(see arparse docs)
        Extend the arparser with your own custom commands
        Parameters:
        argparser - the commands argumentparser
        """
        pass
