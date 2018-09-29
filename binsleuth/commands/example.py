from binsleuth.basecommand import BaseCommand


class exampleCommand(BaseCommand):


    def run(self,arguments):
        print("running")

    def extendArgparse(self,parser):
        """
        Overide to add extra arguments(see arparse docs)
        Extend the arparser with your own custom commands
        Parameters:
        argparser - the commands argumentparser
        """
        pass
