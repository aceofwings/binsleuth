import argparse
import sys

class BaseCommand(object):
    """
    Provides basic template and behavior for how to write a command
    To add arguments to a command overide extendArgparse()
    To add custom behavior to a command overide run()
    """

    #commands alias
    alias = None
    description = None
    arguments = None


    def __init__(self,args):
        self.arguments = args
        self.__parser = argparse.ArgumentParser(description=self.description)


    def __parseArguments(self):
        return self.__parser.parse_args(self.arguments)

    #execute - executes the command by
    def execute(self):
        self.extendArgparse(self.__parser)
        self.run(self.__parseArguments())

    def run(self,arguments):
        """
        Overide to add behavior to the command
        Perform various actions off arguments recieved
        Parameters:
        arguments - arguments recieved from command line excluding command prefix
        By default will attempt to find the launcher
        """
        pass

    def extendArgparse(self,parser):
        """
        Overide to add extra arguments(see arparse docs)
        Extend the arparser with your own custom commands
        Parameters:
        argparser - the commands argumentparser
        """
        pass
