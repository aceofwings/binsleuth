from binsleuth import logger
import logging
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

    loggingLevels = {1 : logging.INFO, 2 : logging.WARNING, 3 : logging.DEBUG}


    def __init__(self,args):
        self.arguments = args
        self.options = {}
        self.__parser = argparse.ArgumentParser(description=self.description)


    def __parse_arguments(self):
        return self.__parser.parse_args(self.arguments)

    #execute - executes the command by
    def execute(self):
        self.extend_argparse(self.__parser)
        self.run(self.__parse_arguments())

    def run(self,arguments):
        """
        Overide to add behavior to the command
        Perform various actions off arguments recieved
        Parameters:
        arguments - arguments recieved from command line excluding command prefix
        By default will attempt to find the launcher
        """
        if arguments.verbose < 4:
            logger.setLevel(self.loggingLevels[arguments.verbose])
        else:
            pass


    def extend_argparse(self,parser):
        """
        Overide to add extra arguments(see arparse docs)
        Extend the arparser with your own custom commands
        Parameters:
        argparser - the commands argumentparser
        """
        parser.add_argument('--verbose', '-v', default="1",help='verbosity of command (1=info,2=warning,3=debug)',type=int)
