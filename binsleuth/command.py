import argparse
import os
import pkgutil
import inspect
from binsleuth import __VERSION__
from binsleuth import commands
from importlib import import_module

#Package where commands are located
def build_command_parsaer():
    DESCRIPTION = "Tools for running Binary Analysis"
    parser = argparse.ArgumentParser(prog='Binsleuth',description=DESCRIPTION, add_help=False)
    parser.PACKAGE = "binsleuth.commands"
    parser.add_argument('--commands', action='help', default=argparse.SUPPRESS,
                       help='list the commands available')
    parser.add_argument('--version', action='version', version='%(prog)s ' + __VERSION__)
    parser.listOfCommands = {}

    modules = pkgutil.iter_modules([os.path.dirname(commands.__file__)])
    for module in modules:
        parser.listOfCommands[module[1]] = import_module('.' + module[1], parser.PACKAGE)

    parser.add_argument('service', choices=parser.listOfCommands.keys())

    return parser

def command_line():
    '''
    Loads all available command namespaces from the commands directory.
    After loading all modules it will take the first argument and match it with
    a namspace.
    '''
    parser = build_command_parsaer()
    arg, options = parser.parse_known_args()
    commandNamespace = parser.listOfCommands[arg.service]

    try:
        execute_command(arg,options,commandNamespace)
    except ClassNonExistent as e:
        print(str(e) + " " + e.errors)

def execute_command(arg,options,namespace):
    """
    execute the class with the given namespace. It will look for a particular structucture
    where commands must be a subclass of binsleuthCommand and have the following name
    **name**Command
    """

    members = inspect.getmembers(namespace, inspect.isclass)
    #Attempt to find the class definition
    commandDefiniton = list(filter(lambda name: name[0].upper() == arg.service.upper() + "COMMAND" , members))

    if not commandDefiniton:
        raise ClassNonExistent("Could not find the command class", arg.service.capitalize() + "Command")

    command = getattr(namespace, commandDefiniton[0][0])
    command(options).execute()

class ClassNonExistent(Exception):
    """
    Raised if the command passed does not exist
    """
    def __init__(self, message, errors):
        super().__init__(message)
        self.errors = errors
