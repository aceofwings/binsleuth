===============================
Binsleuth's Command Structure
===============================
The command structure allows for rapid feature integration with command line interface(CLI). Commands that interface with different parts of bin-sleuth can be developed in their own modules. To develop your own commands you **must** follow these simple rules.

1. Commmands **must** subclass BaseCommand
2. Class name must follow the structure <Name>Command. Eg FullScanCommand.
3. Commands must be placed with the commands module within the binsleuth project.

Once you have established your command class you can override the following methods

.. code-block:: python

      def run(self,arguments):


Called when the command is executed. Passes the arguments from the extend argparse function
to then be used in executing some task

.. code-block:: python

      def extendArgparse(self,parser):


Add your argument parsing by adding onto the argparse object. If you are not familiar with python's argparse, please visit
https://docs.python.org/3/library/argparse.html

You can call your following command by the name you have defined for it. Eg if you have defined a command called FullScanCommand
you can run the following


.. code-block:: bash

      $ binsleuth fullscan
