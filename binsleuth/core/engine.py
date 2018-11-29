import angr
import logging
import os
from jinja2 import Environment, PackageLoader, select_autoescape
from binsleuth.core.report import Report

"""
Where tests will be executed and their results to be rendered into a format
desired by the user
"""



logger = logging.getLogger(__name__)

class Engine(object):

    def __init__(self,configuration):

        self.project = None
        self.config = configuration

        if isinstance(self.config.file, list):
            self.project = []
            for file in self.config.file:
                self.project.append(angr.Project(file))
            self.runner = MultiOperationRunner(self.config.operations, self.project)
        elif isinstance(self.config.file, str):
            self.runner = OperationRunner(self.config.file, self.config)
        else:
            #Add custom exception
            raise Exception()

        Report.report_engine = self.jinja_env()

    def run(self):
        self.runner.runOperations()
        self.close()

    def close(self):
        """
        define soft closing operations here eg. stopping pending operations
        """
        logger.info("Generating report")
        reports = {"reports" : {}}

        reports['operations'] =  self.runner.finishedOperations
        reports['unfinishedOperations'] = self.runner.pendingOperations
        reports['fileName'] = self.config.file

        if self.config.generate_reports:
            for  finish_op in self.runner.finishedOperations:
                reports['reports'][finish_op.obj_name] = finish_op.report_obj()

        report = Report.generate_html_file("base.html",**reports)

        with open(os.path.join(self.config.report_dir,"info.html"), "w") as fh:
            fh.write(report)

        self.exit()


    def exit(self):
        """
        Prepare engine state for exit
        """
        pass

    @classmethod
    def build_operation(cls, config, operation_class):
        """
        Build an operation to be run without having to creating an engine
        """
        return operation_class(angr.Project(config.file, load_options=operation_class.project_settings), config, **{})

    def jinja_env(self):
        """The Jinja2 environment used to load templates."""
        return self.create_jinja_environment()

    def create_jinja_environment(self):
        return Environment(
            loader=PackageLoader('binsleuth', 'templates'),
            autoescape=select_autoescape(['html', 'xml'])
            )


class OperationRunner(object):
    """
    Responsible for preparing and running the operations done to a file
    """
    pendingOperations =  []
    finishedOperations = []


    def __init__(self,file,config):
        """
        file - the filename/location
        operations - list of operation classes to perform on file
        config - configuration settings from config.py
        """
        for operation in config.operations:
            project = angr.Project(file, load_options=operation.project_settings)
            op = operation(project,config,**{})
            self.pendingOperations.append(op)

    def runOperations(self):
        """
        Override to add custom behavior to
        """
        for poperation in self.pendingOperations:
            poperation.run()
            self.finishedOperations.append(poperation)






class MultiOperationRunner(object):
    """
    When the user inputs multiple binaries they want to run at once
    """
    pass
