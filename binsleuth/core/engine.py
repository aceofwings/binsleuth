import angr

"""
Where tests will be executed and their results to be rendered into a format
desired by the user
"""

class Engine(object):

    def __init__(self,configuration):

        self.project = None
        self.config = configuration

        if isinstance(self.config.file, list):
            self.project = []
            for file in self.config.file:
                self.project.append(angr.Project(file))
            self.runner = MultiOperationRunner(self.config.operations, self.project)
        elif isinstance(self.config.file, basestring):
            self.runner = OperationRunner(self.config.file, self.config.operations)
        else:
            #Add custom exception
            raise Exception()

    def run(self):
        self.runner.runOperations()

    def close(self):
        """
        define soft closing operations here eg. stopping pending operations
        """
        pass


    def exit(self):
        """
        Prepare engine state for exit
        """
        pass

class OperationRunner(object):
    pendingOperations =  []
    finishedOperations = []

    def __init__(self,file,operations):
        for operation in operations:
            project = angr.Project(file, load_options=operation.project_settings)
            self.pendingOperations.append(operation(project,**{}))

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
