

class Report(object):

    report_engine = None

    def __init__(self):
        pass

    @classmethod
    def generate_template(cls,template_name):
        return cls.report_engine.get_template(template_name)


    @classmethod
    def generate_html_file(cls, template_name, **kwargs):
        template = cls.generate_template(template_name)
        return template.render(**kwargs)

class ReportObj(object):
    """
    An object which all operations aggregate results into. Attributes defined here are common to all
    operation
    """

    def __init__(self, operation):
        self.operationName = operation.operation_name
        self.objName = operation.obj_name
