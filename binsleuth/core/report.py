from binsleuth.config import Config



class Report(object):

    report_engine = None

    def __init__(self):
        self.temeplate_dir = Config.templates_dir


    @classmethod
    def generate_template(cls,template_name):
        return cls.report_engine.get_template(template_name)


    @classmethod
    def generate_html_file(cls, template_name, **kwargs):
        template = cls.generate_template(template_name)
        return template.render(**kwargs)
