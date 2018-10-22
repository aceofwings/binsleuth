import logging

logger = logging.getLogger(__name__)

class CVEChecker(Operation):

    project_settings = {}

    def __init__(self,project,config,**kwargs):
        self.sm = project.factory.simulation_manager(save_unconstrained=True,**kwargs)

    def run(self):
        logger.info("Grabbing file headers for {}")
        self.get_headers()
        logger.info("Parsing for CVEs")
        vulns = self.cve_search()
        if vulns:
            logger.info("Found CVEs for {}")
        else:
            logger.info("No CVEs found")

    def get_headers():
        pass

    def cve_search():
        vulns = {'some vuln':'found'}
        return vulns
