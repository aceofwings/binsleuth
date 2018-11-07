from binsleuth.core.operation import Operation
import requests
import logging
import angr

logger = logging.getLogger(__name__)

class CVEChecker(Operation):

    project_settings = {}
    
    def __init__(self,project,config,**kwargs):
        self.sm = project.factory.simulation_manager(save_unconstrained=True,**kwargs)
        self.timeframe = config.timeframe
        self.file = config.file
        self.filename = self.file.split('/')[-1]
        self.results = {}

    def run(self):
        logger.info("Grabbing libraries for %s" %(self.filename))
        self.get_libs()
        logger.info("Parsing for CVEs")
        self.cve_search()
        if self.results:
            logger.info("Found CVEs for %s" %(self.results))
        else:
            logger.info("No CVEs found")


    # Get the linked libraries
    def get_libs(self):
        project = angr.Project(self.file, load_options={})
        libs = project.loader.shared_objects
        
        #first item in list is filename
        del libs[self.filename]
        
        #convert orderedDict to list of library names
        self.Libs = []
        for lib in libs:
            self.Libs.append(lib)
    
    #parse cve database
    def cve_search(self):
        for lib in self.Libs:
            URL = 'http://cve.circl.lu/api/browse/'+lib
            req = requests.get(URL)
            if req.json():
                self.results[lib]=req.json()
