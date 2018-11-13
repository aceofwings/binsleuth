from binsleuth.core.operation import Operation
from binsleuth.report import Report
import subprocess
import requests
import datetime
import logging
import json
import angr

logger = logging.getLogger(__name__)

class CVEChecker(Operation):

    project_settings = {}
    
    def __init__(self,project,config,**kwargs):
        self.sm = project.factory.simulation_manager(save_unconstrained=True,**kwargs)
        self.timeframe = config.timeframe
        self.file = config.file
        self.filename = self.file.split('/')[-1]
        self.raw_data = {}
        self.results = {}
        self.report = {}
        self.libs = []

    def run(self):
        logger.info("Grabbing libraries for %s" %(self.filename))
        self.get_libs()

        #if libraries found, look for CVEs
        if self.libs:
            logger.info("%s found" %(len(self.libs)))
            logger.info("Parsing database for CVEs")
            self.cve_search()

            #if CVEs found process them
            if self.raw_data:
                logger.info("Found CVEs for the following:")
                for key in self.raw_data:
                    print("\t\t\t\t\t\t\t\t\t\t" +  key)
                logger.info("processing data...")
                self.process_json()
                self.report_format()
                Report(self.report, build_d3js=True, build_json=True)
            else:
                logger.info("No CVEs found")
        else:
            logger.info("No libraries found")


    # Get the linked libraries
    def get_libs(self):
        project = angr.Project(self.file, load_options={})
        libs = project.loader.shared_objects
        
        #first item in list is filename
        del libs[self.filename]
        
        #convert orderedDict to list of library names
        for lib in libs:
            self.libs.append(lib)
    

    #parse cve database
    def cve_search(self):
        for lib in self.libs:

            #query databse for CVEs
            query = "search.py -o json -f "+lib

            #reformat to json
            info = '['+str(subprocess.check_output(query, shell=True))[2:-1].replace('\\n','\n').replace('\t','').replace('}\n{', '},\n{').replace('\\"','\"').replace("\\'","'")+']'
            
            #load json
            result = json.loads(info)
            if result:
                self.raw_data[lib]=result
                        
    def process_json(self):
        for key in self.raw_data:
            self.results[key] = {}
            for cve in self.raw_data[key]:
                d = cve['Published'].split(' ')[0]
                d = int(datetime.datetime.strptime(d, '%Y-%m-%d').strftime('%Y'))
                dateLimit = int(datetime.date.today().strftime('%Y')) - self.timeframe
                if d > dateLimit:
                    details = {}
                    details['id'] = cve['id']
                    details['Published'] = cve['Published']
                    details['summary'] = cve['summary']
                    self.results[key][cve['id']] = details
                    #print(details)

    def report_format(self):
        report = []
        for key in self.results:
            libs = {}
            libs["name"] = key
            cves = []
            for ID in self.results[key]:
                cve = {}
                summary = {}
                summaries = []
                cve["name"] = ID
                summary["name"] = self.results[key][ID]["summary"]
                summary["size"] = 300
                summaries.append(summary)
                cve["children"] = summaries
                cves.append(cve) 
            libs["children"] = cves 
            report.append(libs)
        self.report["name"] = "CVE Analysis"    
        self.report["children"] = report
