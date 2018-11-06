#!/usr/bin/env python

from procSleuth import *
from staticSleuth import *
from report import *
from datetime import datetime

def main():

  static = StaticAnalyses('fauxware')
  static._d3js_hub()
  
  dynamic = ProcSleuth('firefox-esr')
  dynamic.run() 
  dynamic._d3js_data_hub()
 
 
  report = {
    "name": "Binsleuth Report - " + str(datetime.now()),
    "children": [
        static._report,
        dynamic._report
    ]
  }
  
  Report(report, build_d3js=True, build_json=True)
  
  
if __name__ == '__main__':
    main()  
  