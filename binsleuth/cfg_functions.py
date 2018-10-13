import angr
from angrutils import *

def static_cfg(filename):
  
  project = angr.Project(filename, load_options={'auto_load_libs':False})
  cfg = project.analyses.CFGFast()
  return cfg
  
def dynamic_cfg(filename):
  
  project = angr.Project(filename, load_options={'auto_load_libs':False})
  cfg = project.analyses.CFGEmulated(keep_state=True)
  return cfg
  
  
def graph_cfg(cfg, outfile):
  
  plot_cfg(cfg, outfile, asminst=True, remove_imports=True, remove_path_terminator=True)
  