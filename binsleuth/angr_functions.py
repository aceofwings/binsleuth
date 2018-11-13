#!/usr/bin/env python

import angr
import logging
from angrutils import plot_cfg, plot_cdg, plot_cg, hook0

logging.getLogger('angr.manager').setLevel(logging.DEBUG)

def unmapped_memory(filename):

  '''
    report values that lead to unmapped memory
    TODO: this is buggy on some binaries, I would avoid it for now
  '''

  project = angr.Project(filename, load_options={"auto_load_libs": False})
  state = project.factory.entry_state(add_options={angr.options.STRICT_PAGE_ACCESS})

  sim = project.factory.simulation_manager(state)

  sim.explore()

  valids = []
  errors = {}

  for dead in sim.deadended:
    valids.append(repr(dead.posix.dumps(0)))

  for errored in sim.errored:
    stdin = err.state.posix.dumps(0)
    errors[repr(stdin)] = errored.error
    print("%s caused by %s" % (errored.error, repr(stdin)))

  return (errors, valids)
  
  
  
def graph_cdg(filename, outfile='cdg_graph', format='pdf'):

  ''' 
    purple edge: control dependency
    green edge : post-dominance relationship
  '''

  project = angr.Project(filename, load_options={'auto_load_libs':False, 'main_opts': {'base_addr':0x0}})
  
  try: addr = project.loader.main_object.get_symbol('main').rebased_addr
  except: addr = project.loader.main_object.entry
  
  start_state = project.factory.blank_state(addr=addr)
  start_state.stack_push(0x0)
  
  with hook0(project):
    cfg = project.analyses.CFGAccurate(fail_fast=True, starts=[addr], initial_state=start_state, context_sensitivity_level=2, keep_state=True, call_depth=100, normalize=True)
    
    
  cdg = project.analyses.CDG(cfg=cfg, start=addr)
  plot_cdg(cfg, cdg, outfile, pd_edges=True, format=format, cg_edges=True)
  

def graph_cg(filename, outfile='cg_graph', format='pdf'):

  ''' callgraph with debugging information '''
  
  project = angr.Project(filename, load_options={'auto_load_libs':False, 'main_opts': {'base_addr':0x0}})
  
  try: addr = project.loader.main_object.get_symbol('main').rebased_addr
  except: addr = project.loader.main_object.entry
  
  start_state = project.factory.blank_state(addr=addr)
  start_state.stack_push(0x0)
  
  with hook0(project):
    cfg = project.analyses.CFGAccurate(fail_fast=False, starts=[addr], context_sensitivity_level=1, enable_function_hints=False, keep_state=True, enable_advanced_backward_slicing=False, enable_symbolic_back_traversal=False,normalize=True)

  plot_cg(project.kb, 'cg_'+outfile, verbose=True, format=format)
  
# graph_cdg('ais3_crackme')
# graph_cg('ais3_crackme')
