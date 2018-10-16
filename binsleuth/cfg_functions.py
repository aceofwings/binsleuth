#!/usr/bin/env python2

import os
import angr
from angrutils import plot_cfg, hook0
from angrutils.exploration import NormalizedSteps

# graphviz
# pydot
#TODO: make these Engine methods to access it's project attr?

def static_cfg(filename):
  
  ''' returns a CFGFast object '''
  project = angr.Project(filename, load_options={'auto_load_libs':False})
  cfg = project.analyses.CFGFast()
  return cfg


def dynamic_cfg(filename):

  project = angr.Project(filename, load_options={'auto_load_libs':False})
  # cfg = project.analyses.CFGEmulated(keep_state=True)
  cfg = project.analyses.CFGAccurate(keep_state=True)
  return cfg


def graph_cfg(cfg, outfile):
  
  plot_cfg(cfg, outfile, asminst=True, remove_imports=True, remove_path_terminator=True)
  

def graph_functions(filename):
 
  ''' generates a series of function transition graphs
	output dir is hard coded currently
	requires mkdir permission
  '''
  
  project = angr.Project(filename, load_options={'auto_load_libs':False})
  cfg = project.analyses.CFGFast()
  #cfg = static_cfg(filename)
  
  OUT_DIR = "function_graphs"
  
  if not os.path.exists(OUT_DIR):
	try: os.mkdir(OUT_DIR)
	except Exception as err:
	  print(str(err))
	  return False
  
  for func in cfg.kb.functions.values():
	plot_func_graph(project, func.transition_graph, "%s/%s_cfg" % (OUT_DIR, func.name), asminst=True, vexinst=False)
  
  return True
  

def graph_cfg_loops(filename, outfile):

  #TODO: test this, integrate with Engine?
  ''' generates a cfg with paths highlighted '''
  
  project = angr.Project(filename, load_options={'auto_load_libs':False})
  
  addr = project.loader.main_object.get_symbol("main").rebased_addr
  #except: addr = project.loader.main_object.entry
  
  start_state = project.factory.blank_state(addr=addr)
  start_state.stack_push(0x0)
  
  with hook0(project):
	cfg = project.analyses.CFGAccurate(fail_fast=True,
									   starts=[addr],
									   initial_state=start_state,
									   context_sensitivity_level=5,
									   keep_state=True,
									   call_depth=100,
									   normalize=True
									  )

  start_state = project.factory.blank_state(addr=addr, add_options={angr.sim_options.CONSERVATIVE_READ_STRATEGY} | angr.sim_options.resilience_options)
  start_state.stack_push(0x0)
  simgr = project.factory.simgr(start_state)
  simgr.use_technique(NormalizedSteps(cfg))
  
  def find_loops(state):
  
	last = state.history.bbl_addrs[-1]
	count = 0
	for addr in state.history.bbl_addrs:
	  if addr ==  last:
		count += 1 
	return count > 1
	
  def step_func(sim):
  
	sim.stash(filter_func=find_loops, from_stash='active', to_stash='looping')
	sim.stash(filter_func=lambda state: state.addr == 0, from_stash='active', to_stash='found')
	return sim
	
  simgr.run(step_func=step_func, until=lambda sim: len(sim.active) == 0, n=100)
  
  for stash in simgr.stashes:
	c = 0
	for state in simgr.stashes[stash]:
	  plot_cfg(cfg,
			   "%s_cfg_%s_%d" % (outfile, stash, c), 
			   state=state,
			   asminst=True,
			   vexinst=False,
			   debug_info=False,
			   remove_imports=True, 
			   remove_path_terminator=True
			  )
	  c += 1

graph_cfg_loops('ais3_crackme', 'crack')
graph_functions('ais3_crackme')