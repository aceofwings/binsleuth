import os
import angr
from angrutils import *
import logging

from angrutils.exploration import NormalizedSteps
from binsleuth.core.operation import Operation


# graphviz
# pydot
logger = logging.getLogger(__name__)

class ControlFlowGraph(Operation):

    project_settings = {'auto_load_libs' : False}

    operation_name = "CFG Analysis"


    def __init__(self,project,config,**kwargs):
        super(ControlFlowGraph, self).__init__(project, **kwargs)
        self.function_out_dir = config.function_graph_location
        self.cfg_loops_out_dir = config.loop_graph_location
        self.sm = project.factory.simulation_manager(save_unconstrained=True,**kwargs)
        self.project_name = os.path.basename(self.project.filename)

    def run(self):
        logger.info("Generating cfg graph for " + self.project_name)
        self.graph_cfg_loops(self.project_name)
        logger.info("Generate function graph")
        self.graph_functions()
        logger.info("Sucessfully generated graphs!")


    def static_cfg(self):
        """
        returns a CFGFast object
        """
        cfg = self.project.analyses.CFGFast()
        return cfg


    def dynamic_cfg(self):
       cfg = project.analyses.CFGEmulated(keep_state=True)
       return cfg


    def graph_cfg(self,cfg, outfile):
        plot_cfg(cfg, outfile, asminst=True, remove_imports=True, remove_path_terminator=True)

    def graph_functions(self):
        """
        generates a series of function transition graphs
        output dir is hard coded currently
        requires mkdir permission
        """
        cfg = self.static_cfg()

        OUT_DIR = os.path.join(self.function_out_dir,self.project_name)

        if not os.path.exists(OUT_DIR):
            try:
                os.mkdir(OUT_DIR)
            except Exception as err:
                print(str(err))
                return False

        for func in cfg.kb.functions.values():
            plot_func_graph(self.project, func.transition_graph, "%s/%s_cfg" % (OUT_DIR, func.name), asminst=True, vexinst=False)

        return True


    def graph_cfg_loops(self,outfile):
        """
        generates a cfg with paths highlighted
        """

        addr =  None

        try:
            addr = self.project.loader.main_object.get_symbol("main").rebased_addr
        except:
            addr = self.project.loader.main_object.entry

        start_state = self.project.factory.blank_state(addr=addr)
        start_state.stack_push(0x0)

        with hook0(self.project):
            cfg = self.project.analyses.CFGEmulated(fail_fast=True,
                                           starts=[addr],
                                           initial_state=start_state,
                                           context_sensitivity_level=5,
                                           keep_state=True,
                                           call_depth=100,
                                           normalize=True
                                          )
            simgr = self.project.factory.simgr()
            simgr.use_technique(NormalizedSteps(cfg))

            def find_loops(state):
              """

              """
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
