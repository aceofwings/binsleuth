from binsleuth.core.operation import Operation
from binsleuth.core.report import ReportObj
import logging
import angr

logger = logging.getLogger(__name__)


class StaticOperation(Operation):

    project_settings = {'auto_load_libs': False}
    operation_name = "Static Analysis"
    report_template = "staticana.html"
    obj_name = "staticdata"

    def __init__(self, project, config, **kwargs):
        super().__init__(project,**kwargs)
        self._cfg = self.project.analyses.CFG(fail_fast=True)
        self._function_dict = dict(self.project.kb.functions)
        self.arch = self.project.arch
        self.hard_coded = {}
        self.SIZE = 300


    def run(self):
        logger.info("Beginning Static Analysis")
        self.potential_hard_coded()
        self._d3js_functions()
        self._d3js_hub()

    def buffer_overflow(self):

        sim = self.project.factory.simulation_manager(save_unconstrained=True)

        while len(sim.unconstrained) == 0:
            sim.step()

        state = sim.unconstrained[0]

        stdin = state.posix.dumps(0)
        prompt = state.posix.dumps(1)
        print(stdin, prompt)

    def unmapped_memory(self):
        '''
          report values that lead to unmapped memory
          TODO: this is buggy on some binaries, I would avoid it for now
        '''
        logger.info("Finding unmapped memory")
        state = self.project.factory.entry_state(
            add_options={angr.options.STRICT_PAGE_ACCESS})

        sim = self.project.factory.simulation_manager(state)

        sim.explore()

        valids = []
        errors = {}

        for dead in sim.deadended:
            valids.append(repr(dead.posix.dumps(0)))

        for errored in sim.errored:
            stdin = errored.state.posix.dumps(0)
            prompt = errored.state.posix.dumps(1)
            errors[repr(stdin)] = (errored.error, prompt)
            # print("%s caused by %s at prompt %s" % (errored.error, repr(stdin), repr(prompt)))

        return (errors, valids)

    def potential_hard_coded(self):
        logger.info("Finding Potential Hard coded constants")
        fun_addrs = []
        for key in self._function_dict:
            try:
                mod_addr = int(hex(key), 16)
                fun_addrs.append(mod_addr)
            except:
                pass

        for address in fun_addrs:
            pg = self.project.factory.simgr()
            pg.explore(find=address)
            if pg.found:
                potential = pg.found[0].posix.dumps(0)
                prompt = pg.found[0].posix.dumps(1)
                if len(potential):
                    self.hard_coded[address] = (potential, prompt)

    def find_unconstrainedC(self):
        shellcode = bytes.fromhex(
            "6a68682f2f2f73682f62696e89e331c96a0b5899cd80")

        entry_state = self.project.factory.entry_state(
            add_options={so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY})

        sim = self.project.factory.simulation_manager(
            entry_state, save_unconstrained=True)

        exploitable_state = None

        while exploitable_state is None:

            sim.step()
            if len(sim.unconstrained) > 0:

                for uncon in sim.unconstrained:
                    if fully_symbolic(uncon, uncon.reg.pc):
                        exploitable_state = uncon
                        break

                sim.drop(stash='unconstrained')

        for buf_addr in find_symbolic_buffer(exploitable_state, len(shellcode)):

            memory = exploitable_state.memory.load(buf_addr, len(shellcode))
            sc_bvv = exploitable_state.solver.BVV(shellcode)

            if exploitable_state.satisfiable(extra_constraints=(memory == sc_bvv, exploitable_state.regs.pc == buf_addr)):
                exploitable_state.add_contstraints(memory == sc_bvv)
                exploitable_state.add_contstraints(ep.regs.pc == buf_addr)
                break

        print(exploitable_state.posix.dumps(0))

    def find_symbolic_buffer(state, length):
        '''
        dumb implementation of find_symbolic_buffer, looks for a buffer in memory under the user's
        control
        '''

        # get all the symbolic bytes from stdin
        stdin = state.posix.stdin

        sym_addrs = []
        for _, symbol in state.solver.get_variables('file', stdin.ident):
            sym_addrs.extend(state.memory.addrs_for_name(
                next(iter(symbol.variables))))

        for addr in sym_addrs:
            if check_continuity(addr, sym_addrs, length):
                yield addr

    def fully_symbolic(state, variable):
        '''
        check if a symbolic variable is completely symbolic
        '''

        for i in range(state.arch.bits):
            if not state.solver.symbolic(variable[i]):
                return False
        return True

    def _d3js_functions(self):

        final_functions = []

        for k, v in self._function_dict.items():
            final_functions.append(
                {
                    "name": "Function: " + str(v.name) + " " + str(hex(k)),
                    "children": [
                        {
                            "name": "Address: " + str(hex(k)),
                            "size": self.SIZE
                        },
                        {
                            "name": "Size: " + str(v.size) + " bytes",
                            "size": self.SIZE
                        },
                        {
                            "name": "Is returning: " + str(v.returning),
                            "size": self.SIZE
                        },
                        {
                            "name": "Is syscall: " + str(v.is_syscall),
                            "size": self.SIZE
                        },
                        {
                            "name": "Arguments",
                            "children": [
                                {
                                    "name": str(arg),
                                    "size": self.SIZE
                                } for arg in v.arguments
                            ]
                        },
                        {
                            "name": "Block info: ",
                            "children": [
                                {
                                    "name": "Block Addr: " + str(hex(block.addr)),
                                    "children": [
                                        {
                                            "name": "Size: " + str(block.size) + " bytes",
                                            "size": self.SIZE
                                        },
                                        {
                                            "name": "Disassembly:",
                                            "children": [
                                                {
                                                    "name": str(cmd),
                                                    "size": self.SIZE
                                                } for cmd in str(block.capstone).split("\n")
                                            ]
                                        }
                                    ]
                                } for block in v.blocks
                            ]
                        }
                    ]
                }
            )

        return final_functions

    def _d3js_hub(self):

        data = {
            "name": "Static Analysis",
            "children": [
                {
                    "name": "EXE: " + str(self.project.filename) + " " + str(self.arch),
                    "size": self.SIZE
                },
                {
                    "name": "Function Analysis",
                    "children": self._d3js_functions()
                },
                {
                    "name": "Potential hard coded data",
                    "children": [
                        {
                            "name": "Addr: " + str(hex(k)),
                            "children": [
                                {
                                    "name": "Data: " + repr(v[0]),
                                    "size": self.SIZE
                                },
                                {
                                    "name": "Prompt: " + repr(v[1]),
                                    "size": self.SIZE
                                }
                            ]
                        } for k, v in self.hard_coded.items()
                    ]
                },
                {
                    "name": "Error states",
                    "children": [
                        {
                            "name": "Error",
                            "children": [
                                {
                                    "name": "Error: " + str(err[0]),
                                    "size": self.SIZE
                                },
                                {
                                    "name": "Error input: " + str(cause),
                                    "size": self.SIZE
                                },
                                {
                                    "name": "Prompt: " + str(err[1]),
                                    "size": self.SIZE
                                }
                            ]
                        } for cause, err in self.unmapped_memory()[0].items()
                    ]
                }
            ]
        }

        self._report = data


    def report_obj(self):
            return StaticDataReport(self)

class StaticDataReport(ReportObj):
    def __init__(self,staticOperation):
        super().__init__(staticOperation)
        self.functions = staticOperation._function_dict
