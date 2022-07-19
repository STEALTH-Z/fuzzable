"""
angr.py

    Fallback disassembly backend, most likely for headless analysis.
"""
import angr
from angr.knowledge_plugins.functions.function import Function
from angr.procedures.definitions.glibc import _libc_decls

from . import AnalysisBackend, AnalysisMode, Fuzzability
from ..metrics import CallScore
from ..log import log

# TODO: inherit angr.Analysis
class AngrAnalysis(AnalysisBackend):
    def __init__(self, target: angr.Project, mode: AnalysisMode):
        super().__init__(target, mode)

        log.debug("Doing initial CFG analysis on target")
        self.cfg = self.target.analyses.CFGFast()

    def __str__(self) -> str:
        return "angr"

    def run(self) -> Fuzzability:
        log.debug("Iterating over functions")
        for _, func in self.cfg.functions.items():
            name = func.name

            if self.skip_analysis(func):
                log.warning(f"Skipping {name} from fuzzability analysis.")
                self.skipped += 1
                continue

            # if recommend mode, filter and run only those that are top-level
            if self.mode == AnalysisMode.RECOMMEND and not self.is_toplevel_call(func):
                continue

            log.info(f"Conducting fuzzability analysis on function symbol '{name}'")
            score = self.analyze_call(name, func)
            self.scores += [score]

        return super()._rank_fuzzability(self.scores)

    def analyze_call(self, name: str, func: Function) -> CallScore:
        stripped = "sub_" in name

        # no need to check if no name available
        # TODO: maybe we should run this if a signature was recovered
        fuzz_friendly = False
        if not stripped:
            log.debug(f"{name} - checking if fuzz friendly")
            fuzz_friendly = AngrAnalysis.is_fuzz_friendly(name)

        return CallScore(
            name=name,
            loc=str(hex(func.addr)),
            toplevel=self.is_toplevel_call(func),
            fuzz_friendly=fuzz_friendly,
            risky_sinks=self.risky_sinks(func),
            natural_loops=self.natural_loops(func),
            coverage_depth=self.get_coverage_depth(func),
            cyclomatic_complexity=self.get_cyclomatic_complexity(func),
            stripped=stripped,
        )

    def skip_analysis(self, func: Function) -> bool:
        name = func.name

        # ignore imported functions or syscalls
        if func.is_syscall:
            return True

        # ignore common glibc calls
        if name in _libc_decls:
            return True

        # ignore runtime calls from the binary
        if name in ["_init", "frame_dummy", "call_weak_fn", "$x", "_fini"]:
            return True

        # ignore instrumentation
        if name.startswith("__"):
            return True

        # if set, ignore all stripped functions for faster analysis
        if "Unresolvable" in name:
            return True

        return False

    def is_toplevel_call(self, target: Function) -> bool:
        """
        program_rda = self.target.analyses.ReachingDefinitions(
            subject=target,
        )
        return len(program_rda.all_definitions) == 0
        """
        log.debug(f"{target.name} - checking if top level call")
        return True

    def risky_sinks(self, func: Function) -> int:
        log.debug(f"{func.name} - checking for risky sinks")
        calls_reached = func.get_call_sites()
        for callee in calls_reached:
            # print(callee, type(callee))
            pass

        return len(calls_reached)

    def get_coverage_depth(self, target: Function) -> int:
        """
        Calculates coverage depth by doing a depth first search on function call graph,
        and return a final depth and flag denoting recursive implementation.
        """
        log.debug(f"{target.name} - getting coverage depth")
        depth = 0

        # as we iterate over callees, add to a callstack and iterate over callees
        # for those as well, adding to the callgraph until we're done with all
        callstack = [target]
        while callstack:

            # increase depth as we finish iterating over callees for another func
            func = callstack.pop()
            depth += 1

            # add all childs to callgraph, and add those we haven't recursed into callstack
            for call in func.functions_called():
                if call.name not in self.visited:
                    callstack += [call]

                self.visited += [call.name]

        return depth

    def natural_loops(self, func: Function) -> int:
        log.debug(f"{func.name} - getting natural loops")
        df = self.target.analyses.DominanceFrontier(func)
        if df.frontiers:
            return len(df.frontiers)
        
        return 0

    def get_cyclomatic_complexity(self, func: Function) -> int:
        log.debug(f"{func.name} - cyclomatic complexity")
        num_blocks = 0
        for _ in func.blocks:
            num_blocks += 1

        # do a CFG analysis starting at the fun address
        cfg = self.target.analyses.CFGFast(
            force_complete_scan=False, start_at_entry=hex(func.addr)
        )
        num_edges = len(cfg.graph.edges())
        return num_edges - num_blocks + 2
