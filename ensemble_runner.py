# Description: Ensemble runner for Cmplog and FOX
# 
# Usage: python3 ensemble_runner.py -i [corpus_dir] -o [output_dir] -b [target_binary] -x [dicts] --fox_target_binary [fox_target_binary] --cmplog_target_binary [cmplog_target_binary]
#
# If fox_target_binary and cmplog_target_binary are not provided, they will be set to [target_binary]_fox and [target_binary]_cmplog respectively
# If dicts are not provided, all .dict files in the current directory will be used
#
# One can also directly import the EnsembleFuzzer class, which can be used as follows:
# EnsembleFuzzer(corpus_dir, output_dir, dicts, target_binary, cmplog_target_binary, fox_target_binary).run()
# 
# Required fuzzer binaries in the current directory (names/paths modifiable in the script, see CMPLOG_FUZZ_BIN_NAME and FOX_FUZZ_BIN_NAME):
#   - fox_4.09c_hybrid: https://github.com/adamstorek/AFLplusplus/tree/sbft24_hybrid_mode # sbft24_stable (+ saving/reloading fox metadata, removing flock check on resume)
#   - cmplog_4.09c_hybrid: https://github.com/adamstorek/AFLplusplus/tree/4.09c_hybrid_mode # 4.09c_baseline (4.09c release + removing flock check on resume)
# 
# Environment variables touched:
#   - AFL_AUTORESUME: set to 1 (EnsembleFuzzer will set it to 1 if it is not set)
#

import argparse
import json
import logging
import os
import subprocess
import time

from collections import deque
from typing import List, Deque # breaks with Python >= 3.9, replace with list[str], deque[AFLFuzzer]

# Fuzzer-command specific constants
INT_MAX = '2147483647'
COMMON_ARGS = ['-m', 'none', '-d', '-t', '1000+']
CMPLOG_FUZZ_BIN_NAME = "./cmplog_4.09c_hybrid_start"
FOX_FUZZ_BIN_NAME = "./fox_4.09c_hybrid_start"

# Timeout strategies
TMOUT_CMPLOG = 90 * 60 # 90 minutes
TMOUT_FOX = 120 * 60 # 120 minutes


def time_s():
    """Get the current time in seconds."""
    return int(time.time())


def run_command(command: List[str]):
    """Run a checked command."""
    subprocess.run(command, check=True)


class AbstractFuzzer:
    """Abstract class for a fuzzer."""
    name: str
    run_cnt: int
    corpus_dir: str
    output_dir: str
    command: List[str]
    dicts: List[str]
    target_binary: str
    args: List[str]

    def run(self):
        raise NotImplementedError()

    def build_command(self):
        raise NotImplementedError()

    def get_timeout(self):
        raise NotImplementedError()


class AFLFuzzer(AbstractFuzzer):
    """Base class for an AFL fuzzer."""
    timeout: bool
    run_err: Exception

    def __init__(self, name: str, corpus_dir: str, output_dir: str, dicts: List[str], target_binary: str, args: List[str]):
        self.name = name
        self.corpus_dir = corpus_dir
        self.output_dir = output_dir
        self.dicts = dicts
        self.target_binary = target_binary
        self.args = args
        self.run_cnt = 0
        self.command = None
        self.timeout = False
        self.run_err = None

    def add_common_args(self):
        """Add the common arguments to the command."""
        if self.timeout:
            self.command += ['-V', self.get_timeout()]
        self.command += COMMON_ARGS
        for dict in self.dicts:
            self.command += ['-x', dict]
        self.command += ['-i', self.corpus_dir, '-o', self.output_dir, '-M', self.name, '--', self.target_binary] + self.args + [INT_MAX]

    def do_run(self):
        """Run the fuzzer. If it fails with a CalledProcessError, save the error."""
        try:
            subprocess.run(self.command, check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Unexpected error while running the fuzzer")
            logging.exception(e)
            self.run_err = e

    def do_run_timed(self):
        """Run the fuzzer, time it, and save the error if it fails."""
        self.time_start = time_s()
        self.do_run()
        self.time_end = time_s()

    def run(self):
        """Run the fuzzer and log the result."""
        self.build_command()
        self.do_run_timed()
        logging.info(self.run_info())
        self.run_cnt += 1

    def run_info(self):
        """Get the run info as a JSON string."""
        return json.dumps({
            'name': self.name,
            'run_cnt': self.run_cnt,
            'time_start': self.time_start,
            'time_end': self.time_end,
            'command': self.command,
            'run_err': str(self.run_err)
        })


class CmplogFuzzer(AFLFuzzer):
    cmplog_target_binary: str

    def __init__(self, corpus_dir: str, output_dir: str, dicts: List[str], target_binary: str, cmplog_target_binary: str, args: List[str]):
        self.cmplog_target_binary = cmplog_target_binary
        super().__init__("cmplog", corpus_dir, output_dir, dicts, target_binary, args)

    def build_command(self):
        self.command = [CMPLOG_FUZZ_BIN_NAME, '-c', self.cmplog_target_binary]
        self.add_common_args()

    def get_timeout(self):
        return str(TMOUT_CMPLOG)


class FoxFuzzer(AFLFuzzer):

    def __init__(self, corpus_dir: str, output_dir: str, dicts: List[str], target_binary: str, args: List[str]):
        super().__init__("fox", corpus_dir, output_dir, dicts, target_binary, args)

    def build_command(self):
        self.command = [FOX_FUZZ_BIN_NAME, '-k', '-p', 'wd_scheduler']
        self.add_common_args()

    def get_timeout(self):
        return str(TMOUT_FOX)

class EnsembleFuzzer:
    output_dir: str
    fuzzer_queue: Deque[AFLFuzzer]

    def __init__(self, corpus_dir: str, output_dir: str, dicts: List[str], target_binary: str, cmplog_target_binary: str, fox_target_binary: str, args: List[str]):
        self.output_dir = os.path.join(output_dir, "ensemble_fuzzer")
        self.fuzzer_queue = deque([
            FoxFuzzer(corpus_dir, self.output_dir, dicts, fox_target_binary, args),
            CmplogFuzzer(corpus_dir, self.output_dir, dicts, target_binary, cmplog_target_binary, args)
        ])

    def run(self):
        """Run the fuzzer ensemble. If a fuzzer fails, it is removed from the queue. If one fuzzer remains, it is run without a timeout."""
        os.makedirs(self.output_dir, exist_ok=True)
        os.environ["AFL_AUTORESUME"] = "1"
        while len(self.fuzzer_queue):
            fuzzer = self.fuzzer_queue.popleft()
            fuzzer.timeout = len(self.fuzzer_queue) > 0
            fuzzer.run()
            if fuzzer.run_err is None:
                self.fuzzer_queue.append(fuzzer)
        logging.critical("No fuzzer left in the queue, this should not happen")
        raise RuntimeError("No fuzzer left in the queue, this should not happen")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--corpus_dir", type=str, required=True, help="Directory containing the corpus")
    parser.add_argument("-o", "--output_dir", type=str, required=True, help="Directory to store output")
    parser.add_argument("-b", "--target_binary", type=str, required=True, help="Path to the vanila AFLplusplus-instrumented target binary")
    parser.add_argument("-a", "--args", type=str, nargs="*", default=[], help="Arguments to pass to the target binary")
    parser.add_argument("-x", "--dicts", type=str, nargs="+", default=None, help="Path to the dictionaries, if not provided, will be set to all .dict files in the current directory")
    parser.add_argument("--fox_target_binary", type=str, required=True, help="Path to the FOX-instrumented target binary, if not provided, will be set to [target_binary]_fox")
    parser.add_argument("--cmplog_target_binary", type=str, required=True, help="Path to the cmplog-instrumented target binary, if not provided, will be set to [target_binary]_cmplog")
    return parser.parse_args()


def main(args):
    os.makedirs(args.output_dir, exist_ok=True)
    logging.basicConfig(filename=os.path.join(args.output_dir, "ensemble_runner.log"), level=logging.DEBUG)

    fuzzer = EnsembleFuzzer(args.corpus_dir, args.output_dir, args.dicts, args.target_binary, args.cmplog_target_binary, args.fox_target_binary, args.args)
    fuzzer.run()


if __name__ == "__main__":
    main(parse_args())
