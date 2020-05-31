import os
import sys
from argparse import ArgumentParser
from typing import List

from systack.bpf_program import BPFProgram


def main(sys_args: List[str] = sys.argv[1:]) -> None:
    parser = ArgumentParser()

    trace_option = parser.add_mutually_exclusive_group(required=1)

    trace_option.add_argument('--pid', type=int, help='PID to trace')
    trace_option.add_argument('--run', type=str, help='Binary to run')

    args = parser.parse_args(sys_args)

    b = BPFProgram(pid=args.pid, run=args.run)

    try:
        b.event_loop()
    except KeyboardInterrupt:
        sys.exit()
