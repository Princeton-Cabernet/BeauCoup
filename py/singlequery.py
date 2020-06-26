"BeauCoup project, © Xiaoqi Chen @ Princeton University. License: AGPLv3"
import argparse
import json
import pickle

from core import lib_countdistinct
from core import lib_eval



parser = argparse.ArgumentParser(description="BeauCoup single-query coupon collection simulator")

parser.add_argument("npy_filename", metavar="npy_filename", type=str,
                    help="Filename for input parsed numpy trace file.")

parser.add_argument("out_filename", metavar="out_filename", type=str,
                    help="Filename for output reports.")

parser.add_argument("algorithm", choices=["NSUM", "Sampling", "CC"],
                    help="Algorithm for approximate distinct counting (NitroSketch-UnivMon, Sampling, or Coupon Collector).")

parser.add_argument("gamma", nargs="*", type=float, default=[1.0,0.1,0.01,0.001], help="Sub-constant per-packet memory access limits")

parser.add_argument("--threshold", metavar="threshold", type=int, default=1000,
                    help="Threshold for distinct counting.")

parser.add_argument("--repeat", metavar="repeat", type=int, default=20,
                    help="Repeat for x times.")

parser.add_argument("-v","--verbose", action="store_true", help="Show additional debug info.")

args = parser.parse_args()

if args.verbose:
	print("Run single query using algorithm %s, loading trace from %s, output will be saved to %s. Threshold=%d gamma=%s Random repeat=%d" %(args.algorithm, args.npy_filename, args.out_filename, args.threshold, args.gamma, args.repeat))
Trace = lib_eval.load_trace_npy(args.npy_filename, True)

if args.algorithm == "NSUM":
	Runner = lib_countdistinct.run_NSUM
if args.algorithm == "Sampling":
	Runner = lib_countdistinct.run_Sampling
if args.algorithm == "CC":
	Runner = lib_countdistinct.run_CC

Result = Runner(Trace, threshold=args.threshold, repeat=args.repeat, p_configs=args.gamma, debug=args.verbose)

pickle.dump(Result, open(args.out_filename,"wb"))