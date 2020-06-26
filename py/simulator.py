"BeauCoup project, © Xiaoqi Chen @ Princeton University. License: AGPLv3"
import argparse
import json
from core import lib_eval


parser = argparse.ArgumentParser(description="BeauCoup multi-query coupon collection simulator")

parser.add_argument("IR_filename", metavar="IR_filename", type=str,
                    help="Filename for input Intermediate Representation JSON file.")

parser.add_argument("npy_filename", metavar="npy_filename", type=str,
                    help="Filename for input parsed numpy trace file.")

parser.add_argument("out_filename", metavar="out_filename", type=str,
                    help="Filename for output reports.")

parser.add_argument("--seed", metavar="seed", type=int, default=0,
                    help="Numerical random seed.")

parser.add_argument("--groundtruth", action="store_true",
                    help="Run ground truth instead of simulation.")

parser.add_argument("-v","--verbose", action="store_true", help="Show additional debug info.")


args = parser.parse_args()

IR = json.load(open(args.IR_filename,"r"))

if args.groundtruth:
	lib_eval.groundtruth_run(args.npy_filename, args.out_filename, IR, debug=args.verbose)
else:
	lib_eval.simulate_run(args.npy_filename, args.out_filename, IR, args.seed, debug=args.verbose)