"BeauCoup project, © Xiaoqi Chen @ Princeton University. License: AGPLv3"
import argparse
import json

from core import lib_eval


parser = argparse.ArgumentParser(description="BeauCoup multi-query simulator result plotting")

parser.add_argument("IR_filename", metavar="IR_filename", type=str,
                    help="Filename for input Intermediate Representation JSON file.")

parser.add_argument("GT_filename", metavar="GT_filename", type=str,
                    help="Filename for ground truth.")

parser.add_argument("plot_filename", metavar="plot_filename", type=str,
                    help="Filename for output plot (png or pdf).")

parser.add_argument("reports_PathFmt",metavar="reports_PathFmt", type=str,
                    help="""Path format for all simulation report files. 
                    For example, data/report_{gamma}_{seed}.npz . 
                    (This script will replace {gamma} and {seed} to read many files.)
                    """)

parser.add_argument("--seed_begin", metavar="seed_begin", type=int, default=0,
                    help="List of random seed, smallest value.")
parser.add_argument("--seed_end", metavar="seed_end", type=int, default=100,
                    help="List of random seed, largest value (inclusive).")
parser.add_argument("--gamma_list", metavar="gamma_list", type=str, default=",".join(["0.%d"%i for i in range(1,10)]),
                    help="List of gamma, comma separated strings.")

parser.add_argument("--separate", action="store_true", help="Plot each query's accuracy separately, instead of their average accuracy.")

parser.add_argument("-v","--verbose", action="store_true", help="Show additional debug info.")

args = parser.parse_args()

list_gammas=args.gamma_list.split(",")
list_seeds=[str(i) for i in range(args.seed_begin,args.seed_end+1)]

gamma_results, maxQ=lib_eval.parse_simulation_results(
    args.IR_filename, 
    args.GT_filename, 
    list_gammas, list_seeds, 
    args.reports_PathFmt, 
    args.verbose)

lib_eval.plot_simulation_results(gamma_results, maxQ, args.plot_filename, args.separate, args.verbose)

if args.verbose:
    print("Figure saved to %s" % args.plot_filename)