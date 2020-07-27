"BeauCoup project, © Xiaoqi Chen @ Princeton University. License: AGPLv3"
import argparse
import json

from core import lib_countdistinct


parser = argparse.ArgumentParser(description="BeauCoup single-query simulator result plotting")

parser.add_argument("pickle_filename", metavar="pickle_filename", type=str,
                    help="Filename for loading the simulator's output pickle file.")

parser.add_argument("plot_filename", metavar="plot_filename", type=str,
                    help="Filename for output plot (png or pdf).")

parser.add_argument("-v","--verbose", action="store_true", help="Show additional debug info.")

args = parser.parse_args()

if args.verbose:
    print("Loading pickle from: %s" % args.pickle_filename)
    
memA, acc = lib_countdistinct.parse_memA_acc(args.pickle_filename)
if args.verbose:
    print("Parsed the following data points (AvgMemAccess, MeanRelErr):%s" % list(zip(memA,acc)))

lib_countdistinct.plot_memA_acc(memA, acc, args.plot_filename)

if args.verbose:
    print("Figure saved to %s" % args.plot_filename)