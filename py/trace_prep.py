"BeauCoup project, © Xiaoqi Chen @ Princeton University. License: AGPLv3"
import argparse
import numpy as np

from core import lib_eval

parser = argparse.ArgumentParser(description="BeauCoup evaluation: PCAP conversion utility")

parser.add_argument("PCAP_filename", metavar="PCAP_filename", type=str,
                    help="Filename for input PCAP.")

parser.add_argument("npy_filename", metavar="npy_filename", type=str,
                    help="Filename for output parsed numpy file (for efficient loading).")

parser.add_argument("--count", metavar="count", type=int, default=-1,
                    help="Number of packets to read before stopping. Default is -1 (no limit).")

parser.add_argument("-v","--verbose", action="store_true", help="Show additional debug info.")

args = parser.parse_args()

nparray = lib_eval.parse_pcap_into_npy(args.PCAP_filename, args.count, args.verbose)

np.save(args.npy_filename, nparray)