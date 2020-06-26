"BeauCoup project, © Xiaoqi Chen @ Princeton University. License: AGPLv3"
import argparse
import json
import jinja2
from core import lib_p4gen


parser = argparse.ArgumentParser(description="BeauCoup P4 code generator")

parser.add_argument("IR_filename", metavar="IR_filename", type=str,
                    help="Filename for input Intermediate Representation JSON file.")

parser.add_argument("template_filename", metavar="template_filename", type=str,
                    help="Filename for input Jinja/P4 template.")

parser.add_argument("P4_filename", metavar="P4_filename", type=str,
                    help="Filename for output P4 data plane program.")

parser.add_argument("-v","--verbose", action="store_true", help="Show additional debug info.")


args = parser.parse_args()


IR = json.load(open(args.IR_filename,"r"))

hashes, keydefn = lib_p4gen.prep_hashes_keydefn(IR, args.verbose)



with open(args.template_filename,'r') as f:
    t = jinja2.Template(f.read(),  trim_blocks=True, lstrip_blocks=True)
    
output = (t.render(hashes=hashes,keydefn=keydefn))
with open(args.P4_filename, 'w') as f:
    f.write(output)
