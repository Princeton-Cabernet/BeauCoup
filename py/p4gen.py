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

if args.verbose:
    print("Parsed %d hash functions from IR" % len(hashes))
    print("Parsed %d keydefn from IR" % len(keydefn))

assert(len(keydefn)<=15) # currently the template uses 4-bit keydefn pointer

with open(args.template_filename,'r') as f:
    template_txt=f.read()
    if args.verbose:
        print("Loaded template, %d lines"%(len(template_txt.split("\n"))))
    t = jinja2.Template(template_txt,  trim_blocks=True, lstrip_blocks=True)


    
output = (t.render(hashes=hashes,keydefn=keydefn))
with open(args.P4_filename, 'w') as f:
    f.write(output)
    
if args.verbose:
    print("Generated P4 source, %d lines. Successfully saved to %s"%(len(output.split("\n")),args.P4_filename))