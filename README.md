# BeauCoup: Approximate Distinct Counting with Limited Memory Access

This repository hosts the codebase accompanying the SIGCOMM 2020 paper *BeauCoup: Answering Many Network Traffic Queries, One Memory Update at a Time*. The repository contains several components, corresponding to different parts of the paper.

To install python dependencies, please run `pip3 install -U pip`, then `pip3 install -r py/requirements.txt`.

## Query Syntax

We use YAML to express distinct counting queries:
```
- name : DDoS
  key: [ipv4.dstAddr, tcp.dstPort]
  conditions:
    - distinct: [ipv4.srcAddr, tcp.srcPort]
      exceeds: 5000
```
Each query includes a name, a key defintion (header tuples), an attribute definition (also header tuples), and a threshold T. Packets are first grouped by query key, then for each key, we count how many distinct attributes are seen, and send an alert when there are approximately T distinct attributes.

Please see `query_examples.yaml` for a list of examples. This is also the query set we used for the paper's evaluation section.

## The Query Compiler

The query compiler takes in a set of queries defined in YAML file, fairly allocates memory access among each query, and calculates a coupon collector configuration for each query. Subsequently, it groups queries by attribute tuple definitions and defines hash function mappings.

The compiler generates an Intermediate Representation (IR) json file. This file is used for data plane configuration as well as our simulation experiments.

Please run the following command to compile query definitions into IR:
`python3 BeauCoup/py/compiler.py --gamma=1.0 /path/to/queries.yaml /path/to/IR.json`

The Intermediate Representation contains a list of hash function specifications, used for mapping the output of a random hash function to collecting different coupons. 

The `--gamma` parameter adjusts per-packet memory access by limiting the expected number of coupons collected per packet. Use a smaller `--gamma` to further reduce memory access.


## P4 code generation

The BeauCoup P4 template program is available in `p4src/`.

The P4 code geneator takes in an Intermediate Representation and substantiate the hash function mappings into a P4 program, including the table rules corresponding to the given query set.

Please run the following command to generate the P4 program:
`python3 BeauCoup/py/p4gen.py /path/to/IR.json BeauCoup/p4src/beaucoup.p4template /path/to/beaucoup.p4`

To compile the P4 program and inspect hardware resource utilization on the Tofino switch, you need to use Barefoot P4 SDE (version 9.0.0 or greater).  
* Run `bf-p4c -g beaucoup.p4` to compile. The `-v` flag is necessary for additional visualization.
* Run `p4i -w beaucoup.tofino`, then open `http://localhost:3000/` to inspect. If you're running `p4i` on a server under CLI, you may need to add the `--no-browser` flag.

The results are available under "Dashboard" -> "Resource Summary".

## Evaluation

The evaluation experiments use [The CAIDA Anonymized Internet Traces](https://www.caida.org/data/passive/passive_dataset_download.xml), year [2018](https://data.caida.org/datasets/passive-2018/). Please download the trace directly from CAIDA.

### Trace Pre-processing

To improve performance, we pre-parse the trace packets and store the packet header fields in numpy ndarray format, and use `.npy` file to faithfully save the memory layout on disk. This allows efficient reading of the trace (loads within milliseconds), and multiple threads can use memory-mapping to load the same trace without using extra memory.

Please run the following command to preprocess the trace PCAP:
`python3 py/trace_prep.py /path/to/equinix-nyc.dirA.20180315-130000.UTC.anon.pcap /path/to/caida0.npy`


### Run BeauCoup Simulator

We use a python-based simulator to execute BeauCoup coupon collectors and generate query reports. The following command takes in an intermediate representation, runs the corresponding hash function mappings, and generates reports (saved in numpy compressed format):
`python3 BeauCoup/py/simulator.py --seed=1 /path/to/IR.json /path/to/trace.npy /path/to/reports.npz`

The simulator should be run against multiple random seeds.

The simulator also supports calculating the ground truth query output against the given trace. This is required for evaluating the accuracy of simulation runs. Please use the following command to calculate the ground truth.
`python3 BeauCoup/py/simulator.py --groundtruth /path/to/IR.json /path/to/trace.npy /path/to/groundtruth.npz`


### Comparing distinct counters

We run different algorithms for counting distinct IP pairs and compare their accuracy under sub-constant memory access constraint. Besides Coupon Collectors (`CC`), we implemented NitroSketch-UnivMon (`NSUM`) and Sampling (`Sampling`).

The following command runs the Sampling algorithm to count until 1000 distinct pairs, repeat 20 times with different random seeds, and generates a report:
`python3 BeauCoup/py/singlequery.py --threshold 1000 --repeat 100 /path/to/trace.npy /path/to/output.npz Sampling 1.0 0.1 0.01 0.001`
The algorithm can be changed to `CC`/`NSUM`.

Here, we specify a list of gamma values `1.0 0.1 0.01 0.001` corresponding to average per-packet memory access limit.

Note that the parameter specified here does not directly reflect the number of actual memory access made by the algorithm, and is only used for reference. In the evaluation, we scale the actual number of memory access recorded in the report to more accurately reflect the number of memory words accessed.

# Citing BeauCoup

If you find the code useful, please consider citing:

    @article{chen2020beaucoup,
        title={BeauCoup: Answering Many Network Traffic Queries, One Memory Update at a Time},
        author={Chen, Xiaoqi and Feibish, Shir Landau and Braverman, Mark and Rexford, Jennifer},
        journal={ACM SIGCOMM 2020},
        year={2020},
        publisher={ACM}
    }

# License
The project source code, including the P4 data plane program template, is released under the **AGPLv3 license**. 

If you modify the code and make the functionality of the code available to users interacting with it remotely through a computer network, for example through a P4 program, you must make the modified source code feely available under the same AGPLv3 license.
