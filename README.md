# BeauCoup: Approximate Distinct Counting with Limited Memory Access

This repository hosts the codebase accompanying the SIGCOMM 2020 paper [*BeauCoup: Answering Many Network Traffic Queries, One Memory Update at a Time*](https://doi.org/10.1145/3387514.3405865). The repository contains several components, corresponding to different parts of the paper.

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


#### Format
The IR has three parts. 
- `queries` includes the original query set (parsed into a standardized representation after aliasing).
- `qid_name_lookup` is a dictionary from query ID to name.
- `gamma_specified` is the compilation parameter.
- `hash_functions` includes one hash function lookup table for each attribute. Each entry in the lookup table represents one coupon, with a probability, its query ID, this coupon's ID, the number of total coupons, and the number of required coupons. 

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

The trace pre-processing is memory intensive as it loads the entire trace to memory first. Please run with a smaller `--count` parameter when running on machines with small (<10GB) memory and large (>100MB) traces.

#### Format
The output numpy file has 12 columns, including:
- Col 0: Timestamp (float128)
- Col 1-5: IPv4 Source/Destination (uint32), TTL/Protocol/Checksum (uint16)
- Col 6-8: TCP Source/Destination port, checksum (uint16)
- Col 9-11: UDP Source/Destination port, checksum (uint16)

Each line represents one packet. (Invalid headers are filled in with the unsigned -1 (65535 or 2^32-1), which might overlap with port 65535 or IP 255.255.255.255.)


### Run BeauCoup Simulator

We use a python-based simulator to execute BeauCoup coupon collectors and generate query reports. The following command takes in an intermediate representation, runs the corresponding hash function mappings, and generates reports (saved in numpy compressed format):
`python3 BeauCoup/py/simulator.py --seed=1 /path/to/IR.json /path/to/trace.npy /path/to/reports.npz`

The simulator also supports calculating the ground truth query output against the given trace. This is required for evaluating the accuracy of simulation runs. Please use the following command to calculate the ground truth.
`python3 BeauCoup/py/simulator.py --groundtruth /path/to/IR.json /path/to/trace.npy /path/to/groundtruth.npz`

#### Format
The report includes three parts.
- `event_log_first` is a list of `packet index, query ID` tuples, representing when a coupon collector is first allocated for a particular key of a query (i.e., this key collected the first coupon). 
- `event_log_finish` is a list of `packet index, query ID` tuples, representing when a coupon collector has collected enough coupons for the first time (i.e., time to send out alerts).
- `total_coupons` is a 1-D array with only 0/1 entries, referring to whether each packet collected one coupon or no coupon.

The ground truth is a 2-D array with each row representing a packet and each column representing a query. Each entry contains a number that shows, "for this query, given the key represented by this packet, the number of total distinct attributes seen for this key (since the beginning of the trace)".


#### Repeated runs

The simulator should be run against multiple random seeds and multiple configurations. Attached here is a simple bash script to run multiple such trials and save their outputs.
```bash
for gamma in `seq 0.1 0.1 0.9;` do
  python3 BeauCoup/py/compiler.py --gamma=$gamma queries.yaml IR_${gamma}.json
  for seed in `seq 1 16`; do
	 python3 BeauCoup/py/simulator.py --seed=$seed IR_${gamma}.json /path/to/trace.npy outputs/report_gamma_${gamma}_seed_${seed}.npz
  done
done
```
However, as it takes quite a while to run the simulations, we recommend running them in parallel.

#### Plotting

We attached a script to parse and analyze the reports from the simulatoin runs. To parse the results from the above example script, please run:
`python3 BeauCoup/py/plot_simulator.py /path/to/IR.json  /path/to/groundtruth.npz  /path/to/plot.png outputs/report_gamma_{gamma}_seed_{seed}.npz   --seed_begin=1 --seed_end=16 --gamma_list=0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9 `

The analysis script need the ground truth file and one of the IR file (please make sure they use the same query/trace, consistent with the experiment runs). It will calculate and plot the mean relative errors experienced by all queries, with gamma on x-axis and mean relative error on y-axis. Add the `--separate` flag to plot each query individually (instead of plot all queries together).

### Comparing distinct counters

We run different algorithms for counting distinct IP pairs and compare their accuracy under sub-constant memory access constraint. Besides Coupon Collectors (`CC`), we implemented NitroSketch-UnivMon (`NSUM`) and Sampling (`Sampling`).

The following command runs the Sampling algorithm to count until 1000 distinct pairs, repeat 20 times with different random seeds, and generates a report (pickle file):
`python3 BeauCoup/py/singlequery.py --threshold 1000 --repeat 100 /path/to/trace.npy /path/to/output.pkl Sampling 1.0 0.1 0.01 0.001`
The algorithm can be changed to `CC`/`NSUM`.

Here, we specify a list of gamma values `1.0 0.1 0.01 0.001` corresponding to average per-packet memory access limit. This is only used for suggestion, and we later parse the output report to recover the actual memory access made by the algorithm.

#### Format
The report pickle file contains a dictionary indexed by `gamma, threshold`. Each dictionary item is a list of `numDistinct, memAccess`, where `numDistinct` represents the actual number of distinct items seen when the algorithm's estimate first exceeds `threshold`, and `memAccess` is the average memory access per packet.

#### Plotting

To parse and plot the pickle files, please run `python3 BeauCoup/py/plot_singlequery.py /path/to/output.pkl /path/to/plot.png`. This loads and plots a single accuracy profile curve, with average memory access per packet on x-axis and mean relative error on y-axis. 

The memory access unit for `NSUM` is per sketch entry write (one word per write), for `Sampling` is per packet (accessing 2 words to write each IP pair), and for `BeauCoup` is per coupon (accessing 3 words to collect a coupon). Please scale accordingly when overlaying the different curves for comparison.


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
Copyright 2020 Xiaoqi Chen, Princeton University.

The project source code, including the P4 data plane program template, is released under the **[GNU Affero General Public License v3](https://www.gnu.org/licenses/agpl-3.0.html)**. 

If you modify the code and make the functionality of the code available to users interacting with it remotely through a computer network, for example through a P4 program, you must make the modified source code freely available under the same AGPLv3 license.
