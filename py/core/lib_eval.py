"BeauCoup project, © Xiaoqi Chen @ Princeton University. License: AGPLv3"
from scapy.all import PcapReader, IP, TCP, UDP
import tqdm
import numpy as np
import random
import collections
import crcmod
import struct
import socket
import json
import matplotlib.pyplot as plt
import matplotlib

def dottedQuadToNum(ip):
	"convert decimal dotted quad string to long integer"
	return struct.unpack('>L',socket.inet_aton(ip))[0]

def numToDottedQuad(n):
	"convert long int to dotted quad string"
	return socket.inet_ntoa(struct.pack('>L',n))


def parse_pcap(FN, count=-1, debug=False):
	dicts=[]
	i=0
	with PcapReader(FN) as pcap_reader:
		#iterator=pcap_reader.read_all(count=count)
		#if debug:
		#	iterator=tqdm.tqdm(iterator)
		for pkt in pcap_reader:
			i+=1
			if i>count:break
			if i%10000==0:
				if debug:
					print('Progress: %d'%i)
            
			pdict={}
			pdict['ig_intr_md.ingress_mac_tstamp']=pkt.time
			if pkt.haslayer(IP):
				pdict['hdr.ipv4.ttl']=pkt[IP].ttl
				pdict['hdr.ipv4.protocol']=pkt[IP].proto
				pdict['hdr.ipv4.checksum']=pkt[IP].chksum
				pdict['hdr.ipv4.src_addr']=pkt[IP].src
				pdict['hdr.ipv4.dst_addr']=pkt[IP].dst

			if pkt.haslayer(TCP):
				pdict['hdr.tcp.src_port']=pkt[TCP].sport
				pdict['hdr.tcp.dst_port']=pkt[TCP].dport
				pdict['hdr.tcp.checksum']=pkt[TCP].chksum

			if pkt.haslayer(UDP):
				pdict['hdr.udp.src_port']=pkt[UDP].sport
				pdict['hdr.udp.dst_port']=pkt[UDP].dport
				pdict['hdr.udp.checksum']=pkt[UDP].chksum
			dicts.append(pdict) 
	return dicts

Pack_formatstring="dIIhhhhhhhhh"
header='ig_intr_md.ingress_mac_tstamp,hdr.ipv4.src_addr,hdr.ipv4.dst_addr,hdr.ipv4.ttl,hdr.ipv4.protocol,hdr.ipv4.checksum,hdr.tcp.src_port,hdr.tcp.dst_port,hdr.tcp.checksum,hdr.udp.src_port,hdr.udp.dst_port,hdr.udp.checksum'
harr=header.split(',')
header_loc_map={harr[i]:i for i in range(len(harr))}

# line generator, for saving CSV:
def to_line(p):
	line=[]
	for h in harr:
		if h not in p:
			line.append(-1)
		else:
			line.append(p[h])
	return ",".join([str(i) for i in line])


def prep_npy(dicts, debug=False):
	arr=np.zeros((len(dicts)),dtype=
		np.dtype('f16,u4,u4,i2,i2,i2,i2,i2,i2,i2,i2,i2')
	)
	if debug:
		print('Allocated nparray shape=%s' % arr.shape)

	for i,pdict in zip(range(len(dicts)),dicts):
		line=to_line(pdict)
		larr=line.split(',')
		arr[i][0]=np.float128(larr[0])
		if larr[1]=='-1':
			arr[i][1]=-1
		else:
			arr[i][1]=dottedQuadToNum(larr[1])
		if larr[2]=='-1':
			arr[i][2]=-1
		else:
			arr[i][2]=dottedQuadToNum(larr[2])
		
		arr[i][3]=int(larr[3])
		arr[i][4]=int(larr[4])
		arr[i][5]=int(larr[5])
		arr[i][6]=int(larr[6])
		arr[i][7]=int(larr[7])
		arr[i][8]=int(larr[8])
		arr[i][9]=int(larr[9])
		arr[i][10]=int(larr[10])
		arr[i][11]=int(larr[11])
	return arr


def load_trace_npy(FN, use_mmap=True):
	if use_mmap:
		Trace=np.load(FN, mmap_mode='r')
	else:
		Trace=np.load(FN)
	return Trace



crc16=crcmod.predefined.mkCrcFun('crc-16')
def build_hash_trunc(header_field_name_lists, trunc_bits, seedbytes=bytes()):
	mask=(1<<trunc_bits)-1
	def pull_pack_and_compute(idxs, value_list, mask, seedbytes, Pack_formatstring):
		base=seedbytes
		for i in idxs:
			if value_list[i]==-1:
				return -1
			base+=struct.pack(Pack_formatstring[i],value_list[i])
		return (crc16(base))& mask
	list_indexes=[header_loc_map[n] for n in header_field_name_lists]
	return lambda val:pull_pack_and_compute(list_indexes,val, mask, seedbytes, Pack_formatstring)


def simulate_run(TraceFN, OutFN, IR, seed=0, debug=False):
	# Utilities for reproducible randomness
	random.seed(seed)
	def get_seed_bytes():
		return bytes([random.randrange(256),random.randrange(256)])
	def get_shuffle(n):
		arr=list(range(n))
		random.shuffle(arr)
		return arr
	def get_randidx(n):
		return random.randint(0,n-1)
	def apply_shuffle(shuffle, arr):
		return [arr[i] for i in shuffle]

	# Trace loading, use mmap for parallel friendliness
	if debug:
		print('Simulation starting, loading trace from %s, output will be saved to %s. Random seed=%d' %(TraceFN,OutFN,seed))
	Trace=load_trace_npy(TraceFN,True)

	# Prepare hash functions
	h_compute=[build_hash_trunc(h['key'], h['bits'], get_seed_bytes()) for h in IR['hash_functions']]
	HashMAT=collections.namedtuple("HashMatchActionData",
							   ("upper_lim",
								"lookup_qid",
								"lookup_qkey",
								"lookup_coupon_index",
								"lookup_at_least_coupons",
								"lookup_total_coupons"
							   ))

	hash_mat_lookups=[]
	for h in IR['hash_functions']:
		upper_lim=max([act[0][1] for act in h['match_actions']])
		lookup_qid=list(range(upper_lim))
		lookup_qkey=list(range(upper_lim))
		lookup_coupon_index=list(range(upper_lim))
		lookup_at_least_coupons=list(range(upper_lim))
		lookup_total_coupons=list(range(upper_lim))
		for act in h['match_actions']:
			for idx in range(act[0][0],act[0][1]):
				lookup_qid[idx]=act[1]['qid']
				lookup_qkey[idx]=tuple([header_loc_map[field] for field in act[1]['qkey']])
				lookup_coupon_index[idx]=act[1]['coupon_index']
				lookup_at_least_coupons[idx]=act[1]['at_least_coupons']
				lookup_total_coupons[idx]=act[1]['total_coupons']
		
		shuffle=get_shuffle(upper_lim)
		hash_mat_obj=HashMAT(
			upper_lim=upper_lim,
			lookup_qid=tuple(apply_shuffle(shuffle,lookup_qid)),
			lookup_qkey=tuple(apply_shuffle(shuffle,lookup_qkey)),
			lookup_coupon_index=tuple(apply_shuffle(shuffle,lookup_coupon_index)),
			lookup_at_least_coupons=tuple(apply_shuffle(shuffle,lookup_at_least_coupons)),
			lookup_total_coupons=tuple(apply_shuffle(shuffle,lookup_total_coupons)),
		)
		hash_mat_lookups.append(hash_mat_obj)

	# Start simulation

	total_coupons=[]
	# num_coupons activated for every i

	activ_dict={}
	# (qid, flowkey) => set(coupons)

	finished_set=set()


	event_log_first=[]
	event_log_finish=[]

	# For every packet, look up hash action, then collect coupon
	iterator=range(Trace.shape[0])
	if debug:
		iterator=tqdm.tqdm(iterator)
	for i in iterator:
		all_actions=[]
		for j in range(len(h_compute)):
			val=h_compute[j](Trace[i])
			if val>=0 and val<hash_mat_lookups[j].upper_lim:
				#action! first remember it.
				all_actions.append( (j,val) )
		
		total_coupons.append(len(all_actions))
		#for now, only do fair among 2
		if len(all_actions)==0:
			continue
		if len(all_actions)>2:
			continue
		if len(all_actions)==2:
			j,val=all_actions[get_randidx(2)]
		if len(all_actions)==1:
			j,val=all_actions[0]
		# chosen an action!
		
		qid=hash_mat_lookups[j].lookup_qid[val]
		qkey_idx=hash_mat_lookups[j].lookup_qkey[val]
		
		qkey=tuple(Trace[i][idx] for idx in qkey_idx)
		if (qid, qkey) in finished_set:
			pass
		else:
					coupon_index=hash_mat_lookups[j].lookup_coupon_index[val]
					at_least_coupons=hash_mat_lookups[j].lookup_at_least_coupons[val]

					if (qid, qkey) not in activ_dict:
						event_log_first.append((i,qid))
						activ_dict[(qid, qkey)]=set()
					
					activ_dict[(qid, qkey)].add(coupon_index)
					if len(activ_dict[(qid, qkey)])>=at_least_coupons:
						event_log_finish.append((i,qid))
						finished_set.add((qid, qkey))
	if debug:
		print('Finished simulation, result length:',len(event_log_first),len(event_log_finish))
	np.savez_compressed(OutFN,event_log_first=event_log_first,event_log_finish=event_log_finish, total_coupons=total_coupons)
	 


def groundtruth_run(TraceFN, OutFN, IR, debug=False):
	# Trace loading, use mmap for parallel friendliness
	if debug:
		print('Ground Truth run starting, loading trace from %s, output will be saved to %s.' %(TraceFN,OutFN))
	Trace=load_trace_npy(TraceFN,True)

	QR=IR['queries']
	lookup_idx_qkeys=[tuple(header_loc_map[hdr] for hdr in q['key']) for q in QR]
	lookup_idx_qhashs=[tuple(header_loc_map[hdr] for hdr in q['conditions'][0]['distinct']) for q in QR]
	
	# for every query, maintain GT table: for each key, how many distinct came in
	GT_distinct_sets=[{} for j in range(len(QR))]
	GT_distinct_count=np.zeros((len(Trace), len(QR)), dtype=np.int32)

	iterator=range(len(Trace))
	if debug:
		iterator=tqdm.tqdm(iterator)

	for i in iterator:
	    for j in range(len(QR)):
	        qkey=tuple(Trace[i][idx] for idx in lookup_idx_qkeys[j])
	        qhashs=tuple(Trace[i][idx] for idx in lookup_idx_qhashs[j])
	        if -1 in qhashs:
	            continue
	        
	        if qkey not in GT_distinct_sets[j]:
	            GT_distinct_sets[j][qkey]=set()
	        GT_distinct_sets[j][qkey].add(qhashs)
	        GT_distinct_count[i][j]=len(GT_distinct_sets[j][qkey])
	print('Done. Saving output...')
	np.save(OutFN, GT_distinct_count)       
    
    
## Evaluation plotting
def parse_simulation_results(IR_FN, GT_FN, list_gamma, list_seeds, reports_npz_path_format, debug=False):
    if debug:
        print("Loading IR from %s, ground truth from %s." % (IR_FN, GT_FN))
    GT_Distinct=np.load(GT_FN, mmap_mode='r')
    IR=json.load(open(IR_FN,"r"))
    queries=IR["queries"]
    if len(queries) != GT_Distinct.shape[1]:
        raise ValueError("Number of queries in IR (%d) mismatch from ground truth file (%d)" % (len(queries) , GT_Distinct.shape[1]))
    
    def format_FN(gamma,seed):
        return reports_npz_path_format.replace("{gamma}",gamma).replace("{seed}",seed)
    
    if debug:
        print("Batch loading reports.npz, using format string: %s"%(reports_npz_path_format))
        print("(Example: from %s)" % (format_FN(list_gamma[0], list_seeds[0])))
    
    def analyze_log(TrialFN):
        arr=np.load(TrialFN, mmap_mode='r')
        event_log_finish=arr['event_log_finish'] # for query accuracy analysis
        #event_log_first=arr['event_log_first']  # for memory space analysis
        #total_coupons=arr['total_coupons']      # for memory access analysis
        trial_finish=[[] for q in queries]
        for idx in range(len(event_log_finish)):
            i,qid=event_log_finish[idx]
            gt=GT_Distinct[i][qid]
            trial_finish[qid].append(gt)
        mean_rel_error_dict={}
        for QID in range(len(queries)):
            T=queries[QID]['conditions'][0]['exceeds']
            vect=trial_finish[qid]
            if len(vect)<5:
                raise ValueError("Too few reports for query %d to calculate a meaningful mean relative error! File:%s. (Use a longer trace with >10M packets?)" %(QID,TrialFN))
            rel_err=np.abs(np.array(vect)-T)/T
            mean_rel_error_dict[QID]=np.mean(rel_err)
        return mean_rel_error_dict
    
    gamma_results={}
    for gamma in list_gamma:
        gamma_results[gamma]=[]
        if debug: print('Loading gamma=%s'%gamma)
        iterator=list_seeds
        if debug:
            iterator=tqdm.tqdm(iterator)
        for seed in iterator:
            TrialFN=format_FN(gamma,seed)
            gamma_results[gamma].append(analyze_log(TrialFN))
    return gamma_results, len(queries)

def plot_simulation_results(gamma_results, maxQ, FN, separate_queries=False, debug=False):
    list_gamma = gamma_results.keys()
    perQ_error_samples={gamma:[[] for qid in range(maxQ)] for gamma in list_gamma}
    for gamma in list_gamma:
        for mean_rel_error_dict in gamma_results[gamma]:
            for qid,error in mean_rel_error_dict.items():
                perQ_error_samples[gamma][qid].append(error)
    
    # median within per Q, then avg across Q
    allQ_error_each_gamma=[
        [np.median(perQ_error_samples[gamma][qid]) for qid in range(maxQ)]
        for gamma in list_gamma
    ]
    xrange=range(1,len(list_gamma)+1)
    
    fig, ax = plt.subplots()
    if not separate_queries:
        # violin plot, average accuracy across all Q 
        plt.violinplot(allQ_error_each_gamma, showmeans=True)
        avgd_across_q=[np.mean(x) for x in allQ_error_each_gamma]
        plt.plot(xrange, avgd_across_q)
        plt.xticks(xrange,list_gamma)
        if debug: 
            print("Mean Relative Error, averaged across queries: %s" % avgd_across_q)
            print("(Gamma=%s)"%list_gamma)
    else:
        # one line for each query
        for qid in range(maxQ):
            perQ_error_each_gamma=[np.median(perQ_error_samples[gamma][qid]) for gamma in list_gamma]
            plt.plot(list_gamma, perQ_error_each_gamma,label='Q%d'%qid) 
            if debug: 
                print("Mean Relative Error, query #%s: %s" % (qid, perQ_error_each_gamma))
        plt.legend(loc="lower left",ncol=4)
        if debug: 
            print("(Gamma=%s)"%list_gamma)
    plt.xlabel("Total memory access per packet limit ($Gamma$)")
    plt.ylabel("Mean Relative Error")
    ax.yaxis.set_major_formatter( matplotlib.ticker.FuncFormatter(lambda x, pos: '%d%%' % (x*100, )) )
    plt.savefig(FN)