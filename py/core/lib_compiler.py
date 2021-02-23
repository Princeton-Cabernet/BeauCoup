"BeauCoup project, © Xiaoqi Chen @ Princeton University. License: AGPLv3"
import yaml
import json
import numpy as np


def validate_header_name(header_name):
	valid_parsed_hdr=[
        'ig_intr_md.ingress_mac_tstamp',
        'hdr.ipv4.src_addr',
        'hdr.ipv4.dst_addr',
        'hdr.ipv4.protocol',
        'hdr.tcp.src_port',
        'hdr.udp.src_port',
        'hdr.tcp.dst_port',
        'hdr.udp.dst_port',
        ]
	aliases={
        "packets":"ig_intr_md.ingress_mac_tstamp",
        "ingress_metadata.ingress_timestamp":"ig_intr_md.ingress_mac_tstamp",
        'ipv4.srcAddr':'hdr.ipv4.src_addr',
        'ipv4.dstAddr':'hdr.ipv4.dst_addr',
        'ipv4.protocol':'hdr.ipv4.protocol',
        'tcp.srcPort':'hdr.tcp.src_port',
        'tcp.dstPort':'hdr.tcp.dst_port',
        'udp.srcPort':'hdr.udp.src_port',
        'udp.dstPort':'hdr.udp.dst_port',
        'ipv4.src_addr':'hdr.ipv4.src_addr',
        'ipv4.dst_addr':'hdr.ipv4.dst_addr',
        'tcp.src_port':'hdr.tcp.src_port',
        'tcp.dst_port':'hdr.tcp.dst_port',
        'udp.src_port':'hdr.udp.src_port',
        'udp.dst_port':'hdr.udp.dst_port',
    }
	
	if type(header_name)!=str:
		raise ValueError("Header field not string?",header_name)
	
	if header_name in aliases:
		return validate_header_name(aliases[header_name])
	
	if header_name in valid_parsed_hdr:
		return header_name
	else:
		raise ValueError("Unexpected header field:",header_name)

def validate_yaml(queries):
	# syntax check
	for i in range(len(queries)):
		assert(type(queries[i]["name"])==str)
		assert(type(queries[i]["key"]) in [str,list])
		if type(queries[i]["key"])==str:
			queries[i]["key"]=[queries[i]["key"]]
		assert(type(queries[i]["conditions"])==list)
		for j in range(len(queries[i]["conditions"])):
			assert(type(queries[i]["conditions"][j]["exceeds"])==int)
			assert(type(queries[i]["conditions"][j]["distinct"]) in [str, list])
			if type(queries[i]["conditions"][j]["distinct"])==str:
				queries[i]["conditions"][j]["distinct"]=[ queries[i]["conditions"][j]["distinct"] ]
	return queries

def validate_header(queries):  
	for i in range(len(queries)):
		for j in range(len(queries[i]["key"])):
			queries[i]["key"][j]=validate_header_name(queries[i]["key"][j])
		for j in range(len(queries[i]["conditions"])):
			for k in range(len(queries[i]["conditions"][j]["distinct"])):
				queries[i]["conditions"][j]["distinct"][k]=validate_header_name(queries[i]["conditions"][j]["distinct"][k])
	return queries

def parse_file(filename="query.yaml", debug=False):
	with open(filename,"r") as f:
		cont=f.read()
	queries=yaml.safe_load(cont)
	if debug:
		print("validating YAML structure...")
	queries=validate_yaml(queries)
	if debug:
		print("done.")
		print("validating header field names...")
	queries=validate_header(queries)
	if debug:
		print("done.")
		print("validating probability...")
	max_prob=0.99 
	per_query_prob=max_prob/len(queries)
	for q in queries:
		sum_prob=sum([1.0/c["exceeds"] for c in q["conditions"]])
		if sum_prob>per_query_prob:
			print("Warning, query threshold likely too low for:",q)
	if debug:
		print("done.")
		print("Assigning qid...")
	for i in range(len(queries)):
		queries[i]["qid"]=i
	if debug:
		print("done.")
		print("Successfully parsed %d queries."%len(queries))
	return queries


def compute_expected_activation_time(num_total_coupon, num_to_collect, prob_each):
	# Calculate the expected number of activation needed to complete a coupon collector
	# Note: this function gives expectation, not maximum likelihood. Skewed to right.
	activation_time=0
	for i in range(num_to_collect):
		available_coupon_for_collection=num_total_coupon-i
		total_prob_triggering_any=prob_each*available_coupon_for_collection
		geo_expectation=1.0/total_prob_triggering_any
		activation_time+=geo_expectation
	return activation_time
	# sum of geometric"s expectation
	# if there"s 16 slots, each 1/128:
	# first coupon has prob 16/128
	# next has 15/128, last has 12/128




def find_best_cc_partial_smart(prob_thres, bias_factor, expected_activ, debug=False, SCORING_ALLOWED_BONUS=0.01):
	"Find the optimal partial collection scheme."
	"""
	Note 1: we use all 32 coupons when possible. However, initially we can only use less than 32.
	In this case, just use whatever we have.
	Note 2: when there are >10 coupons, do not use all of them.
	Using 32 out of 32 is not accurate (compared with 16/32 up till 28/32).
	Hence, we use at most 90% coupons if there are >10.
	Note 3: bonus heuristics for using more coupons, even if expectation is alightly further away
	The new |(expected activ-T)/T-1| cannot be 0.05 worse than the original 

	For allocation: again we use scoring. 
	We say 10 coupons compared with 5 coupons give you 100% more relative accuracy.
	However, 15 coupons compared with 10 gives you only 30%.
	After 15, it"s useless.
	"""
	inv_prob_list=[2**i for i in range(1,20)]
	priority_list=[]
	def num_cc_weight(num_cc):
		### New constraint: max bonus based on more coupons is SCORING_ALLOWED_BONUS
		score=0.0
		stage1_cc=min(num_cc,10)
		score+=0.008*(SCORING_ALLOWED_BONUS/0.10)*stage1_cc
		num_cc-=10
		if num_cc>=0:
			stage2_cc=min(num_cc,5)
			score+=0.004*(SCORING_ALLOWED_BONUS/0.10)*stage2_cc
			num_cc-=5
		return score
	
	for inv_prob in inv_prob_list:
		prob_each=(1.0/inv_prob)*bias_factor
		max_coupons_allowed=int(prob_thres/prob_each)
		if max_coupons_allowed>=32:
			max_coupons_allowed=32
		if max_coupons_allowed<1:
			continue
		upper_range=max_coupons_allowed+1
		if max_coupons_allowed>=10:
			upper_range=int(0.9*max_coupons_allowed)+1
		lower_range=1
		if max_coupons_allowed>=10:
			lower_range=int(0.3*max_coupons_allowed)
		for num_to_collect in range(lower_range,upper_range):
			this_exp_activ=compute_expected_activation_time(max_coupons_allowed, num_to_collect, prob_each)
			relative_accuracy=abs(this_exp_activ-expected_activ)/float(expected_activ)
			score=relative_accuracy-num_cc_weight(num_to_collect)
			priority_list.append((score, (this_exp_activ, relative_accuracy), (num_to_collect,max_coupons_allowed),inv_prob))
	#print(sorted(priority_list)[:20])
	opt=sorted(priority_list)[0]
	(num_to_collect,max_coupons_allowed),inv_prob=opt[-2],opt[-1]
	prob_each=(1.0/inv_prob)*bias_factor
	this_exp_activ=compute_expected_activation_time(max_coupons_allowed, num_to_collect, prob_each)
	total_activ_prob=(1.0/inv_prob)*bias_factor*max_coupons_allowed

	if debug:
		print("Finding allocation, for per-packet coupon limit=%f bias=%f activation threshold=%f" %(prob_thres, bias_factor, expected_activ))
		print("Output: each coupon probability 1/%d, collect n=%d out of m=%d coupons; expected activation after %f items, total average per-packet coupon=%f" %(inv_prob, num_to_collect,max_coupons_allowed, this_exp_activ, total_activ_prob))

	return (inv_prob, (num_to_collect,max_coupons_allowed), this_exp_activ, total_activ_prob)
	#num_cc,inv_prob=opt[-2],opt[-1]
	#total_activ_prob, this_exp_activ=activ_matrix[inv_prob][num_cc]
	#return (inv_prob, num_cc, this_exp_activ, total_activ_prob)


def generate_hash_functions(queries, allocate_fn, debug=False):
	def prep_hash_qids(queries, debug=False):
		attr_tuples=[
		 ("ig_intr_md.ingress_mac_tstamp",),
		 ("hdr.ipv4.dst_addr",),
		 ("hdr.ipv4.dst_addr", "hdr.tcp.dst_port"),
		 ("hdr.ipv4.dst_addr", "hdr.udp.dst_port"),
		 ("hdr.ipv4.src_addr",),
		 ("hdr.ipv4.src_addr", "hdr.tcp.src_port"),
		 ("hdr.ipv4.src_addr", "hdr.udp.src_port"),
		 ("hdr.tcp.dst_port",),
		 ("hdr.tcp.src_port",),
		 ("hdr.udp.dst_port",),
		 ("hdr.udp.src_port",)]
		q_attr_tuples=sorted(set([ tuple(queries[i]["conditions"][0]["distinct"]) for i in range(len(queries))]))
		for i in q_attr_tuples:
			if i not in attr_tuples:
				attr_tuples.append(i)
		if debug:
			print("Preparing %d hash functions for unique attribute tuples: %s" %(len(attr_tuples),attr_tuples))
		
		hash_qid_list={hf:[] for hf in attr_tuples}
		for query in queries:
			qid=query["qid"]
			assert(len(query["conditions"])==1)
			cond=query["conditions"][0]
			hashkey=tuple(sorted(cond["distinct"]))
			assert(hashkey in hash_qid_list)
			exceeds=cond["exceeds"]
			hash_qid_list[hashkey].append((qid, exceeds))
		return attr_tuples,hash_qid_list

	attr_tuples, hash_qid_list=prep_hash_qids(queries, debug)
	hashfn_actions={hf:[] for hf in hash_qid_list}

	for i in range(len(attr_tuples)):
		hashkey=attr_tuples[i]
		base_prob_bias=1.0
		for qid,exceeds in hash_qid_list[hashkey]:
			query=queries[qid]
			prob_thres=allocate_fn(query)
			if debug:
				print("Processing qid#%d query=%s threshold=%d"%(qid,query,exceeds))

			partial_alloc_result=find_best_cc_partial_smart(prob_thres, base_prob_bias, exceeds, debug)

			(inv_per_coupon_prob, (num_to_collect,max_coupons_allowed), expSize, activation_prob)=partial_alloc_result
			hashfn_actions[hashkey].append((qid,partial_alloc_result))

	hash_functions=[]
	log2_lookup={2**i:i for i in range(32)}
	for i in range(len(attr_tuples)):
		hashkey=attr_tuples[i]
		#sort from large prob to small prob
		all_queries=sorted(hashfn_actions[hashkey], key=lambda q:q[1][0])
		if len(all_queries)==0:
			print("Warning: hashkey %s has no actions." % str(hashkey))
			max_inv_prob=16
		else:
			max_inv_prob=max([q[1][0] for q in all_queries])
		
		base=0
		match_actions=[]
		for act in all_queries:
			qid=act[0]
			(inv_per_coupon_prob, (num_to_collect,max_coupons_allowed), expSize, activation_prob)=act[1]
			
			slots=int(max_inv_prob / inv_per_coupon_prob)
			for i in range(max_coupons_allowed):
				act={"coupon_index": i,
					 "_coupon_inv_probability_hash": inv_per_coupon_prob,
					 "qid": qid,
					 "qkey": queries[qid]["key"],
					 "at_least_coupons":num_to_collect,
					 "total_coupons": max_coupons_allowed}
				match_range=(base, base+slots)
				match_actions.append((match_range, act))
				base+=slots
		if debug:
			print("Allocated hash function #%d for attr tuple=%s, total matching entries=%d (out of %d possible), utilization=%.02f percent"%(i,hashkey,base,max_inv_prob,base*100/max_inv_prob))
		assert(base*100/max_inv_prob<=100)
		hash_functions.append({
			"key":hashkey,
			"_inv_prob_per_slot":max_inv_prob,
			"bits":log2_lookup[max_inv_prob],
			"match_actions":match_actions,
		})
	if debug:
		print("Finished generating hash functions (%d in total)"%(len(hash_functions)))
	return hash_functions
