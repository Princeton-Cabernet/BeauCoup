"BeauCoup project, © Xiaoqi Chen @ Princeton University. License: AGPLv3"
import random


def prep_hashes_keydefn(IR, debug=False):
	queries=IR['queries']
	qkcnt=0
	qkeys={}
	for q in queries:
	    k=tuple(q['key'])
	    if k not in qkeys:
	        qkcnt+=1
	        qkeys[k]=qkcnt
	keydefn={v:k for k,v in qkeys.items()}
	if debug:
		print('Prepared %d key definition tuples. They are: %s'%(qkcnt,keydefn))

	hashes=[]
	for i,hf in zip(range(len(IR['hash_functions'])),IR['hash_functions']):    
	    scaling=65536//(2**hf['bits'])
	    matches=[]
	    for mrange,ma in hf['match_actions']:
	        matches.append(
	            {"l":mrange[0]*scaling,"r":mrange[1]*scaling-1,
	             "cid":ma['coupon_index'],
	             "qid":ma['qid'],
	             "ctot":ma['at_least_coupons'],
	             "kdf":qkeys[tuple(ma['qkey'])]}
	        )
		def gen_rnd():
			a=random.randint(10000,60000)
			w=random.randint(1,16)
			return "16w%d,%dw0,  "%(a,w)
	    hashes.append({
	        "id":i+1,
	        "fields":gen_rnd()+ ",".join(hf['key']),
	        "matches":matches
	    })
	    if debug:
	    	print('Preparing hash function #%d: attribute tuple %s, scaling %d/65536 per match'%(i+1,hf['key'],scaling))
	return hashes,keydefn


