"BeauCoup project, © Xiaoqi Chen @ Princeton University. License: AGPLv3"
import numpy as np
import scipy.stats
import crcmod
import random
import tqdm
import pickle
import matplotlib
import matplotlib.pyplot as plt

# Part 1: simulate the behavior of BeauCoup Coupon Collectors efficiently, using geometric sampling

def simulate(M,N,p, repeat=1000):
	list_geomrv=[]
	for j in range(N):
		g_p=(p*(M-j))
		list_geomrv.append(scipy.stats.geom(g_p))
	samples=[]
	for i in range(repeat):
		samples.append(
			sum([v.rvs() for v in list_geomrv])
		)
	return samples

def mean_rel_err(samples, target=None):
	if target==None:
		target=np.mean(samples)
	return np.mean(np.abs(np.array(samples)-target))/target


def gen_samples_64x64(debug=False):
	all_samples={}
	for M in reversed(range(1,64+1)):
		for N in tqdm(range(1,M+1)):
			if debug:
				print("Generating samples for M=%d N=%d"%(M,N))
			p=0.01
			all_samples[(M,N,p)]=simulate(M,N,p)
	return all_samples


# Part 2: Comparing BeauCoup with other distinct counting algorithms, using real trace-based data

# Use IP pair as key
def getKey(p):
	return tuple(p)[1:3]
# Random stuff

bitmap=np.zeros((65536,16),dtype=np.int8)
for i in range(65536):
	for j in range(16):
		power2=2**j
		thisbit=(i%(2*(power2)))//power2
		assert(thisbit==0 or thisbit==1)
		bitmap[i][j]=thisbit

crc32_func = crcmod.predefined.mkCrcFun("crc-32") #for flow_id
crc16_func1 = crcmod.predefined.mkCrcFun("crc-16-genibus") #for location in table 1
crc16_func2 = crcmod.predefined.mkCrcFun("crc-16-dnp") #for location in table 2
crc16_func3 = crcmod.predefined.mkCrcFun("crc-16-dect") #for location in table 3
crc16_func4 = crcmod.predefined.mkCrcFun("crc-16-maxim") #for location in table 4

def hash_64bits(inp):
	b=bytes(str(inp),encoding="ascii")
	return np.concatenate([bitmap[crc16_func1(b)],bitmap[crc16_func2(b)],bitmap[crc16_func3(b)],bitmap[crc16_func4(b)]])

def make_hash_bits(seed=0):
	return lambda x: hash_64bits((seed,x,"-",seed,x))

def hash_64int(inp):
	b=bytes(str(inp),encoding="ascii")
	return (crc16_func1(b)<<48)+(crc16_func2(b)<<32)+(crc16_func3(b)<<16)+(crc16_func4(b))

def make_hash_int(seed=0):
	return lambda x: hash_64int((x,seed,x,"-",seed,x))

# NitroSketch-UnivMon

def max_continuous_1(arr):
	N=len(arr)
	for i in range(N):
		if arr[i]==0:
			return i
	return N

import collections
class TopK:
	def __init__(self, K=20):
		self.K=K
		self.counter=collections.Counter()
	def update(self, key, count):
		self.counter[key]=count
		if len(self.counter)>self.K*4:
			topk=self.counter.most_common(self.K*2)
			self.counter=collections.Counter()
			for i,c in topk:
				self.counter[i]=c
	def topk(self):
		return self.counter.most_common(self.K)
class NS_UM:
	def __init__(self,R=4,C=1024,L=16,Heapsize=20,pspec=0.01, seedbase=0):
		self.R=R
		self.C=C
		self.L=L
        
		pl0=pspec/L/C # approximately equal share across all layers
		self.p=[min(1,pl0*(2**i)) for i in range(L)]
		#self.p=[pl0 for i in range(L)]
		# could also use same P
		
		self.CS=[np.zeros((R,C)) for i in range(L)]
		self.topKs=[TopK(Heapsize) for i in range(L)]
		
		self.hashesA=[make_hash_int(seedbase+i) for i in range(R)]
		self.hashesB=[make_hash_bits(seedbase+10000+i) for i in range(R)]
		self.layer_hash=make_hash_bits(-seedbase*3)

	def queryLayer(self,l,flowid):
		def read(i):
			ha=self.hashesA[i](flowid)
			hb=self.hashesB[i](flowid)
			j=ha % self.C
			pn=1-2*hb[0]
			return self.CS[l][i][j]*pn
		return np.median([read(i) for i in range(self.R)])
	
	def insert(self, flowid, count=1):
		memA=0
		
		# always insert to level 0, max is L
		hbits=self.layer_hash(flowid)
		hbits[0]=1 #always insert into layer 0, h0(i)=1
		MaxL=max_continuous_1(hbits)
		MaxL=min(MaxL, self.L)
		
		for l in range(MaxL):
			#each level independently decides
			p_update=self.p[l]
			for i in range(self.R):
				#each row decides update or not
				if random.random()<=p_update:
					memA+=1

					scale=1.0/p_update
					
					ha=self.hashesA[i](flowid)
					hb=self.hashesB[i](flowid)
					j=ha % self.C
					pn=1-2*hb[0]
					self.CS[l][i][j]+=count*pn*scale
					
					#maintain topK
					estimate=self.queryLayer(l,flowid)
					self.topKs[l].update(flowid,estimate)
		return memA
	 
	def calcG(self, g): 
		Y=np.zeros(self.L)
		Qbottom=self.topKs[self.L-1].topk()
		Y[self.L-1]=sum([g(cnt) for fid,cnt in Qbottom])  
		for j in reversed(range(self.L-1)):
			Qj=self.topKs[j].topk()
			
			Y[j]=2*Y[j+1]+sum([(1-2*self.layer_hash(fid)[j+1])*g(cnt) for fid,cnt in Qj])
		return Y[0]
	
	def countDistinct(self):
		return self.calcG(np.sign)

def run_NSUM(Trace, threshold=1000, repeat=20, p_configs=[1,1e-1,1e-2,1e-3,1e-4,1e-5,1e-6,1e-7], debug=False):
	activation_count={}
	for p in (p_configs):
		if debug:
			print("NSUM Experiment, trial p=",p)
		samples=[]
		iterator=range(repeat)
		if debug:
			iterator=tqdm.tqdm(iterator)
		for seedbase in iterator:
			obj=NS_UM(pspec=p, seedbase=seedbase)
			gt=set()
			memAccess=[]
			for i in range(len(Trace)):
				key=getKey(Trace[i])
				gt.add(key)
				memAccess.append(obj.insert(key))
				estimate=obj.countDistinct()
				if estimate>=threshold:
					break
			samples.append([len(gt), np.mean(memAccess), i])
		activation_count[(p,threshold)]=samples
	return activation_count

# Sampling
# Code adapted from Bruce Spang`s work "On estimating the number of flows"
import pydistinct
from pydistinct.stats_estimators import chao_estimator

class SamplingDistinctCounter_chao:
	def __init__(self, p=0.1,seedbase=0):
		random.seed(seedbase)
		self.p=p
		self.samples=[]
	def insert(self,flowid):
		if random.random()<self.p:
			self.samples.append(flowid)
			return 1
		return 0
	def countDistinct(self):
		return chao_estimator(self.samples)

def run_Sampling(Trace, threshold=1000, repeat=20, p_configs=[1,1e-1,1e-2,1e-3,1e-4,1e-5,1e-6,1e-7], debug=False):
	activation_count={}
	for p in (p_configs):
		if debug:
			print("Sampling Experiment, trial p=",p)
		samples=[]
		iterator=range(repeat)
		if debug:
			iterator=tqdm.tqdm(iterator)
		for seedbase in iterator:
			obj=SamplingDistinctCounter_chao(p=p, seedbase=seedbase)
			gt=set()
			memAccess=[]
			for i in range(len(Trace)):
				key=getKey(Trace[i])
				gt.add(key)
				memAccess.append(obj.insert(key))
				estimate=obj.countDistinct()
				if estimate>=threshold:
					break
			samples.append([len(gt), np.mean(memAccess), i])
		activation_count[(p,threshold)]=samples
	return activation_count


# Coupon Collector
# A simpler implementation. 
class CouponCollector:
	def __init__(self, n=4,m=8,invp=128, seedbase=0):
		random.seed(seedbase)
		self.n=n
		self.m=m
		self.invp=invp 
		# each coupon has p=1/invp probability being activated
		self.coupons=[False for i in range(m)]
		self.hashfn=make_hash_int(seedbase*1000)
	def insert(self,flowid):
		cc_id= (self.hashfn(flowid) % 100000007) % self.invp
		if cc_id < self.m:
			self.coupons[cc_id]=True
			return 1
		return 0
	def satisfied(self):
		return sum(self.coupons)>=self.n

# Reuse the compiler to find configuration
from .lib_compiler import find_best_cc_partial_smart
def run_CC(Trace, threshold=1000, repeat=20, p_configs=[1,1e-1,1e-2,1e-3,1e-4,1e-5,1e-6,1e-7], debug=False):
	activation_count={}
	for p in (p_configs):
		if debug:
			print("Sampling Experiment, trial p=",p)
		samples=[]
		iterator=range(repeat)
		if debug:
			iterator=tqdm.tqdm(iterator)
		for seedbase in iterator:
			(inv_prob, (num_to_collect,max_coupons_allowed), _, _)=find_best_cc_partial_smart(p,1.0,threshold)
			obj=CouponCollector(n=num_to_collect,m=max_coupons_allowed,invp=inv_prob, seedbase=seedbase)
			gt=set()
			memAccess=[]
			for i in range(len(Trace)):
				key=getKey(Trace[i])
				gt.add(key)
				memAccess.append(obj.insert(key))
				if obj.satisfied():
					break
			samples.append([len(gt), np.mean(memAccess), i])
		activation_count[(p,threshold)]=samples
	return activation_count



# Plotting
def parse_memA_acc(FN):
    activation_count=pickle.load(open(FN,"rb"))
    memA_list=[]
    acc_list=[]
    for p,th in activation_count.keys():
        x=activation_count[(p,th)]
        s=[i[0] for i in x]
        memA=np.mean([i[1] for i in x])
        relAcc=mean_rel_err(s,th)

        memA_list.append(memA)
        acc_list.append(relAcc)
    return memA_list,acc_list

def plot_memA_acc(memA, acc, FN):
    fig, ax = plt.subplots()
    ax.semilogx(memA, acc, '-x')
    #
    plt.xlabel("Average memory access per packet")
    plt.ylabel("Mean Relative Error")
    ax.yaxis.set_major_formatter( matplotlib.ticker.FuncFormatter(lambda x, pos: '%d%%' % (x*100, )) )
    plt.savefig(FN)