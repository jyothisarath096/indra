//! Deterministic transport/oracle substrate for the Phase 3 audit.
//! Consensus transitions are intentionally not simulated here; integration
//! adapters must call the production driver and feed resulting envelopes back.
use rand::{seq::SliceRandom, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope { pub id: u64, pub src: usize, pub dst: usize, pub kind: String, pub height: u64, pub round: Option<u32>, pub created: u64, pub deliver: u64 }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceEntry { pub tick: u64, pub seq: u64, pub src: usize, pub dst: usize, pub action: String, pub kind: String, pub height: u64, pub round: Option<u32> }

pub struct Network { pub tick: u64, pub gst: Option<u64>, pub delta: u64, next_id: u64, next_seq: u64, queue: VecDeque<Envelope>, blocked: HashSet<(usize, usize)>, disconnected: HashSet<usize>, pub trace: Vec<TraceEntry>, rng: ChaCha8Rng }
impl Network {
    pub fn new(seed: u64, delta: u64) -> Self { Self { tick: 0, gst: None, delta, next_id: 1, next_seq: 1, queue: VecDeque::new(), blocked: HashSet::new(), disconnected: HashSet::new(), trace: Vec::new(), rng: ChaCha8Rng::seed_from_u64(seed) } }
    pub fn set_gst(&mut self, tick: u64) { self.gst = Some(tick); }
    pub fn partition(&mut self, a: &[usize], b: &[usize]) { for &x in a { for &y in b { self.blocked.insert((x,y)); self.blocked.insert((y,x)); } } }
    pub fn heal_partition(&mut self) { self.blocked.clear(); }
    pub fn disconnect(&mut self, n: usize) { self.disconnected.insert(n); }
    pub fn reconnect(&mut self, n: usize) { self.disconnected.remove(&n); }
    pub fn send(&mut self, src: usize, dst: usize, kind: impl Into<String>, height: u64, round: Option<u32>, delay: u64) -> Result<u64, &'static str> {
        if self.disconnected.contains(&src) || self.disconnected.contains(&dst) || self.blocked.contains(&(src,dst)) { return Err("delivery blocked"); }
        let d = self.tick.saturating_add(delay);
        if let Some(gst) = self.gst { if self.tick >= gst && src != dst && delay > self.delta { return Err("GST bound exceeded"); } }
        let id = self.next_id; self.next_id += 1;
        self.queue.push_back(Envelope { id, src, dst, kind: kind.into(), height, round, created: self.tick, deliver: d });
        self.trace.push(TraceEntry { tick: self.tick, seq: self.next_seq, src, dst, action: "enqueue".into(), kind: self.queue.back().unwrap().kind.clone(), height, round }); self.next_seq += 1; Ok(id)
    }
    pub fn reorder(&mut self) { let mut v: Vec<_> = self.queue.drain(..).collect(); v.shuffle(&mut self.rng); self.queue.extend(v); }
    pub fn advance(&mut self, ticks: u64) { self.tick = self.tick.saturating_add(ticks); }
    pub fn deliver_ready(&mut self) -> Vec<Envelope> { let mut out = Vec::new(); let mut keep = VecDeque::new(); while let Some(e) = self.queue.pop_front() { if e.deliver <= self.tick { self.trace.push(TraceEntry { tick:self.tick, seq:self.next_seq, src:e.src,dst:e.dst,action:"deliver".into(),kind:e.kind.clone(),height:e.height,round:e.round }); self.next_seq+=1; out.push(e); } else { keep.push_back(e); } } self.queue=keep; out }
    pub fn pending(&self) -> usize { self.queue.len() }
}

#[derive(Default)]
pub struct SafetyOracle { finalized: HashMap<u64, [u8;32]>, votes: HashMap<(usize,u64,u32,u8), [u8;32]>, committed: HashMap<usize,u64> }
impl SafetyOracle {
    pub fn observe_finalized(&mut self, h:u64, hash:[u8;32]) -> Result<(),String> { if let Some(old)=self.finalized.insert(h,hash) { if old!=hash { return Err(format!("conflicting finalized hash at {h}")); } } Ok(()) }
    pub fn observe_vote(&mut self, n:usize,h:u64,r:u32,s:u8,hash:[u8;32],honest:bool)->Result<(),String>{ if !honest{return Ok(());} if let Some(old)=self.votes.insert((n,h,r,s),hash){if old!=hash{return Err("honest conflicting vote".into())}} Ok(()) }
    pub fn observe_commit(&mut self,n:usize,h:u64)->Result<(),String>{let e=self.committed.entry(n).or_insert(h);if h<*e{return Err("committed height regression".into())}*e=h;Ok(())}
}

#[cfg(test)] mod tests {
 use super::*;
 #[test] fn partition_and_heal(){let mut n=Network::new(1,2);n.partition(&[0,1],&[2,3]);assert!(n.send(0,2,"vote",1,Some(0),0).is_err());n.heal_partition();assert!(n.send(0,2,"vote",1,Some(0),0).is_ok());}
 #[test] fn gst_bound(){let mut n=Network::new(1,2);n.set_gst(0);assert!(n.send(0,1,"vote",1,Some(0),2).is_ok());assert!(n.send(0,1,"vote",1,Some(0),3).is_err());}
 #[test] fn deterministic_seed(){let mut a=Network::new(7,2);let mut b=Network::new(7,2);for i in 0..8{a.send(0,1,"x",i,None,0).unwrap();b.send(0,1,"x",i,None,0).unwrap();}a.reorder();b.reorder();assert_eq!(a.queue,b.queue);}
 #[test] fn oracle_detects_conflict(){let mut o=SafetyOracle::default();o.observe_finalized(1,[1;32]).unwrap();assert!(o.observe_finalized(1,[2;32]).is_err());}
}
