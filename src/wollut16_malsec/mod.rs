//! This module implements the maliciously-secure oblivious AES protocol "WOL LUT 16".

use crate::{
    network::ConnectedParty,
    party::{broadcast::BroadcastContext, error::MpcResult, MainParty},
    share::{gf4::BsGF4, Field},
    wollut16::RndOhvOutput,
};

mod mult_verification;
mod offline;
pub mod online;

/// Party for WOLLUT16 with active security
pub struct WL16ASParty{
    inner: MainParty,
    prep_ohv: Vec<RndOhvOutput>,
    // Multiplication triples that need checking at the end
    gf4_triples_to_check: MulTripleVector<BsGF4>,
    broadcast_context: BroadcastContext,
}

impl WL16ASParty {
    pub fn setup(connected: ConnectedParty, n_worker_threads: Option<usize>) -> MpcResult<Self> {
        MainParty::setup(connected, n_worker_threads).map(|party| Self {
            inner: party,
            prep_ohv: Vec::new(),
            gf4_triples_to_check: MulTripleVector::new(),
            broadcast_context: BroadcastContext::new(),
        })
    }
}

struct MulTripleVector<F: Field> {
    // s.t. a*b = c
    a_i: Vec<F>,
    a_ii: Vec<F>,
    b_i: Vec<F>,
    b_ii: Vec<F>,
    c_i: Vec<F>,
    c_ii: Vec<F>,
}

impl<F: Field> MulTripleVector<F> {
    pub fn new() -> Self {
        Self {
            a_i: Vec::new(),
            a_ii: Vec::new(),
            b_i: Vec::new(),
            b_ii: Vec::new(),
            c_i: Vec::new(),
            c_ii: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.a_i.len()
    }

    pub fn shrink(&mut self, new_length: usize) {
        self.a_i.truncate(new_length);
        self.a_ii.truncate(new_length);
        self.b_i.truncate(new_length);
        self.b_ii.truncate(new_length);
        self.c_i.truncate(new_length);
        self.c_ii.truncate(new_length);
    }

    pub fn push(&mut self, ai: F, aii: F, bi: F, bii: F, ci: F, cii: F) {
        self.a_i.push(ai);
        self.a_ii.push(aii);
        self.b_i.push(bi);
        self.b_ii.push(bii);
        self.c_i.push(ci);
        self.c_ii.push(cii);
    }
}

#[cfg(test)]
mod test {
    use std::thread::JoinHandle;

    use crate::{
        network::ConnectedParty,
        party::test::{localhost_connect, TestSetup},
    };

    use super::WL16ASParty;

    pub fn localhost_setup_wl16as<T1: Send + 'static, F1: Send + FnOnce(&mut WL16ASParty) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(&mut WL16ASParty) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(&mut WL16ASParty) -> T3 + 'static>(f1: F1, f2: F2, f3: F3, n_worker_threads: Option<usize>) -> (JoinHandle<(T1,WL16ASParty)>, JoinHandle<(T2,WL16ASParty)>, JoinHandle<(T3,WL16ASParty)>) {
        fn adapter<T, Fx: FnOnce(&mut WL16ASParty)->T>(conn: ConnectedParty, f: Fx, n_worker_threads: Option<usize>) -> (T,WL16ASParty) {
            let mut party = WL16ASParty::setup(conn, n_worker_threads).unwrap();
            let t = f(&mut party);
            // party.finalize().unwrap();
            party.inner.teardown().unwrap();
            (t, party)
        }
        localhost_connect(move |conn_party| adapter(conn_party, f1, n_worker_threads), move |conn_party| adapter(conn_party, f2, n_worker_threads), move |conn_party| adapter(conn_party, f3, n_worker_threads))
    }

    pub struct WL16ASSetup;
    impl TestSetup<WL16ASParty> for WL16ASSetup {
        fn localhost_setup<T1: Send + 'static, F1: Send + FnOnce(&mut WL16ASParty) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(&mut WL16ASParty) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(&mut WL16ASParty) -> T3 + 'static>(f1: F1, f2: F2, f3: F3) -> (std::thread::JoinHandle<(T1,WL16ASParty)>, std::thread::JoinHandle<(T2,WL16ASParty)>, std::thread::JoinHandle<(T3,WL16ASParty)>) {
            localhost_setup_wl16as(f1, f2, f3, None)
        }
        fn localhost_setup_multithreads<T1: Send + 'static, F1: Send + FnOnce(&mut WL16ASParty) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(&mut WL16ASParty) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(&mut WL16ASParty) -> T3 + 'static>(n_threads: usize, f1: F1, f2: F2, f3: F3) -> (JoinHandle<(T1,WL16ASParty)>, JoinHandle<(T2,WL16ASParty)>, JoinHandle<(T3,WL16ASParty)>) {
            localhost_setup_wl16as(f1, f2, f3, Some(n_threads))
        }
    }
}
