//! This module implements the maliciously-secure oblivious AES protocol "WOL LUT 16".

use crate::{
    network::ConnectedParty,
    party::{broadcast::BroadcastContext, error::MpcResult, Party},
    share::{gf4::GF4, gf8::GF8},
    wollut16::RndOhvOutput,
};

mod mult_verification;
mod offline;

/// Party for WOLLUT16 with active security
pub struct WL16ASParty {
    inner: Party,
    prep_ohv: Vec<RndOhvOutput>,
    // Multiplication triples that need checking at the end
    gf4_triples_to_check: MulTripleVector<GF4>,
    gf8_triples_to_check: MulTripleVector<GF8>,
    broadcast_context: BroadcastContext,
}

impl WL16ASParty {
    pub fn setup(connected: ConnectedParty) -> MpcResult<Self> {
        Party::setup(connected).map(|party| Self {
            inner: party,
            prep_ohv: Vec::new(),
            gf4_triples_to_check: MulTripleVector::new(),
            gf8_triples_to_check: MulTripleVector::new(),
            broadcast_context: BroadcastContext::new(),
        })
    }
}

struct MulTripleVector<F> {
    // s.t. a*b = c
    ai: Vec<F>,
    aii: Vec<F>,
    bi: Vec<F>,
    bii: Vec<F>,
    ci: Vec<F>,
    cii: Vec<F>,
}

impl<F> MulTripleVector<F> {
    pub fn new() -> Self {
        Self {
            ai: Vec::new(),
            aii: Vec::new(),
            bi: Vec::new(),
            bii: Vec::new(),
            ci: Vec::new(),
            cii: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.ai.len()
    }

    pub fn push(&mut self, ai: F, aii: F, bi: F, bii: F, ci: F, cii: F) {
        self.ai.push(ai);
        self.aii.push(aii);
        self.bi.push(bi);
        self.bii.push(bii);
        self.ci.push(ci);
        self.cii.push(cii);
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

    pub fn localhost_setup_wl16as<
        T1: Send + 'static,
        F1: Send + FnOnce(&mut WL16ASParty) -> T1 + 'static,
        T2: Send + 'static,
        F2: Send + FnOnce(&mut WL16ASParty) -> T2 + 'static,
        T3: Send + 'static,
        F3: Send + FnOnce(&mut WL16ASParty) -> T3 + 'static,
    >(
        f1: F1,
        f2: F2,
        f3: F3,
    ) -> (
        JoinHandle<(T1, WL16ASParty)>,
        JoinHandle<(T2, WL16ASParty)>,
        JoinHandle<(T3, WL16ASParty)>,
    ) {
        fn adapter<T, Fx: FnOnce(&mut WL16ASParty) -> T>(
            conn: ConnectedParty,
            f: Fx,
        ) -> (T, WL16ASParty) {
            let mut party = WL16ASParty::setup(conn).unwrap();
            let t = f(&mut party);
            // party.finalize().unwrap();
            party.inner.teardown().unwrap();
            (t, party)
        }
        localhost_connect(
            |conn_party| adapter(conn_party, f1),
            |conn_party| adapter(conn_party, f2),
            |conn_party| adapter(conn_party, f3),
        )
    }

    pub struct WL16ASSetup;
    impl TestSetup<WL16ASParty> for WL16ASSetup {
        fn localhost_setup<
            T1: Send + 'static,
            F1: Send + FnOnce(&mut WL16ASParty) -> T1 + 'static,
            T2: Send + 'static,
            F2: Send + FnOnce(&mut WL16ASParty) -> T2 + 'static,
            T3: Send + 'static,
            F3: Send + FnOnce(&mut WL16ASParty) -> T3 + 'static,
        >(
            f1: F1,
            f2: F2,
            f3: F3,
        ) -> (
            std::thread::JoinHandle<(T1, WL16ASParty)>,
            std::thread::JoinHandle<(T2, WL16ASParty)>,
            std::thread::JoinHandle<(T3, WL16ASParty)>,
        ) {
            localhost_setup_wl16as(f1, f2, f3)
        }
    }
}
