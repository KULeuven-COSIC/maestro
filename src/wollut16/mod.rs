//! This module implements the semi-honest oblivious AES protocol "WOL LUT 16".
//!
//!


use crate::{chida::ChidaParty, network::{task::IoLayer, ConnectedParty}, party::{error::MpcResult, ArithmeticBlackBox}, share::{gf4::GF4, Field}};

mod online;
mod offline;

// Party for WOLLUT16
pub struct WL16Party {
    inner: ChidaParty,
    prep_ohv: Vec<RndOhvOutput>,
}

// a random one-hot vector of size 16
#[derive(PartialEq,Debug)]
pub struct RndOhv16(u16);

/// Output of the random one-hot vector pre-processing.
/// Contains a (2,3)-sharing of a size 16 one-hot vector `RndOhv16` and a (3,3)-sharing of the corresponding `GF4` element that indicates
/// the position of 1 in the vector.
pub struct RndOhvOutput {
    /// share i of one-hot vector
    pub si: RndOhv16,
    /// share i+1 of one-hot vector
    pub sii: RndOhv16,
    /// (3,3) sharing of the position of the 1 in the vector
    pub random: GF4,
}

impl WL16Party {
    pub fn setup(connected: ConnectedParty) -> MpcResult<Self> {
        ChidaParty::setup(connected).map(|party| {
            Self {
                inner: party,
                prep_ohv: Vec::new(),
            }
        })
    }

    pub fn prepare_rand_ohv(&mut self, n: usize) -> MpcResult<()> {
        let mut new = offline::generate_random_ohv16(&mut self.inner, n)?;
        if self.prep_ohv.is_empty() {
            self.prep_ohv = new;
        }else{
            self.prep_ohv.append(&mut new);
        }
        Ok(())
    }

    pub fn io(&self) -> &IoLayer {
        <ChidaParty as ArithmeticBlackBox<GF4>>::io(&self.inner)
    }
}

impl RndOhv16 {
    pub fn lut(&self, offset: usize, table: &[u8; 16]) -> GF4 {
        let mut res = GF4::ZERO;
        for i in 0..16_usize {
            if ((self.0 >> i) & 0x1) == 0x1 {
                res += GF4::new_unchecked(table[i ^ offset]);
            }
        }
        res
    }
}

#[cfg(test)]
mod test {
    use std::thread::JoinHandle;


    use crate::{network::ConnectedParty, party::test::{localhost_connect, TestSetup}};

    use super::WL16Party;

    pub fn localhost_setup_wl16<T1: Send + 'static, F1: Send + FnOnce(&mut WL16Party) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(&mut WL16Party) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(&mut WL16Party) -> T3 + 'static>(f1: F1, f2: F2, f3: F3) -> (JoinHandle<(T1,WL16Party)>, JoinHandle<(T2,WL16Party)>, JoinHandle<(T3,WL16Party)>) {
        fn adapter<T, Fx: FnOnce(&mut WL16Party)->T>(conn: ConnectedParty, f: Fx) -> (T,WL16Party) {
            let mut party = WL16Party::setup(conn).unwrap();
            let t = f(&mut party);
            // party.finalize().unwrap();
            party.inner.teardown().unwrap();
            (t, party)
        }
        localhost_connect(|conn_party| adapter(conn_party, f1), |conn_party| adapter(conn_party, f2), |conn_party| adapter(conn_party, f3))
    }

    pub struct WL16Setup;
    impl TestSetup<WL16Party> for WL16Setup {
        fn localhost_setup<T1: Send + 'static, F1: Send + FnOnce(&mut WL16Party) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(&mut WL16Party) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(&mut WL16Party) -> T3 + 'static>(f1: F1, f2: F2, f3: F3) -> (std::thread::JoinHandle<(T1,WL16Party)>, std::thread::JoinHandle<(T2,WL16Party)>, std::thread::JoinHandle<(T3,WL16Party)>) {
            localhost_setup_wl16(f1, f2, f3)
        }
    }
}