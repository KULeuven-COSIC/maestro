mod commitment;
mod correlated_randomness;
mod offline;
mod broadcast;
pub mod error;
mod online;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use crate::network::{CommChannel, ConnectedParty};
use crate::party::correlated_randomness::{GlobalRng, SharedRng};
use crate::share::{Field, FieldDigestExt, FieldRngExt, RssShare};


pub struct Party {
    pub i: usize,
    /// Channel to player i+1
    pub comm_next: CommChannel,
    /// Channel to player i-1
    pub comm_prev: CommChannel,
    random_next: SharedRng,
    random_prev: SharedRng,
    random_local: ChaCha20Rng,
}

impl Party {
    pub fn setup(mut party: ConnectedParty) -> Self {

        let mut rng = ChaCha20Rng::from_entropy();

        let (rand_next, rand_prev) = match party.i {
            0 => {
                let rand01 = SharedRng::setup_pairwise(&mut rng, &mut party.comm_next, 0, 1).unwrap();
                let rand02 = SharedRng::setup_pairwise(&mut rng, &mut party.comm_prev, 0, 2).unwrap();
                (rand01, rand02)
            }
            1 => {
                let rand01 = SharedRng::setup_pairwise(&mut rng, &mut party.comm_prev, 1, 0).unwrap();
                let rand12 = SharedRng::setup_pairwise(&mut rng, &mut party.comm_next, 1, 2).unwrap();
                (rand12, rand01)
            }
            2 => {
                let rand02 = SharedRng::setup_pairwise(&mut rng, &mut party.comm_next, 2, 0).unwrap();
                let rand12 = SharedRng::setup_pairwise(&mut rng, &mut party.comm_prev, 2, 1).unwrap();
                (rand02, rand12)
            }
            _ => unreachable!()
        };

        Self {
            i: party.i,
            comm_next: party.comm_next,
            comm_prev: party.comm_prev,
            random_next: rand_next,
            random_prev: rand_prev,
            random_local: rng
        }
    }

    pub fn setup_semi_honest(mut party: ConnectedParty) -> Self {
        let mut rng = ChaCha20Rng::from_entropy();
        let (rand_next, rand_prev) = SharedRng::setup_all_pairwise_semi_honest(&mut rng, &mut party.comm_next, &mut party.comm_prev).unwrap();
        Self {
            i: party.i,
            comm_next: party.comm_next,
            comm_prev: party.comm_prev,
            random_next: rand_next,
            random_prev: rand_prev,
            random_local: rng
        }
    }

    pub fn generate_zero<F: Field>(&mut self, global_rng: &mut GlobalRng, n: usize) -> Vec<RssShare<F>>
    where ChaCha20Rng: FieldRngExt<F>
    {
        let shares = global_rng.as_mut().generate(2*n);
        let mut zero_share = Vec::with_capacity(n);
        for r in shares.chunks_exact(2) {
            let share = match self.i {
                0 => RssShare::from(-r[0].clone() - r[1].clone(), r[0].clone()),
                1 => RssShare::from(r[0].clone(), r[1].clone()),
                2 => RssShare::from(r[1].clone(), -r[0].clone() - r[1].clone()),
                _ => unreachable!()
            };
            zero_share.push(share);
        }
        zero_share
    }

    /// returns alpha_i s.t. alpha_1 + alpha_2 + alpha_3 = 0
    pub fn generate_alpha<F: Field>(&mut self, n: usize) -> Vec<F>
    where ChaCha20Rng: FieldRngExt<F>
    {
        self.random_next.as_mut().generate(n).into_iter().zip(
            self.random_prev.as_mut().generate(n).into_iter()
        ).map(|(next, prev)| next - prev).collect()
    }

    pub fn generate_random<F: Field>(&mut self, n: usize) -> Vec<RssShare<F>>
    where ChaCha20Rng: FieldRngExt<F>
    {
        let si = self.random_prev.as_mut().generate(n);
        let sii = self.random_next.as_mut().generate(n);
        si.into_iter().zip(sii).map(|(si,sii)| RssShare::from(si,sii)).collect()
    }
}


#[cfg(test)]
pub mod test {
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;
    use std::thread;
    use std::thread::JoinHandle;
    use rand::RngCore;
    use crate::network::{Config, ConnectedParty, CreatedParty};
    use crate::party::correlated_randomness::{GlobalRng, SharedRng};
    use crate::party::Party;
    use crate::share::field::GF8;
    use crate::share::test::{assert_eq, consistent};

    pub fn localhost_connect<T1: Send + 'static, F1: Send + FnOnce(ConnectedParty) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(ConnectedParty) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(ConnectedParty) -> T3 + 'static>(f1: F1, f2: F2, f3: F3) -> (JoinHandle<T1>, JoinHandle<T2>, JoinHandle<T3>) {
        let addr: Vec<Ipv4Addr> = (0..3).map(|_| Ipv4Addr::from_str("127.0.0.1").unwrap()).collect();
        let party1 = CreatedParty::bind(0, IpAddr::V4(addr[0]), 0).unwrap();
        let party2 = CreatedParty::bind(1, IpAddr::V4(addr[1]), 0).unwrap();
        let party3 = CreatedParty::bind(2, IpAddr::V4(addr[2]), 0).unwrap();

        // get ports
        let port1 = party1.port().unwrap();
        let port2 = party2.port().unwrap();
        let port3 = party3.port().unwrap();

        let ports = vec![port1, port2, port3];
        // println!("Ports: {:?}", ports);

        let party1 = {
            let config = Config::new( addr, ports.clone());
            thread::spawn(move || {
                // println!("P1 running");
                let party1 = party1.connect(config).unwrap();
                // println!("P1 connected");
                let res = f1(party1);
                res
            })
        };

        let party2 = {
            let addr: Vec<Ipv4Addr> = (0..3).map(|_| Ipv4Addr::from_str("127.0.0.1").unwrap()).collect();
            let config = Config::new(addr, ports.clone());
            thread::spawn(move || {
                // println!("P2 running");
                let party2 = party2.connect(config).unwrap();
                // println!("P2 connected");
                let res = f2(party2);
                res
            })
        };

        let party3 = {
            let addr: Vec<Ipv4Addr> = (0..3).map(|_| Ipv4Addr::from_str("127.0.0.1").unwrap()).collect();
            let config = Config::new(addr, ports);
            thread::spawn(move || {
                // println!("P3 running");
                let party3 = party3.connect(config).unwrap();
                // println!("P3 connected");
                let res = f3(party3);
                res
            })
        };

        (party1, party2, party3)
    }

    pub fn localhost_setup<T1: Send + 'static, F1: Send + FnOnce(&mut Party) -> T1 + 'static, T2: Send + 'static, F2: Send + FnOnce(&mut Party) -> T2 + 'static, T3: Send + 'static, F3: Send + FnOnce(&mut Party) -> T3 + 'static>(f1: F1, f2: F2, f3: F3) -> (JoinHandle<(T1,Party)>, JoinHandle<(T2,Party)>, JoinHandle<(T3,Party)>) {
        let _f1 = |p: ConnectedParty| {
            // println!("P1: Before Setup");
            let mut p = Party::setup(p);
            // println!("P1: After Setup");
            let res = f1(&mut p);
            (res, p)
        };
        let _f2 = |p: ConnectedParty| {
            // println!("P2: Before Setup");
            let mut p = Party::setup(p);
            // println!("P2: After Setup");
            let res = f2(&mut p);
            (res, p)
        };
        let _f3 = |p: ConnectedParty| {
            // println!("P3: Before Setup");
            let mut p = Party::setup(p);
            // println!("P3: After Setup");
            let res = f3(&mut p);
            (res, p)
        };
        localhost_connect(_f1, _f2, _f3)
    }

    pub fn simple_localhost_setup<F: Send + Clone + Fn(&mut Party) -> T + 'static, T: Send + 'static>(f: F) -> ((T,T,T), (Party, Party, Party)) {
        let (h1, h2, h3) = localhost_setup(f.clone(), f.clone(), f);
        let (t1, p1) = h1.join().unwrap();
        let (t2, p2) = h2.join().unwrap();
        let (t3, p3) = h3.join().unwrap();
        ((t1, t2, t3), (p1,p2,p3))
    }

    #[test]
    //#[serial]
    fn correct_channel_connection() {
        let f1 = |mut p: ConnectedParty| {
            p.comm_next.write("P12".as_bytes()).unwrap();
            let mut buf = [0u8; 3];
            p.comm_prev.read(&mut buf).unwrap();
            assert_eq!(&buf, "P31".as_bytes());
        };
        let f2 = |mut p: ConnectedParty| {
            p.comm_next.write("P23".as_bytes()).unwrap();
            let mut buf = [0u8; 3];
            p.comm_prev.read(&mut buf).unwrap();
            assert_eq!(&buf, "P12".as_bytes());
        };
        let f3 = |mut p: ConnectedParty| {
            p.comm_next.write("P31".as_bytes()).unwrap();
            let mut buf = [0u8; 3];
            p.comm_prev.read(&mut buf).unwrap();
            assert_eq!(&buf, "P23".as_bytes());
        };
        let (p1, p2, p3) = localhost_connect(f1, f2, f3);
        p1.join().unwrap();
        p2.join().unwrap();
        p3.join().unwrap();
    }

    #[test]
    fn correct_party_setup() {
        let (_, (mut p1, mut p2, mut p3)) = simple_localhost_setup(|_|());
        // check correlated randomness
        fn assert_common_randomness(shared_random1: &mut SharedRng, shared_random2: &mut SharedRng) {
            let mut expected = [0u8; 100];
            let mut actual = [0u8; 100];
            shared_random1.as_mut().fill_bytes(&mut expected);
            shared_random2.as_mut().fill_bytes(&mut actual);
            assert_eq!(&expected, &actual);
        }

        assert_common_randomness(&mut p1.random_next, &mut p2.random_prev);
        assert_common_randomness(&mut p2.random_next, &mut p3.random_prev);
        assert_common_randomness(&mut p3.random_next, &mut p1.random_prev);

        // check local rngs are not correlated
        let mut buf1 = [0u8; 100];
        let mut buf2 = [0u8; 100];
        let mut buf3 = [0u8; 100];
        p1.random_local.fill_bytes(&mut buf1);
        p2.random_local.fill_bytes(&mut buf2);
        p3.random_local.fill_bytes(&mut buf3);

        assert_ne!(&buf1, &buf2);
        assert_ne!(&buf2, &buf3);
        assert_ne!(&buf1, &buf3);
    }

    #[test]
    fn correct_zeros_gf8() {
        const N: usize = 100;
        let ((z1, z2, z3), _) = simple_localhost_setup(|p| {
            let mut global_rng = GlobalRng::setup_global(p).unwrap();
            p.generate_zero(&mut global_rng, N)
        });

        for (z1, (z2, z3)) in z1.into_iter().zip(z2.into_iter().zip(z3)) {
            consistent(&z1, &z2, &z3);
            assert_eq(z1, z2, z3, GF8(0));
        }
    }
}