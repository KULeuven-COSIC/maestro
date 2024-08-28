use crate::rep3_core::party::error::MpcResult;

use crate::wollut16::{self, RndOhv16Output};

use super::WL16ASParty;


pub fn generate_random_ohv16(party: &mut WL16ASParty, n: usize, use_bitstring_check: bool) -> MpcResult<Vec<RndOhv16Output>> {
    if use_bitstring_check {
        wollut16::offline::generate_random_ohv16_bitstring(&mut party.inner, &mut party.gf64_triples_to_check, n)
    }else{
        wollut16::offline::generate_random_ohv16(&mut party.inner, &mut party.gf2_triples_to_check, n)
    }
}

pub fn generate_random_ohv16_mt(party: &mut WL16ASParty, n: usize, use_bitstring_check: bool) -> MpcResult<Vec<RndOhv16Output>> {
    if use_bitstring_check {
        wollut16::offline::generate_random_ohv16_bitstring_mt(&mut party.inner, &mut party.gf64_triples_to_check, n)
    }else{
        wollut16::offline::generate_random_ohv16_mt(&mut party.inner, &mut party.gf2_triples_to_check, n)
    }
}

#[cfg(test)]
mod test {
    use crate::rep3_core::test::TestSetup;

    use crate::{wollut16::offline::test::check_correct_rnd_ohv16, wollut16_malsec::{offline::{generate_random_ohv16, generate_random_ohv16_mt}, test::{WL16ASSetup, WL16BitString, WL16DefaultParams}, WL16ASParty}};


    #[test]
    fn random_ohv16() {
        const N: usize = 10000;
        let program = || {
            |p: &mut WL16ASParty| {
                let rnd = generate_random_ohv16(p, N, false).unwrap();
                // also check the triples
                p.verify_multiplications().unwrap();
                rnd
            }
        };

        let ((o1, _), (o2, _), (o3, _)) = WL16ASSetup::<WL16DefaultParams>::localhost_setup(program(), program(), program());
        assert_eq!(o1.len(), N);
        assert_eq!(o2.len(), N);
        assert_eq!(o3.len(), N);
        check_correct_rnd_ohv16(o1, o2, o3);
    }

    #[test]
    fn random_ohv16_mt() {
        const N: usize = 10000;
        const N_THREADS: usize = 3;
        
        let program = || {
            |p: &mut WL16ASParty| {
                let rnd = generate_random_ohv16_mt(p, N, false).unwrap();
                // also check the triples
                p.verify_multiplications().unwrap();
                rnd
            }
        };

        let ((o1, _), (o2, _), (o3, _)) = WL16ASSetup::<WL16DefaultParams>::localhost_setup_multithreads(N_THREADS, program(), program(), program());
        assert_eq!(o1.len(), N);
        assert_eq!(o2.len(), N);
        assert_eq!(o3.len(), N);
        check_correct_rnd_ohv16(o1, o2, o3);
    }

    #[test]
    fn random_ohv16_bitstring_check() {
        const N: usize = 10000;
        let program = || {
            |p: &mut WL16ASParty| {
                let rnd = generate_random_ohv16(p, N, true).unwrap();
                // also check the triples
                p.verify_multiplications().unwrap();
                rnd
            }
        };

        let ((o1, _), (o2, _), (o3, _)) = WL16ASSetup::<WL16BitString>::localhost_setup(program(), program(), program());
        assert_eq!(o1.len(), N);
        assert_eq!(o2.len(), N);
        assert_eq!(o3.len(), N);
        check_correct_rnd_ohv16(o1, o2, o3);
    }

    #[test]
    fn random_ohv16_mt_bitstring_check() {
        const N: usize = 10000;
        const N_THREADS: usize = 3;
        
        let program = || {
            |p: &mut WL16ASParty| {
                let rnd = generate_random_ohv16_mt(p, N, true).unwrap();
                // also check the triples
                p.verify_multiplications().unwrap();
                rnd
            }
        };

        let ((o1, _), (o2, _), (o3, _)) = WL16ASSetup::<WL16BitString>::localhost_setup_multithreads(N_THREADS, program(), program(), program());
        assert_eq!(o1.len(), N);
        assert_eq!(o2.len(), N);
        assert_eq!(o3.len(), N);
        check_correct_rnd_ohv16(o1, o2, o3);
    }
}