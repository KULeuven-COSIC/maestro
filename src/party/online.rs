use sha2::Sha256;
use crate::network::CommChannel;
use crate::party::broadcast::{Broadcast, BroadcastContext};
use crate::party::error::MpcResult;
use crate::party::offline::MulTriple;
use crate::party::Party;
use crate::share::{Field, FieldDigestExt, FieldVectorCommChannel, RssShare};





pub fn add<F: Field>(a: &RssShare<F>, b: &RssShare<F>) -> RssShare<F> {
    RssShare {
        si: a.si.clone() + b.si.clone(),
        sii: a.sii.clone() + b.sii.clone(),
    }
}

pub fn sub<F: Field>(a: &RssShare<F>, b: &RssShare<F>) -> RssShare<F> {
    RssShare {
        si: a.si.clone() - b.si.clone(),
        sii: a.sii.clone() - b.sii.clone(),
    }
}



pub fn vector_add<F: Field>(a: &[RssShare<F>], b: &[RssShare<F>]) -> Vec<RssShare<F>> {
    debug_assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(aj, bj)| add(aj, bj)).collect()
}

pub fn vector_sub<'a, 'b, F: Field + 'a + 'b, I1, I2: Iterator>(a: I1, b: I2) -> Vec<RssShare<F>>
    where I1: Iterator<Item=&'a RssShare<F>>,
          I2: Iterator<Item=&'b RssShare<F>>
{
    //debug_assert_eq!(a.len(), b.len());
    a.zip(b).map(|(aj, bj)| sub(aj, bj)).collect()
}

pub fn vector_mul<F: Field>(party: &mut Party, context: &mut BroadcastContext, x: &[RssShare<F>], y: &[RssShare<F>], triples: Vec<MulTriple<F>>) -> MpcResult<Vec<RssShare<F>>>
    where CommChannel: FieldVectorCommChannel<F>,
          Sha256: FieldDigestExt<F>
{
    debug_assert_eq!(x.len(), y.len());
    debug_assert_eq!(x.len(), triples.len());
    let mut opens_si = Vec::with_capacity(2 * x.len());
    let mut opens_sii = Vec::with_capacity(2 * x.len());
    // sigma = x - a
    let sigma = vector_sub(x.iter(), triples.iter().map(|t| &t.a));
    for s in sigma {
        opens_si.push(s.si);
        opens_sii.push(s.sii);
    }
    // gamma = y - b
    let gamma = vector_sub(y.iter(), triples.iter().map(|t| &t.b));
    for s in gamma {
        opens_si.push(s.si);
        opens_sii.push(s.sii);
    }
    // open sigma, gamma
    let opens = party.open_rss(context, &opens_si, &opens_sii)?;

    // c + y * sigma + x * gamma - sigma * gamma
    let mut result = Vec::with_capacity(x.len());
    for (i, triple) in triples.into_iter().enumerate() {
        let sigma = &opens[i];
        let gamma = &opens[x.len() + i];
        let mut r = triple.c + y[i].clone() * sigma.clone() + x[i].clone() * gamma.clone();
        if party.i == 0 {
            r.si = r.si - sigma.clone() * gamma.clone();
        } else if party.i == 2 {
            r.sii = r.sii - sigma.clone() * gamma.clone();
        }
        result.push(r);
    }
    Ok(result)
}

#[cfg(test)]
mod test {
    use rand::thread_rng;
    use crate::party::broadcast::{Broadcast, BroadcastContext};
    use crate::party::offline::create_correct_mul_triples;
    use crate::party::online::{vector_add, vector_mul, vector_sub};
    use crate::party::Party;
    use crate::party::test::localhost_setup;
    use crate::share::{FieldRngExt, RssShare};
    use crate::share::field::GF8;
    use crate::share::test::{assert_eq, consistent, secret_share};

    fn random_gf8(n: usize) -> (Vec<GF8>, Vec<RssShare<GF8>>, Vec<RssShare<GF8>>, Vec<RssShare<GF8>>) {
        let mut rng = thread_rng();
        let a = rng.generate(n);

        // into secret shares
        let mut  a1 = Vec::new();
        let mut a2 = Vec::new();
        let mut a3 = Vec::new();
        for ai in &a {
            let (x1, x2, x3) = secret_share(&mut rng, ai);
            a1.push(x1);
            a2.push(x2);
            a3.push(x3);
        }

        (a, a1,a2,a3)
    }

    #[test]
    fn vector_add_gf8() {
        const N: usize = 100;
        let (a, a1, a2, a3) = random_gf8(N);
        let (b, b1, b2, b3) = random_gf8(N);

        let c1 = vector_add(&a1, &b1);
        let c2 = vector_add(&a2, &b2);
        let c3 = vector_add(&a3, &b3);

        for i in 0..c1.len() {
            consistent(&c1[i], &c2[i], &c3[i]);
        }
        for (i, (c1, (c2, c3))) in c1.into_iter().zip(c2.into_iter().zip(c3)).enumerate() {
            assert_eq(c1, c2, c3, a[i] + b[i]);
        }
    }

    #[test]
    fn vector_sub_gf8() {
        const N: usize = 100;
        let (a, a1, a2, a3) = random_gf8(N);
        let (b, b1, b2, b3) = random_gf8(N);

        let c1 = vector_sub(a1.iter(), b1.iter());
        let c2 = vector_sub(a2.iter(), b2.iter());
        let c3 = vector_sub(a3.iter(), b3.iter());

        for i in 0..c1.len() {
            consistent(&c1[i], &c2[i], &c3[i]);
        }
        for (i, (c1, (c2, c3))) in c1.into_iter().zip(c2.into_iter().zip(c3)).enumerate() {
            assert_eq(c1, c2, c3, a[i] - b[i]);
        }
    }

    #[test]
    fn vector_mul_gf8() {
        const N: usize = 100;
        const SOUNDNESS: usize = 40;
        let (a, a1, a2, a3) = random_gf8(N);
        let (b, b1, b2, b3) = random_gf8(N);

        let program = |ai: Vec<_>, bi: Vec<_>| {
            move |p: &mut Party| {
                let triples = create_correct_mul_triples(p, N, SOUNDNESS).unwrap();
                let mut context = BroadcastContext::new();
                let c = vector_mul(p, &mut context, &ai, &bi, triples).unwrap();
                p.compare_view(context).unwrap();
                c
            }
        };

        let (h1, h2, h3) = localhost_setup(program(a1, b1), program(a2, b2), program(a3, b3));
        let (c1, _) = h1.join().unwrap();
        let (c2, _) = h2.join().unwrap();
        let (c3, _) = h3.join().unwrap();

        assert_eq!(c1.len(), N);
        assert_eq!(c2.len(), N);
        assert_eq!(c3.len(), N);

        for i in 0..N {
            consistent(&c1[i], &c2[i], &c3[i]);
        }
        for (i, (c1, (c2, c3))) in c1.into_iter().zip(c2.into_iter().zip(c3)).enumerate() {
            assert_eq(c1, c2, c3, a[i] * b[i]);
        }
    }
}