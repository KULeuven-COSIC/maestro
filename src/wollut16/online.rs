//! This module contains the online phase components.
//!
use itertools::{izip, Itertools};
use crate::{
    network::task::Direction, party::{error::MpcResult, Party}, share::{gf4::GF4, gf8::GF8, wol::{wol_inv_map, wol_map}, Field}
};


/// Computes `<<x * y>>` for `[[x]]` and `[[y]]` over GF4.
/// 
/// This function assumes that all input vectors are of the same length
#[inline]
fn local_multiplication(x_i: &[GF4], x_ii: &[GF4], y_i: &[GF4], y_ii: &[GF4]) -> Vec<GF4> {
    izip!(x_i,x_ii,y_i,y_ii).map(|(&x_i,&x_ii,&y_i,&y_ii)| {
        x_i * y_i + (x_i + x_ii) * (y_i + y_ii) 
    }).collect_vec()
}

/// Computes <<v>> for
/// 
/// This function assumes that all input vectors are of the same length
#[inline]
fn compute_v(ah_i_sq: &[GF4], al_i_sq: &[GF4], ah_mul_al: &[GF4]) -> Vec<GF4> {
    izip!(ah_i_sq,al_i_sq,ah_mul_al).map(|(&ah_i_sq,&al_i_sq,&ah_mul_al)| {
        ah_i_sq.mul_e() + ah_mul_al + al_i_sq
    }).collect_vec()  
}

/// Placeholder for the LUT protocol
fn LUT_layer(v: &[GF4]) -> (Vec<GF4>,Vec<GF4>) {
    todo!()
}

/// Concatenates two vectors
#[inline]
fn append(a: &[GF4], b: &[GF4]) -> Vec<GF4> {
    let mut res = vec![GF4::zero(); a.len() + b.len()];
    res[..a.len()].copy_from_slice(a);
    res[a.len()..].copy_from_slice(b);
    res
}

/// Share conversion protocol <<x>> to [[x]]
fn SS_to_RSS_layer(party: &mut Party, xss_i: &[GF4], x_i: &mut [GF4], x_ii: &mut [GF4]) -> MpcResult<()> {
    debug_assert_eq!(xss_i.len(), x_i.len());
    debug_assert_eq!(xss_i.len(), x_ii.len());
    let alphas:Vec<GF4> = party.generate_alpha(xss_i.len());
    //
    x_i.iter_mut().enumerate().for_each(|(j, y_i)| {
        *y_i = xss_i[j] + alphas[j]
    });
    party.io().send_field::<GF4>(Direction::Previous, x_i.iter());
    party.io().receive_field_slice(Direction::Next, x_ii).rcv()?;
    party.io().wait_for_completion();
    Ok(())
}

/**
This function implements multiplicative inversion as in `Protocol 2`.

Given a (2,3)-RSS shared vector [[x]] of elements in GF(2^8),
the protocol computes the component-wise multiplicative inverse.

The function inputs are:
- `party` - the local party `P_i``
- `si` - the first component of `[[x]]_i`
- `sii` - the second component of `[[x]]_i`

The output, the share [[x^-1]]_i, is written into `(s_i,s_ii)`.
*/
fn gf8_inv_layer(party: &mut Party, si: &mut [GF8], sii: &mut [GF8]) -> MpcResult<()> {
    let n = si.len();
    // Step 1: WOL-conversion
    let (ah_i,al_i): (Vec<GF4>,Vec<GF4>) = si.iter().map(wol_map).unzip();
    let (ah_ii,al_ii): (Vec<GF4>,Vec<GF4>) = sii.iter().map(wol_map).unzip();
    // Steps 2: Locally generate additive sharing of a_h^2 and a_l^2
    let ah_i_sq: Vec<GF4> = ah_i.iter().map(GF4::square).collect();
    let al_i_sq: Vec<GF4> = al_i.iter().map(GF4::square).collect();
    // Step 3: Locally generate additive sharing of ah * al
    let ah_mul_al = local_multiplication(&ah_i, &ah_ii, &al_i, &al_ii);
    // Step 4: Compute additive sharing of v
    let v = compute_v(&ah_i_sq,&al_i_sq,&ah_mul_al);
    // Step 5: Compute replicated sharing of v inverse
    let (v_inv_i, v_inv_ii) = LUT_layer(&v);
    // Step 6: Locally compute additive sharing of a_h' and a_l'
    let ah_plus_al_i:Vec<_> = ah_i.iter().zip(al_i).map(|(&ah_i,al_i)| ah_i+al_i).collect();
    let ah_plus_al_i:Vec<_> = ah_ii.iter().zip(al_ii).map(|(&ah_ii,al_ii)| ah_ii+al_ii).collect();
    let a_h_prime_ss = local_multiplication(&ah_i, &ah_ii,&v_inv_i, &v_inv_ii);
    let a_l_prime_ss = local_multiplication(&ah_i, &ah_ii,&v_inv_i, &v_inv_ii);
    // Step 7: Generate replicated sharing of a_h' and a_l'
    let mut a_h_a_l_i = vec![GF4::zero(); 2*n];
    let mut a_h_a_l_ii = vec![GF4::zero(); 2*n];
    SS_to_RSS_layer(party, &append(&a_h_prime_ss, &a_l_prime_ss), &mut a_h_a_l_i, &mut a_h_a_l_ii)?;
    // Step 8: WOL-back-conversion
    si.iter_mut().enumerate().for_each(|(j,s_i)|{
        *s_i = wol_inv_map(&a_h_a_l_i[j],&a_h_a_l_i[j+n])
    });
    sii.iter_mut().enumerate().for_each(|(j,s_i)|{
        *s_i = wol_inv_map(&a_h_a_l_ii[j],&a_h_a_l_ii[j+n])
    });
    Ok(())
}
