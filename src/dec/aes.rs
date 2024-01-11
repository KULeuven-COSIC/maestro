// use crate::party::Party;
// use crate::share::field::GF8;
// use crate::share::RssShare;

// pub struct Aes128Key([RssShare<GF8>; 16]);

// pub struct Aes128State([RssShare<GF8>; 16]);

// struct VAes128State(Vec<Aes128State>);
// struct VAes128Key(Vec<Aes128Key>);

// pub fn aes(party: &mut Party, inputs: impl Iterator<Item=(Aes128Key,Aes128State)> + ExactSizeIterator) -> Vec<Aes128State> {
//     let mut states = Vec::with_capacity(inputs.len());
//     let mut keys = Vec::with_capacity(inputs.len());
//     for (key,state) in inputs {
//         states.push(state);
//         keys.push(key);
//     }

//     todo!()
// }