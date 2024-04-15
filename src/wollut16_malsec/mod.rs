use crate::{chida::ChidaParty, share::Field, wollut16::RndOhvOutput};

mod online;
mod offline;

// Party for WOLLUT16 with active security
pub struct WL16ASParty<F: Field + Copy> {
    inner: ChidaParty,
    prep_ohv: Vec<RndOhvOutput>,
    // Multiplication triples that need checking at the end
    triples_to_check: MulTripleVector<F>, 
}

struct MulTripleVector<F> {
    // s.t. a*b = c
    ai: Vec<F>,
    aii: Vec<F>,
    bi: Vec<F>,
    bii: Vec<F>,
    ci: Vec<F>,
    cii: Vec<F>
}

impl<F> MulTripleVector<F> {
    pub fn new() -> Self {
        Self { ai: Vec::new(), aii: Vec::new(), bi: Vec::new(), bii: Vec::new(), ci: Vec::new(), cii: Vec::new() }
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