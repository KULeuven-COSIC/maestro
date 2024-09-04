use std::ops::{Add, AddAssign, Mul, Sub};

/// A party's RSS-share of a (2,3)-shared field element.
#[derive(Clone, Debug)]
pub struct RssShare<T> {
    /// The first share of the party.
    pub si: T,
    /// The second share of the party.
    pub sii: T,
}

/// A vector of [RssShare]s.
pub type RssShareVec<F> = Vec<RssShare<F>>;

// Provides the neutral element of addition
pub trait HasZero {
    /// Zero the neutral element of addition
    const ZERO: Self;
}

impl<T> RssShare<T> {
    /// Computes an RSS-share given two shares.
    pub fn from(si: T, sii: T) -> Self {
        Self { si, sii }
    }
}

// impl<T: Mul> RssShare<T> {
    
//     pub fn mul_by_sc(self, scalar: T) -> Self {
//         Self {
//             si: self.si * scalar,
//             sii: self.sii * scalar,
//         }
//     }
// }

impl<T: Add> Add<Self> for RssShare<T> {
    type Output = RssShare<<T as Add>::Output>;

    fn add(self, rhs: Self) -> Self::Output {
        RssShare {
            si: self.si + rhs.si,
            sii: self.sii + rhs.sii,
        }
    }
}

impl<T: Sub> Sub<Self> for RssShare<T> {
    type Output = RssShare<<T as Sub>::Output>;

    fn sub(self, rhs: Self) -> Self::Output {
        RssShare {
            si: self.si - rhs.si,
            sii: self.sii - rhs.sii,
        }
    }
}

/// Multiplies the RSS-share with a scalar.
impl<T: Mul + Copy> Mul<T> for RssShare<T> {
    type Output = RssShare<<T as Mul>::Output>;

    fn mul(self, rhs: T) -> Self::Output {
        RssShare {
            si: self.si * rhs,
            sii: self.sii * rhs,
        }
    }
}

impl<T: AddAssign> AddAssign for RssShare<T> {
    fn add_assign(&mut self, rhs: Self) {
        self.si += rhs.si;
        self.sii += rhs.sii;
    }
}

impl<T: Copy> Copy for RssShare<T> {}

impl<T: HasZero> HasZero for RssShare<T> {
    const ZERO: Self = Self {si: T::ZERO, sii: T::ZERO};
}