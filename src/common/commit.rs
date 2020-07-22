use std::fmt;
use std::fmt::Debug;

use cryptid::{AsBase64, Scalar, Hasher};
use cryptid::elgamal::{CryptoContext, CurveElem};
use serde::{Serialize, Deserialize};
use serde::export::Formatter;

use uuid::Uuid;
use std::convert::TryFrom;

#[derive(Clone)]
pub struct PedersenCtx {
    ctx: CryptoContext,
    h: CurveElem,
}

impl PedersenCtx {
    pub fn new(session_id: &Uuid, ctx: CryptoContext) -> Self {
        let mut h = None;
        let mut count: u128 = 0;

        loop {
            // SHA-512 for 64 bytes of entropy
            let bytes = Hasher::sha_512()
                .and_update(session_id.as_bytes())
                .and_update(&count.to_be_bytes())
                .finish_vec();

            let s = Scalar::try_from(bytes).unwrap();
            if let Ok(elem) = CurveElem::try_from(s) {
                h.replace(elem);
                break;
            }

            count += 1;
        }

        Self::from(ctx, h.unwrap())
    }

    pub fn from(ctx: CryptoContext, h: CurveElem) -> Self {
        Self { ctx, h }
    }

    pub fn commit(&self, x: &Scalar, r: &Scalar) -> Commitment {
        Commitment {
            g: self.ctx.generator(),
            h: self.h.clone(),
            value: self.ctx.g_to(&x) + self.h.scaled(&r),
        }
    }
}

#[derive(PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Commitment {
    g: CurveElem,
    h: CurveElem,
    value: CurveElem,
}

impl Debug for Commitment {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value.as_base64())
    }
}

impl Commitment {
    pub fn validate(&self, x: &Scalar, r: &Scalar) -> bool {
        self.value == self.g.scaled(&x) + self.h.scaled(&r)
    }

    pub fn as_base64(&self) -> String {
        self.value.as_base64()
    }

    pub fn try_from_base64(encoded: &str, g: CurveElem, h: CurveElem) -> Option<Self> {
        if let Ok(value) = CurveElem::try_from_base64(encoded) {
            Some(Self { g, h, value })
        } else {
            None
        }
    }
}