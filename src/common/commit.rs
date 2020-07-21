use serde::{Serialize, Deserialize};
use cryptid::elgamal::{CryptoContext, CurveElem};
use crate::common::config::PapervoteConfig;
use crate::APP_NAME;
use cryptid::{Scalar, AsBase64};
use std::fmt::Debug;
use serde::export::Formatter;
use std::fmt;

#[derive(Clone)]
pub struct PedersenCtx {
    ctx: CryptoContext,
    h: CurveElem,
}

impl PedersenCtx {
    pub fn new(ctx: CryptoContext) -> Self {
        // TODO: prove h isn't trapdoored
        let cfg: PapervoteConfig = confy::load(APP_NAME).unwrap();
        let h = CurveElem::try_from_base64(cfg.pedersen_h.as_str()).unwrap();

        Self::from(ctx, h)
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