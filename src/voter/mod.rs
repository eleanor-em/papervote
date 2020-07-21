use serde::{Serialize, Deserialize};
use cryptid::elgamal::{CryptoContext, Ciphertext, PublicKey};
use crate::common::commit::{PedersenCtx, Commitment};
use cryptid::Scalar;
use eyre::Report;
use cryptid::zkp::PrfKnowDlog;
use crate::voter::vote::Vote;

pub mod vote;

// TODO: fix up serialisation to be more efficient
#[derive(Debug, Serialize, Deserialize)]
pub enum VoterMessage {
    InitialCommit {
        voter_id: String,
        c_a: Commitment,
        c_b: Commitment,
    },
    EcCommit {
        voter_id: String,
        enc_mac: Ciphertext,
        enc_vote: Ciphertext,
        prf_know_mac: PrfKnowDlog,
        prf_know_vote: PrfKnowDlog,
    }
}

pub struct Voter {
    pubkey: PublicKey,
    ctx: CryptoContext,
    commit_ctx: PedersenCtx,
    voter_id: String,
    a: Scalar,
    r_a: Scalar,
    b: Scalar,
    r_b: Scalar,
    vote: Option<Vote>,
}

impl Voter {
    pub fn new(pubkey: PublicKey, mut ctx: CryptoContext, commit_ctx: PedersenCtx, voter_id: String) -> Result<Self, Report> {
        Ok(Self {
            pubkey,
            ctx: ctx.clone(),
            commit_ctx,
            voter_id,
            a: ctx.random_power()?,
            r_a: ctx.random_power()?,
            b: ctx.random_power()?,
            r_b: ctx.random_power()?,
            vote: None
        })
    }

    pub fn get_init_commit(&self) -> VoterMessage {
        VoterMessage::InitialCommit {
            voter_id: self.voter_id.clone(),
            c_a: self.commit_ctx.commit(&self.a, &self.r_a),
            c_b: self.commit_ctx.commit(&self.b, &self.r_b),
        }
    }

    pub fn set_vote(&mut self, vote: Vote) {
        self.vote.replace(vote);
    }

    fn get_encoded_vote(&self) -> Option<Scalar> {
        self.vote.as_ref()
            .and_then(|vote| vote.clone().to_string().parse::<u128>().ok())
            .map(|encoded| Scalar::from(encoded))
    }

    fn get_mac(&self) -> Option<Scalar> {
        self.get_encoded_vote().map(|scalar| self.a * scalar + self.b)
    }

    pub fn get_ec_commit(&mut self) -> Option<VoterMessage> {
        if self.vote.is_none() {
            return None;
        }

        let r1 = self.ctx.random_power().unwrap();
        let r2 = self.ctx.random_power().unwrap();

        let mac = &self.ctx.g_to(&self.get_mac().unwrap());
        let vote = &self.ctx.g_to(&self.get_encoded_vote().unwrap());

        let enc_mac = self.pubkey.encrypt(&self.ctx, mac, &r1);
        let enc_vote = self.pubkey.encrypt(&self.ctx, vote, &r2);

        let g = self.ctx.generator();

        let prf_know_mac = PrfKnowDlog::new(&mut self.ctx, &g, &r1, &enc_mac.c1).unwrap();
        assert!(prf_know_mac.verify().unwrap());

        let prf_know_vote = PrfKnowDlog::new(&mut self.ctx, &g, &r1, &enc_mac.c1).unwrap();
        assert!(prf_know_vote.verify().unwrap());

        Some(VoterMessage::EcCommit {
            voter_id: self.voter_id.clone(),
            enc_mac,
            enc_vote,
            prf_know_mac,
            prf_know_vote,
        })
    }
}