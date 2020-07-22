pub mod vote;
use std::convert::TryInto;
use std::error::Error;
use std::fmt::{Display, Formatter};

use cryptid::Scalar;
use cryptid::elgamal::{CryptoContext, Ciphertext, PublicKey, CurveElem};
use cryptid::zkp::PrfKnowDlog;
use eyre::Result;
use serde::{Serialize, Deserialize};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time;
use tokio::time::Duration;
use uuid::Uuid;

use crate::common::commit::{PedersenCtx, Commitment};
use crate::voter::vote::Vote;
use crate::wbb::api::{WrappedResponse, Response};
use crate::wbb::api;

#[derive(Clone, Debug)]
pub enum VoterError {
    Api(Response),
    VoteMissing,
    Encode,
    PostMissing,
}

impl Display for VoterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for VoterError {}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct VoterId(String);

impl ToString for VoterId {
    fn to_string(&self) -> String {
        self.0.clone()
    }
}

impl VoterId {
    pub fn try_as_curve_elem(&self) -> Result<CurveElem, VoterError> {
        CurveElem::try_encode(self.0.as_bytes().to_vec().try_into().map_err(|_| VoterError::Encode)?)
            .map_err(|_| VoterError::Encode)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Ballot {
    pub p1_vote: String,
    pub p1_enc_a: Ciphertext,
    pub p1_enc_b: Ciphertext,
    pub p1_enc_r_a: Ciphertext,
    pub p1_enc_r_b: Ciphertext,
    pub p1_prf_a: PrfKnowDlog,
    pub p1_prf_b: PrfKnowDlog,
    pub p1_prf_r_a: PrfKnowDlog,
    pub p1_prf_r_b: PrfKnowDlog,
    pub p2_id: VoterId,
    pub p2_enc_id: Ciphertext,
    pub p2_prf_enc: Scalar,
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub enum VoterMessage {
    InitialCommit {
        voter_id: VoterId,
        c_a: Commitment,
        c_b: Commitment,
    },
    EcCommit {
        voter_id: VoterId,
        enc_mac: Ciphertext,
        enc_vote: Ciphertext,
        prf_know_mac: PrfKnowDlog,
        prf_know_vote: PrfKnowDlog,
    },
    Ballot(Ballot),
}

pub struct Voter {
    session_id: Uuid,
    pubkey: PublicKey,
    ctx: CryptoContext,
    commit_ctx: PedersenCtx,
    voter_id: VoterId,
    a: CurveElem,
    r_a: CurveElem,
    b: CurveElem,
    r_b: CurveElem,
    vote: Option<Vote>,
}

impl Voter {
    pub fn new(session_id: Uuid, pubkey: PublicKey, mut ctx: CryptoContext, commit_ctx: PedersenCtx, voter_id: String) -> Result<Self> {
        Ok(Self {
            session_id,
            pubkey,
            ctx: ctx.clone(),
            commit_ctx,
            voter_id: VoterId(voter_id),
            a: ctx.random_elem()?,
            r_a: ctx.random_elem()?,
            b: ctx.random_elem()?,
            r_b: ctx.random_elem()?,
            vote: None
        })
    }

    pub fn id(&self) -> &str {
        &self.voter_id.0
    }

    pub async fn post_init_commit(&self) -> Result<()> {
        let msg = VoterMessage::InitialCommit {
            voter_id: self.voter_id.clone(),
            c_a: self.commit_ctx.commit(&self.a.into(), &self.r_a.into()),
            c_b: self.commit_ctx.commit(&self.b.into(), &self.r_b.into()),
        };

        let client = reqwest::Client::new();
        let response: WrappedResponse = client.post(&api::address(&self.session_id, "/cast/ident"))
            .json(&msg).send().await?
            .json().await?;
        if !response.status {
            return Err(VoterError::Api(response.msg))?;
        }

        Ok(())
    }

    pub async fn post_ec_commit(&mut self, address: &str) -> Result<()> {
        // Send the commit
        let msg = self.get_ec_commit()?;
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(serde_json::to_string(&msg)?.as_ref()).await?;
        Ok(())
    }

    pub async fn check_ec_commit(&mut self) -> Result<()> {
        let client = reqwest::Client::new();
        time::delay_for(Duration::from_millis(1000)).await;

        let path = format!("/cast/commit/{}", self.voter_id.to_string());
        let response: WrappedResponse = client.get(&api::address(&self.session_id, &path))
            .send().await?
            .json().await?;

        match response.msg {
            Response::Outcome(true) => Ok(()),
            Response::Outcome(false) => Err(VoterError::PostMissing)?,
            _ => Err(VoterError::Api(response.msg))?
        }
    }

    pub async fn post_vote(&mut self, address: &str) -> Result<()> {
        let (a, prf_a) = self.encrypt(&self.a.try_into()?)?;
        let (b, prf_b) = self.encrypt(&self.b.try_into()?)?;
        let (r_a, prf_r_a) = self.encrypt(&self.r_a.try_into()?)?;
        let (r_b, prf_r_b) = self.encrypt(&self.r_b.try_into()?)?;
        let (id, prf_id) = self.encrypt(&self.voter_id.try_as_curve_elem()?)?;

        let g = self.ctx.generator();

        let ballot = Ballot {
            p1_vote: self.vote.as_ref().map(|v| v.to_string()).ok_or(VoterError::VoteMissing)?,
            p1_enc_a: a.clone(),
            p1_enc_b: b.clone(),
            p1_enc_r_a: r_a.clone(),
            p1_enc_r_b: r_b.clone(),
            p1_prf_a: PrfKnowDlog::new(&mut self.ctx, &g, &prf_a, &a.c1)?,
            p1_prf_b: PrfKnowDlog::new(&mut self.ctx, &g, &prf_b, &b.c1)?,
            p1_prf_r_a: PrfKnowDlog::new(&mut self.ctx, &g, &prf_r_a, &r_a.c1)?,
            p1_prf_r_b: PrfKnowDlog::new(&mut self.ctx, &g, &prf_r_b, &r_b.c1)?,
            p2_id: self.voter_id.clone(),
            p2_enc_id: id,
            p2_prf_enc: prf_id,
        };

        let msg = VoterMessage::Ballot(ballot);
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(serde_json::to_string(&msg)?.as_ref()).await?;

        Ok(())
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
        let a: Scalar = self.a.into();
        let b: Scalar = self.b.into();
        self.get_encoded_vote().map(|scalar| a * scalar + b)
    }

    fn encrypt(&mut self, m: &CurveElem) -> Result<(Ciphertext, Scalar)> {
        let r = self.ctx.random_power()?;
        let ct = self.pubkey.encrypt(&self.ctx, m, &r);
        Ok((ct, r))
    }

    fn get_ec_commit(&mut self) -> Result<VoterMessage> {
        if self.vote.is_none() {
            Err(VoterError::VoteMissing)?;
        }

        let r1 = self.ctx.random_power()?;
        let r2 = self.ctx.random_power()?;

        let mac = &self.ctx.g_to(&self.get_mac().ok_or(VoterError::VoteMissing)?);
        let vote = &self.ctx.g_to(&self.get_encoded_vote().ok_or(VoterError::VoteMissing)?);

        let enc_mac = self.pubkey.encrypt(&self.ctx, mac, &r1);
        let enc_vote = self.pubkey.encrypt(&self.ctx, vote, &r2);

        let g = self.ctx.generator();

        let prf_know_mac = PrfKnowDlog::new(&mut self.ctx, &g, &r1, &enc_mac.c1)?;
        assert!(prf_know_mac.verify()?);

        let prf_know_vote = PrfKnowDlog::new(&mut self.ctx, &g, &r1, &enc_mac.c1)?;
        assert!(prf_know_vote.verify()?);

        Ok(VoterMessage::EcCommit {
            voter_id: self.voter_id.clone(),
            enc_mac,
            enc_vote,
            prf_know_mac,
            prf_know_vote,
        })
    }
}