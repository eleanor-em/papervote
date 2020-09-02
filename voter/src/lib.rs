use std::error::Error;
use std::fmt::{Display, Formatter};

use cryptid::{Scalar, CryptoError};
use cryptid::elgamal::{CryptoContext, Ciphertext, PublicKey, CurveElem};
use cryptid::zkp::PrfKnowPlaintext;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time;
use tokio::time::Duration;
use uuid::Uuid;

use common::voter::{VoterMessage, VoterId, Vote, Ballot, VoterIdent};
use common::net::{WrappedResponse, Response};
use cryptid::commit::PedersenCtx;

#[derive(Debug)]
pub enum VoterError {
    Api(Response),
    Crypto(CryptoError),
    Io(std::io::Error),
    Net(reqwest::Error),
    VoteMissing,
    Encode,
    Decode,
    PostMissing,
}

impl From<CryptoError> for VoterError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<std::io::Error> for VoterError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<reqwest::Error> for VoterError {
    fn from(e: reqwest::Error) -> Self {
        Self::Net(e)
    }
}

impl Display for VoterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for VoterError {}

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
    pub fn new(session_id: Uuid,
               pubkey: PublicKey,
               ctx: CryptoContext,
               commit_ctx: PedersenCtx,
               voter_id: String) -> Result<Self, VoterError> {
        Ok(Self {
            session_id,
            pubkey,
            ctx: ctx.clone(),
            commit_ctx,
            voter_id: VoterId::new(voter_id),
            a: ctx.random_elem(),
            r_a: ctx.random_elem(),
            b: ctx.random_elem(),
            r_b: ctx.random_elem(),
            vote: None
        })
    }

    pub fn id(&self) -> &str {
        self.voter_id.as_str()
    }

    pub async fn post_init_commit(&self, api_base_addr: &str) -> Result<(), VoterError> {
        let c_a = self.commit_ctx.commit(&self.a.into(), &self.r_a.into());
        let c_b = self.commit_ctx.commit(&self.b.into(), &self.r_b.into());

        let msg = VoterMessage::InitialCommit(VoterIdent {
            id: self.voter_id.clone(),
            c_a,
            c_b
        });


        let client = reqwest::Client::new();
        let response: WrappedResponse = client.post(&format!("{}/{}/cast/ident", api_base_addr, self.session_id))
            .json(&msg).send().await?
            .json().await?;
        if !response.status {
            return Err(VoterError::Api(response.msg))?;
        }

        Ok(())
    }

    pub async fn post_ec_commit(&mut self, address: &str) -> Result<(), VoterError> {
        // Send the commit
        let msg = self.get_ec_commit()?;
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(serde_json::to_string(&msg)
            .map_err(|_| VoterError::Encode)?
            .as_ref()).await?;
        Ok(())
    }

    pub async fn check_ec_commit(&mut self, api_base_addr: &str) -> Result<(), VoterError> {
        let client = reqwest::Client::new();
        time::delay_for(Duration::from_millis(1000)).await;

        let path = format!("{}/{}/cast/commit/{}", api_base_addr, self.session_id, self.voter_id.to_string());
        let response: WrappedResponse = client.get(&path)
            .send().await?
            .json().await?;

        match response.msg {
            Response::Outcome(true) => Ok(()),
            Response::Outcome(false) => Err(VoterError::PostMissing)?,
            _ => Err(VoterError::Api(response.msg))?
        }
    }

    pub fn get_ballot(&mut self) -> Result<Ballot, VoterError> {
        let (a, prf_a) = self.encrypt(&self.a.clone())?;
        let (b, prf_b) = self.encrypt(&self.b.clone())?;
        let (r_a, prf_r_a) = self.encrypt(&self.r_a.clone())?;
        let (r_b, prf_r_b) = self.encrypt(&self.r_b.clone())?;
        let (id, prf_id) = self.encrypt(&self.voter_id.try_as_curve_elem().ok_or(VoterError::Decode)?)?;

        Ok(Ballot {
            p1_vote: self.vote.as_ref().map(|v| v.to_string()).ok_or(VoterError::VoteMissing)?,
            p1_enc_a: a.clone(),
            p1_enc_b: b.clone(),
            p1_enc_r_a: r_a.clone(),
            p1_enc_r_b: r_b.clone(),
            // p1_prf_a: PrfKnowPlaintext::new(&self.ctx, a, prf_a),
            // p1_prf_b: PrfKnowPlaintext::new(&self.ctx, b, prf_b),
            // p1_prf_r_a: PrfKnowPlaintext::new(&self.ctx, r_a, prf_r_a),
            // p1_prf_r_b: PrfKnowPlaintext::new(&self.ctx, r_b, prf_r_b),
            p2_id: self.voter_id.clone(),
            p2_enc_id: id,
            p2_prf_enc: prf_id,
        })
    }

    pub async fn post_vote(&mut self, address: &str) -> Result<(), VoterError> {
        let ballot = self.get_ballot()?;
        let msg = VoterMessage::Ballot(ballot);
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(serde_json::to_string(&msg)
            .map_err(|_| VoterError::Encode)?
            .as_ref()).await?;

        Ok(())
    }

    pub fn set_vote(&mut self, vote: Vote) {
        self.vote.replace(vote);
    }

    fn get_encoded_vote(&self) -> Option<Scalar> {
        self.vote.as_ref().map(|vote| vote.encode())
    }

    fn get_mac(&self) -> Option<Scalar> {
        let a: Scalar = self.a.into();
        let b: Scalar = self.b.into();
        self.get_encoded_vote().map(|scalar| a * scalar + b)
    }

    fn encrypt(&mut self, m: &CurveElem) -> Result<(Ciphertext, Scalar), VoterError> {
        let r = self.ctx.random_scalar();
        let ct = self.pubkey.encrypt(&self.ctx, m, &r);
        Ok((ct, r))
    }

    fn get_ec_commit(&mut self) -> Result<VoterMessage, VoterError> {
        if self.vote.is_none() {
            Err(VoterError::VoteMissing)?;
        }

        let r1 = self.ctx.random_scalar();
        let r2 = self.ctx.random_scalar();

        // Exponential encryption
        let mac = &self.ctx.g_to(&self.get_mac().ok_or(VoterError::VoteMissing)?);
        let vote = &self.ctx.g_to(&self.get_encoded_vote().ok_or(VoterError::VoteMissing)?);

        let enc_mac = self.pubkey.encrypt(&self.ctx, mac, &r1);
        let enc_vote = self.pubkey.encrypt(&self.ctx, vote, &r2);

        let prf_know_mac = PrfKnowPlaintext::new(&self.ctx, enc_mac.clone(), r1.clone());
        assert!(prf_know_mac.verify());

        let prf_know_vote = PrfKnowPlaintext::new(&self.ctx, enc_vote.clone(), r2.clone());
        assert!(prf_know_vote.verify());

        Ok(VoterMessage::EcCommit {
            voter_id: self.voter_id.clone(),
            enc_mac,
            enc_vote,
            prf_know_mac,
            prf_know_vote,
        })
    }
}

#[cfg(test)]
mod tests {
    use cryptid::elgamal::{CryptoContext, PublicKey, Ciphertext, CurveElem};
    use crate::Voter;
    use cryptid::commit::PedersenCtx;
    use common::voter::{Vote, Candidate};
    use uuid::Uuid;
    use cryptid::{AsBase64, Scalar};

    #[test]
    fn test_mac_recons() {
        let session_id = Uuid::new_v4();
        let ctx = CryptoContext::new().unwrap();
        let secret_key = ctx.random_scalar();
        let pubkey = PublicKey::new(ctx.g_to(&secret_key));
        let voter_id = "hello world".to_string();
        let commit_ctx = PedersenCtx::new(&[0]);

        let mut voter = Voter::new(session_id, pubkey, ctx.clone(), commit_ctx, voter_id).unwrap();
        let mut vote = Vote::new();
        vote.set(&Candidate::new("alice", 0), 0);
        vote.set(&Candidate::new("bob", 1), 1);
        vote.set(&Candidate::new("charlie", 2), 2);
        voter.set_vote(vote);

        let vote = voter.get_encoded_vote().unwrap();
        let a: Scalar = voter.a.into();
        let b: Scalar = voter.b.into();
        let mac = a * vote + b;

        let r = ctx.random_scalar();
        let enc_vote = pubkey.encrypt(&ctx, &ctx.g_to(&vote), &r);

        let r = ctx.random_scalar();
        let enc_mac = pubkey.encrypt(&ctx, &ctx.g_to(&mac), &r);

        let r = ctx.random_scalar();
        let enc_b = pubkey.encrypt(&ctx, &ctx.g_to(&b), &r);

        let received_mac = enc_vote.scaled(&a).add(&enc_b);

        assert_eq!(received_mac.decrypt(&secret_key).as_base64(), ctx.g_to(&mac).as_base64());

        let mac_ct = Ciphertext {
            c1: received_mac.c1 - enc_mac.c1,
            c2: received_mac.c2 - enc_mac.c2,
        };
        assert_eq!(mac_ct.decrypt(&secret_key).as_base64(), CurveElem::identity().as_base64());
    }
}
