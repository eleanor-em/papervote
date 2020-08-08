#![feature(async_closure)]
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Formatter, Display};

use cryptid::{CryptoError, Scalar, Hasher};
use cryptid::elgamal::{CryptoContext, PublicKey, Ciphertext, CurveElem};
use cryptid::threshold::{Threshold, ThresholdParty, Decryption, PubkeyProof};
use cryptid::AsBase64;
use reqwest::Client;
use reqwest::multipart::{Form, Part};
use tokio::time;
use tokio::time::Duration;
use uuid::Uuid;

use common::sign::{SignedMessage, SigningKeypair};
use tokio::net::{TcpListener, TcpStream};
use tokio::stream::StreamExt;
use tokio::io::AsyncReadExt;
use cryptid::zkp::{PrfKnowDlog, PrfEqDlogs};
use std::sync::{Arc, Mutex};
use futures::future::AbortHandle;
use common::net::{TrusteeMessage, TrusteeInfo, Response, WrappedResponse};
use common::vote::{VoterMessage, Candidate, VoterId, Ballot, Vote};
use cryptid::commit::{PedersenCtx, Commitment};
use cryptid::shuffle::Shuffle;
use rayon::prelude::*;
use std::convert::TryFrom;
use crate::gen::GeneratingTrustee;

mod api;
mod gen;

#[derive(Debug)]
pub enum TrusteeError {
    NoSuchTrustee(Uuid),
    Crypto(CryptoError),
    Io(std::io::Error),
    Serde(serde_json::Error),
    Net(reqwest::Error),
    Decode,
    FailedResponse(Response),
    InvalidSignature,
    InvalidResponse,
    MissingRegistration,
    MissingCommitment,
    MissingSignature,
    InvalidState,
}

impl Display for TrusteeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<CryptoError> for TrusteeError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl From<std::io::Error> for TrusteeError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for TrusteeError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serde(e)
    }
}

impl From<reqwest::Error> for TrusteeError {
    fn from(e: reqwest::Error) -> Self {
        Self::Net(e)
    }
}

impl Error for TrusteeError {}

struct PetInstance {
    voter_id: VoterId,
    enc_mac: Ciphertext,
    enc_vote: Ciphertext,
    enc_received_vote: Ciphertext,
    a: CurveElem,
    b: CurveElem,
}

pub struct PetData {
    voter_id: VoterId,
    vote_ct: Ciphertext,
    vote_r: (Scalar, Scalar),
    mac_ct: Ciphertext,
    mac_r: (Scalar, Scalar),
    vote_proof: PrfEqDlogs,
    mac_proof: PrfEqDlogs,
    vote_commit: (Commitment, Commitment),
    mac_commit: (Commitment, Commitment),
}

pub struct Trustee {
    info: InternalInfo,
    trustee_info: HashMap<Uuid, TrusteeInfo>,
    failed_voter_ids: Arc<Mutex<Vec<VoterId>>>,
    received_votes: Arc<Mutex<Vec<SignedMessage>>>,
    downloaded_votes: Option<Vec<Vec<Ciphertext>>>,
    party: ThresholdParty,
    abort_handle: Option<AbortHandle>,
    log: Hasher,
}

#[derive(Clone)]
pub struct InternalInfo {
    api_base_addr: String,
    address: String,
    index: usize,
    id: Uuid,
    session_id: Uuid,
    client: Client,
    signing_keypair: Arc<SigningKeypair>,
    ctx: CryptoContext,
    commit_ctx: PedersenCtx,
    pubkey: PublicKey,
    pubkey_proof: PubkeyProof,
}

impl Trustee {
    pub async fn new(api_base_addr: String,
                     session_id: Uuid,
                     ctx: CryptoContext,
                     index: usize,
                     min_trustees: usize,
                     trustee_count: usize) -> Result<Trustee, TrusteeError> {
        let mut trustee = GeneratingTrustee::new(api_base_addr.clone(), session_id.clone(), &ctx, index, min_trustees, trustee_count)?;

        let client = reqwest::Client::builder()
            .gzip(true)
            .timeout(Duration::from_secs(60))
            .build().map_err(|_| TrusteeError::InvalidState)?;

        // 1. Registration
        let msg = trustee.gen_registration();
        let response: WrappedResponse = client.post(&format!("{}/{}/trustee/register", api_base_addr, session_id))
            .json(&msg).send().await?
            .json().await?;
        if !response.status {
            eprintln!("error registering: {:?}", response.msg);
        }
        trustee.get_registrations(&msg, &client).await?;
        assert!(trustee.received_info());

        // 2. Commitment
        let msg = trustee.gen_commitment();
        let response: WrappedResponse = client.post(&format!("{}/{}/keygen/commitment", api_base_addr, session_id))
            .json(&msg).send().await?
            .json().await?;
        if !response.status {
            eprintln!("error committing: {:?}", response.msg);
        }
        trustee.get_commitments(&msg, &client).await?;
        assert!(trustee.received_commitments());

        // 3. Shares
        let shares = trustee.gen_shares()?;

        // Create sender threads
        for (id, share) in shares {
            let address = trustee.trustee_info[&id].address.clone();
            let msg = trustee.sign(TrusteeMessage::KeygenShare { share });
            tokio::spawn(GeneratingTrustee::send_share(address, msg));
        }
        trustee.receive_shares().await?;
        let party = trustee.generator.finish()?;

        // 4. Sign public key
        let msg = trustee.sign(TrusteeMessage::KeygenSign {
            pubkey: party.pubkey(),
            pubkey_proof: party.pubkey_proof(),
        });
        let response: WrappedResponse = client.post(&format!("{}/{}/keygen/sign", api_base_addr, session_id))
            .json(&msg).send().await?
            .json().await?;
        if !response.status {
            eprintln!("error signing: {:?}", response.msg);
        }

        // 5. Check signatures
        trustee.get_signatures(&msg, &client).await?;

        println!("Trustee {} done: {}", index, party.pubkey().as_base64());

        let info = InternalInfo {
            api_base_addr,
            address: trustee.trustee_info[&trustee.id].address.clone(),
            index,
            id: trustee.id,
            session_id,
            client,
            signing_keypair: Arc::new(trustee.signing_keypair),
            ctx,
            commit_ctx: PedersenCtx::new(session_id.as_bytes()),
            pubkey: party.pubkey(),
            pubkey_proof: party.pubkey_proof(),
        };

        // TODO: Store on disk.
        Ok(Trustee {
            info,
            trustee_info: trustee.trustee_info,
            failed_voter_ids: Arc::new(Mutex::new(Vec::new())),
            received_votes: Arc::new(Mutex::new(Vec::new())),
            downloaded_votes: None,
            party,
            abort_handle: None,
            log: trustee.log,
        })
    }

    pub fn index(&self) -> usize {
        self.info.index
    }

    pub fn log(&self) -> String {
        let hasher = self.log.clone();
        base64::encode(&hasher.finish_vec())
    }

    pub fn pubkey(&self) -> PublicKey {
        self.party.pubkey()
    }

    pub fn address(&self) -> String {
        self.info.address.clone()
    }

    pub async fn close_votes(&self, expected: usize) -> Result<(), TrusteeError> {
        let mut count = 0;
        loop {
            let current = self.received_votes.lock().unwrap().len() ;
            if count >= 5 || current >= expected {
                break;
            }
            println!("waiting for votes... ({}/{})", current, expected);
            count += 1;
            time::delay_for(Duration::from_millis(1000)).await;
        }

        if let Some(handle) = &self.abort_handle {
            // Abort tasks
            handle.abort();

            // Send votes
            let votes = self.received_votes.lock().unwrap();
            println!("Votes received: {}", votes.len());
            for vote in votes.iter() {
                let response: WrappedResponse = self.info.client.post(&format!("{}/{}/tally/vote", &self.info.api_base_addr, &self.info.session_id))
                    .json(&vote).send().await?
                    .json().await?;
                if !response.status {
                    eprintln!("Error response: {:?}", response.msg);
                }
            }

            Ok(())
        } else {
            Err(TrusteeError::InvalidState)?
        }
    }

    pub fn receive_voter_data(&mut self, candidates: Arc<HashMap<usize, Candidate>>)  {
        let (future, handle) = futures::future::abortable(Self::receive_voter_data_task(
            self.info.clone(),
            self.failed_voter_ids.clone(),
            self.received_votes.clone(),
            candidates
        ));
        self.abort_handle = Some(handle);
        tokio::spawn(future);
    }

    async fn receive_voter_data_task(info: InternalInfo,
                                     failed_voter_ids: Arc<Mutex<Vec<VoterId>>>,
                                     received_votes: Arc<Mutex<Vec<SignedMessage>>>,
                                     candidates: Arc<HashMap<usize, Candidate>>) -> Result<(), TrusteeError> {
        let mut listener = TcpListener::bind(&info.address).await?;

        while let Some(stream) = listener.next().await {
            if let Ok(stream) = stream {
                tokio::spawn(Self::receive_voter_data_inner(stream, info.clone(), failed_voter_ids.clone(), received_votes.clone(), candidates.clone()));
            }
        }

        Ok(())
    }

    async fn receive_voter_data_inner(mut stream: TcpStream,
                                      info: InternalInfo,
                                      failed_voter_ids: Arc<Mutex<Vec<VoterId>>>,
                                      received_votes: Arc<Mutex<Vec<SignedMessage>>>,
                                      candidates: Arc<HashMap<usize, Candidate>>) -> Result<(), TrusteeError> {
        // Read entire stream
        let mut buffer = String::new();
        stream.read_to_string(&mut buffer).await?;

        if let Ok(msg) = serde_json::from_str::<VoterMessage>(&buffer) {
            match msg {
                VoterMessage::EcCommit { voter_id, enc_mac, enc_vote, prf_know_mac, prf_know_vote } => {
                    tokio::spawn((async move || {
                        if let Err(e) = Self::handle_ec_commit(
                            info.clone(),
                            voter_id,
                            enc_mac,
                            enc_vote,
                            prf_know_mac,
                            prf_know_vote
                        ).await {
                            eprintln!("#{}: error handling commit: {}", info.index, e);
                        }
                    })());
                },
                VoterMessage::Ballot(ballot) => {
                    tokio::spawn((async move || {
                        if let Err(e) = Self::handle_ballot(
                            info.clone(),
                            failed_voter_ids.clone(),
                            received_votes.clone(),
                            candidates.clone(),
                            ballot
                        ).await {
                            eprintln!("#{}: error handling ballot: {}", info.index, e);
                        }
                    })());
                },
                _ => {
                    eprintln!("#{}: unrecognised message", info.index);
                },
            }
        }

        Ok(())
    }

    async fn handle_ec_commit(info: InternalInfo,
                              voter_id: VoterId,
                              enc_mac: Ciphertext,
                              enc_vote: Ciphertext,
                              prf_know_mac: PrfKnowDlog,
                              prf_know_vote: PrfKnowDlog) -> Result<(), TrusteeError> {
        // Check the proofs
        if !prf_know_mac.verify() {
            eprintln!("#{}: failed to verify MAC proof-of-knowledge", info.index);
            return Ok(());
        }
        if !prf_know_vote.verify() {
            eprintln!("#{}: failed to verify vote proof-of-knowledge", info.index);
            return Ok(());
        }

        // Re-randomise encryptions
        let r = info.ctx.random_scalar();
        let enc_mac = info.pubkey.rerand(&info.ctx, &enc_mac, &r);
        let r = info.ctx.random_scalar();
        let enc_vote = info.pubkey.rerand(&info.ctx, &enc_vote, &r);

        api::post_ec_commit(&info, voter_id, enc_mac, enc_vote).await?;

        Ok(())
    }

    async fn handle_ballot(info: InternalInfo,
                           failed_voter_ids: Arc<Mutex<Vec<VoterId>>>,
                           received_votes: Arc<Mutex<Vec<SignedMessage>>>,
                           candidates: Arc<HashMap<usize, Candidate>>,
                           ballot: Ballot) -> Result<(), TrusteeError> {
        let mut failed = false;

        // Check the proofs
        if !ballot.p1_prf_a.verify() {
            eprintln!("#{}: failed to verify proof-of-knowledge for a", info.index);
            failed = true;
        }
        if !ballot.p1_prf_b.verify() {
            eprintln!("#{}: failed to verify proof-of-knowledge for b", info.index);
            failed = true;
        }
        if !ballot.p1_prf_r_a.verify() {
            eprintln!("#{}: failed to verify proof-of-knowledge for r_a", info.index);
            failed = true;
        }
        if !ballot.p1_prf_r_b.verify() {
            eprintln!("#{}: failed to verify proof-of-knowledge for r_b", info.index);
            failed = true;
        }
        if failed {
            let mut vids = failed_voter_ids.lock().unwrap();
            vids.push(ballot.p2_id);
            return Ok(());
        }

        let encoded_voter_id = ballot.p2_id.try_as_curve_elem().ok_or(TrusteeError::Decode)?;
        if info.pubkey.encrypt(&info.ctx, &encoded_voter_id, &ballot.p2_prf_enc) != ballot.p2_enc_id {
            eprintln!("#{}: failed to verify proof-of-encryption for voter ID", info.index);
            return Ok(());
        }

        match Vote::from_string(&ballot.p1_vote, &candidates) {
            None => {
                eprintln!("#{}: invalid vote encoding", info.index);
                return Ok(());
            },
            Some(_vote) => {
                // println!("#{}: received vote:\n{}", info.index, vote.pretty());
            }
        }

        // Re-randomise encryptions
        let r = info.ctx.random_scalar();
        let enc_id = info.pubkey.rerand(&info.ctx, &ballot.p2_enc_id, &r);
        let r = info.ctx.random_scalar();
        let enc_a = info.pubkey.rerand(&info.ctx, &ballot.p1_enc_a, &r);
        let r = info.ctx.random_scalar();
        let enc_b = info.pubkey.rerand(&info.ctx, &ballot.p1_enc_b, &r);
        let r = info.ctx.random_scalar();
        let enc_r_a = info.pubkey.rerand(&info.ctx, &ballot.p1_enc_r_a, &r);
        let r = info.ctx.random_scalar();
        let enc_r_b = info.pubkey.rerand(&info.ctx, &ballot.p1_enc_r_b, &r);

        // Encrypt the vote with exponential encryption
        let vote = ballot.p1_vote;
        let vote_value = u128::from_str_radix(&vote, 10)
            .map_err(|_| TrusteeError::Decode)?;
        let vote_value: Scalar = vote_value.into();
        let prf_enc_vote = info.ctx.random_scalar();
        let enc_vote = info.pubkey.encrypt(&info.ctx, &info.ctx.g_to(&vote_value), &prf_enc_vote);

        // Construct message
        let inner = TrusteeMessage::EcVote {
            vote, enc_vote, prf_enc_vote, enc_id, enc_a, enc_b, enc_r_a, enc_r_b
        };
        let data = serde_json::to_string(&inner)?.as_bytes().to_vec();
        let signature = info.signing_keypair.sign(&data).as_ref().to_vec();

        let msg = SignedMessage {
            inner,
            signature,
            sender_id: info.id,
        };

        // Add it to the store
        received_votes.lock().unwrap().push(msg);

        Ok(())
    }

    pub async fn mix_votes(&mut self) -> Result<(), TrusteeError> {
        let response: WrappedResponse = if self.info.index == 1 {
            // if index 1, get the raw votes
            self.info.client.get(&format!("{}/{}/tally/vote", &self.info.api_base_addr, &self.info.session_id))
                .send().await?
                .json().await?
        } else {
            // otherwise, get the output of the previous mix
            self.info.client.get(&format!("{}/{}/tally/vote_mix/{}", &self.info.api_base_addr, &self.info.session_id, self.info.index - 1))
                .send().await?
                .json().await?
        };

        if !response.status {
            return Err(TrusteeError::FailedResponse(response.msg));
        }

        println!("#{}: Votes downloaded", self.info.index);

        let votes = match response.msg {
            Response::Ciphertexts(cts) => cts,
            _ => {
                return Err(TrusteeError::InvalidResponse);
            }
        };

        let mut ctx = self.info.ctx.clone();
        let (commit_ctx, generators) = PedersenCtx::with_generators(self.info.session_id.as_bytes(), votes.len());
        let shuffle = Shuffle::new(ctx.clone(), votes.to_vec(), &self.info.pubkey)?;
        println!("#{}: Shuffled", self.info.index);
        let proof = shuffle.gen_proof(&mut ctx, &commit_ctx, &generators, &self.info.pubkey)?;
        println!("#{}: Generated proof", self.info.index);

        let outputs = shuffle.outputs().to_vec();
        let mut enc_votes = Vec::new();
        let mut enc_voter_ids = Vec::new();
        let mut enc_as = Vec::new();
        let mut enc_bs = Vec::new();
        let mut enc_r_as = Vec::new();
        let mut enc_r_bs = Vec::new();

        for mut cts in outputs.into_iter() {
            enc_r_bs.push(cts.remove(5));
            enc_r_as.push(cts.remove(4));
            enc_bs.push(cts.remove(3));
            enc_as.push(cts.remove(2));
            enc_voter_ids.push(cts.remove(1));
            enc_votes.push(cts.remove(0));
        }

        // send shuffle
        api::post_shuffle(&self.info, enc_votes, enc_voter_ids, enc_as, enc_bs, enc_r_as, enc_r_bs, proof).await?;
        println!("#{}: Uploaded shuffle", self.info.index);
        Ok(())
    }

    async fn download_votes(&mut self) -> Result<(), TrusteeError> {
        if self.downloaded_votes.is_some() {
            return Ok(());
        }

        // Download and cache the votes
        let votes = api::get_votes(&self.info, &self.party).await?;
        self.downloaded_votes.replace(votes);
        Ok(())
    }

    pub async fn decrypt_first_mix(&mut self) -> Result<(), TrusteeError> {
        self.download_votes().await?;
        let votes = self.downloaded_votes.as_ref().unwrap();

        // Generate decryption shares
        let mut decrypt_shares: Vec<Vec<_>> = Vec::new();
        decrypt_shares.par_extend(votes.into_par_iter().map(|row| {
            // Need to decrypt all but the first element
            let mut row_shares: Vec<_> = row.iter()
                .map(|ct| self.party.decrypt_share(&ct))
                .collect();
            row_shares.remove(0);
            row_shares
        }));

        let signatures = decrypt_shares.iter().map(|shares| {
            let string = shares.iter()
                .map(|share| serde_json::to_string(share).unwrap())
                .collect::<Vec<_>>()
                .join(":");
            self.info.signing_keypair.sign(string.as_bytes()).as_ref().to_vec()
        }).collect();

        api::post_decrypt_shares(&self.info, signatures, decrypt_shares).await?;

        Ok(())
    }

    async fn decrypt_votes(&self, votes: &[Vec<Ciphertext>]) -> Result<Vec<Vec<CurveElem>>, TrusteeError> {
        // Download decryption shares
        let decrypt_shares = api::get_decrypt_shares(&self.info).await?;

        // Perform decryption using the posted shares
        let mut rows = Vec::new();
        for (vote, shares) in votes.iter().zip(decrypt_shares) {
            let mut decryptions = vec![
                Decryption::new(self.party.min_trustees(), &self.info.ctx, &vote[1]),
                Decryption::new(self.party.min_trustees(), &self.info.ctx, &vote[2]),
                Decryption::new(self.party.min_trustees(), &self.info.ctx, &vote[3]),
                Decryption::new(self.party.min_trustees(), &self.info.ctx, &vote[4]),
                Decryption::new(self.party.min_trustees(), &self.info.ctx, &vote[5])
            ];
            for (trustee_id, _, these_shares) in shares {
                let info = &self.trustee_info[&trustee_id];

                for (dec, share) in decryptions.iter_mut().zip(these_shares) {
                    dec.add_share(info.index, &info.pubkey_proof.as_ref().unwrap(), &share);
                }
            }

            match decryptions.into_iter()
                .map(|dec| dec.finish())
                .collect::<Result<Vec<_>, _>>() {
                Ok(results) => {
                    rows.push(results);
                },
                Err(e) => {
                    eprintln!("Decryption failed for a vote: {}", e);
                }
            }
        }

        Ok(rows)
    }

    pub async fn validate_votes(&mut self) -> Result<Vec<PetData>, TrusteeError> {
        self.download_votes().await?;
        let votes = self.downloaded_votes.as_ref().unwrap();
        let decrypted = self.decrypt_votes(&votes).await?;

        // Decode decryptions
        let mut rows = Vec::new();
        let mut voter_id_counts = HashMap::new();

        for mut row in decrypted.into_iter() {
            if let Ok(voter_id) = VoterId::try_from(row[0]) {
                *voter_id_counts.entry(voter_id.clone())
                    .or_insert(0usize) += 1;

                let r_b = row.remove(4);
                let b = row.remove(3);
                let r_a = row.remove(2);
                let a = row.remove(1);
                rows.push((voter_id, a, r_a, b, r_b));
            } else {
                eprintln!("Decoding voter ID failed.");
            }
        }

        // Get commitments
        let ec_commits = api::get_ec_commitments(&self.info).await?;
        let mut ec_commit_map = HashMap::new();
        for (voter_id, enc_mac, enc_vote) in ec_commits {
            ec_commit_map.entry(voter_id)
                .or_insert(Vec::new())
                .push((enc_mac, enc_vote));
        }

        // Check uniqueness of IDs and EC commitments
        let unique_rows: Vec<_> = rows.into_iter()
            .filter(|(voter_id, _, _, _, _)| voter_id_counts[voter_id] == 1)
            .collect();

        // Get idents
        let idents = api::get_idents(&self.info).await?;
        let mut ident_map = HashMap::new();
        for (voter_id, c_a, c_b) in idents {
            ident_map.entry(voter_id)
                .or_insert(Vec::new())
                .push((c_a, c_b));
        }

        // Verify the commitments from the voter and EC to produce a set of votes for PETing
        let mut to_pet: Vec<PetInstance> = Vec::new();

        for (i, (voter_id, a, b, r_a, r_b)) in unique_rows.into_iter().enumerate() {
            if let Some(commits) = ident_map.get(&voter_id) {
                if let Some(ec_commits) = ec_commit_map.get(&voter_id) {
                    let voter_id_copy = voter_id.clone();
                    let (enc_mac, enc_vote) = ec_commits[0].clone();

                    let mut matched = false;
                    for (c_a, c_b) in commits {
                        if c_a.validate(&self.info.commit_ctx, &a.into(), &r_a.into())
                                && c_b.validate(&self.info.commit_ctx, &b.into(), &r_b.into()) {
                            // Commitments validated
                            let enc_received_vote = votes[i][0].clone();
                            to_pet.push(PetInstance {
                                voter_id, enc_mac, enc_vote, enc_received_vote,
                                a: a.into(), b: b.into()
                            });
                            matched = true;
                            break;
                        }
                    }

                    if !matched {
                        eprintln!("No valid commitment for {}.", voter_id_copy);
                    }
                } else {
                    eprintln!("No EC commitment for {}.", voter_id);
                }
            } else {
                eprintln!("No commitment for {}.", voter_id);
            }
        }

        println!("Vote validation and matching done, {} votes need to be PET'd.", to_pet.len());

        Ok(self.do_pet_commits(to_pet).await?)
    }

    async fn do_pet_commits(&self, to_test: Vec<PetInstance>) -> Result<Vec<PetData>, TrusteeError> {
        let mut data = Vec::new();
        data.par_extend(to_test.into_par_iter().map(|test| {
            // Construct vote commitment
            let vote_quotient_c1 = test.enc_received_vote.c1 - test.enc_vote.c1;
            let vote_quotient_c2 = test.enc_received_vote.c2 - test.enc_vote.c2;
            let vote_ct = Ciphertext {
                c1: vote_quotient_c1, c2: vote_quotient_c2
            };

            let blind = self.info.ctx.random_scalar();
            let vote_blind = (vote_quotient_c1.scaled(&blind), vote_quotient_c2.scaled(&blind));
            let vote_r = (self.info.ctx.random_scalar(), self.info.ctx.random_scalar());
            let vote_commit = (self.info.commit_ctx.commit(&vote_blind.0.into(), &vote_r.0),
                               self.info.commit_ctx.commit(&vote_blind.1.into(), &vote_r.1));

            let vote_proof = PrfEqDlogs::new(&self.info.ctx, &vote_quotient_c1, &vote_quotient_c2, &vote_blind.0, &vote_blind.1, &blind);
            assert!(vote_proof.verify());

            // Reconstruct the MAC
            let enc_b = self.info.pubkey.encrypt(&self.info.ctx, &test.b, &Scalar::zero());
            let mac_c1 = test.enc_vote.c1.scaled(&test.a.into()) + enc_b.c1;
            let mac_c2 = test.enc_vote.c2.scaled(&test.a.into()) + enc_b.c2;

            // Construct MAC commitment
            let mac_quotient_c1 = test.enc_mac.c1 - mac_c1;
            let mac_quotient_c2 = test.enc_mac.c2 - mac_c2;
            let mac_ct = Ciphertext {
                c1: mac_quotient_c1, c2: mac_quotient_c2
            };

            let blind = self.info.ctx.random_scalar();
            let mac_blind = (mac_quotient_c1.scaled(&blind), mac_quotient_c2.scaled(&blind));
            let mac_r = (self.info.ctx.random_scalar(), self.info.ctx.random_scalar());
            let mac_commit = (self.info.commit_ctx.commit(&mac_blind.0.into(), &mac_r.0),
                              self.info.commit_ctx.commit(&mac_blind.1.into(), &mac_r.1));

            let mac_proof = PrfEqDlogs::new(&self.info.ctx, &mac_quotient_c1, &mac_quotient_c2, &mac_blind.0, &mac_blind.1, &blind);
            assert!(mac_proof.verify());

            PetData {
                voter_id: test.voter_id,
                vote_ct,
                vote_r,
                mac_ct,
                mac_r,
                vote_proof,
                mac_proof,
                vote_commit,
                mac_commit,
            }
        }));

        // Post commitments
        self.post_pet_commitments(&data).await?;

        Ok(data)
    }

    async fn post_pet_commitments(&self, data: &[PetData]) -> Result<(), TrusteeError> {
        let mut voter_ids = Vec::new();
        let mut vote_commits = Vec::new();
        let mut mac_commits = Vec::new();
        let mut signatures = Vec::new();

        for row in data {
            let voter_id = row.voter_id.clone();
            let vote_commit = row.vote_commit.clone();
            let mac_commit = row.mac_commit.clone();

            let mut bytes = Vec::new();
            bytes.extend_from_slice(voter_id.to_string().as_bytes());
            bytes.extend_from_slice(vote_commit.0.to_string().as_bytes());
            bytes.extend_from_slice(vote_commit.1.to_string().as_bytes());
            bytes.extend_from_slice(mac_commit.0.to_string().as_bytes());
            bytes.extend_from_slice(mac_commit.1.to_string().as_bytes());

            let signature = self.info.signing_keypair.sign(&bytes).as_ref().to_vec();

            voter_ids.push(voter_id);
            vote_commits.push(vote_commit);
            mac_commits.push(mac_commit);
            signatures.push(signature);
        }

        api::post_pet_commits(&self.info, voter_ids, vote_commits, mac_commits, signatures).await?;

        Ok(())
    }

    pub async fn do_pet_openings(&self, data: Vec<PetData>) -> Result<(), TrusteeError> {
        Ok(())
    }
}
