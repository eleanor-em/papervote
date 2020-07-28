#![feature(async_closure)]
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Formatter, Display};

use cryptid::{CryptoError, Scalar, Hasher};
use cryptid::elgamal::{CryptoContext, PublicKey, Ciphertext, CurveElem};
use cryptid::threshold::{ThresholdGenerator, Threshold, ThresholdParty, KeygenCommitment};
use cryptid::AsBase64;
use reqwest::Client;
use tokio::time;
use tokio::time::Duration;
use uuid::Uuid;

use common::sign;
use common::sign::{SignedMessage, SigningKeypair};
use tokio::net::{TcpListener, TcpStream};
use tokio::stream::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use cryptid::zkp::PrfKnowDlog;
use std::sync::{Arc, Mutex};
use ring::signature::KeyPair;
use futures::future::AbortHandle;
use common::net::{TrusteeMessage, TrusteeInfo, Response, WrappedResponse};
use common::vote::{VoterMessage, Candidate, VoterId, Ballot, Vote};

#[derive(Debug)]
pub enum TrusteeError {
    NoSuchTrustee(Uuid),
    Crypto(CryptoError),
    Io(std::io::Error),
    Serde(serde_json::Error),
    Net(reqwest::Error),
    Decode,
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

pub struct GeneratingTrustee {
    api_base_addr: String,
    session_id: Uuid,
    id: Uuid,
    signing_keypair: SigningKeypair,
    trustee_info: HashMap<Uuid, TrusteeInfo>,
    generator: ThresholdGenerator,
    log: Hasher,
}

impl GeneratingTrustee {
    pub fn new(api_base_addr: String, session_id: Uuid, ctx: &CryptoContext, index: usize, k: usize, n: usize) -> Result<GeneratingTrustee, CryptoError> {
        let mut ctx = ctx.clone();
        let id = Uuid::new_v4();

        // Generate a signature keypair
        let signing_keypair = sign::new_keypair(&ctx);

        // Create identification for this trustee
        let port = 14000 + index;
        let mut trustee_info = HashMap::new();
        let my_info = TrusteeInfo {
            id,
            pubkey: signing_keypair.public_key().into(),
            index,
            address: format!("localhost:{}", port),
        };
        trustee_info.insert(id, my_info);

        let generator = ThresholdGenerator::new(&mut ctx, index, k, n)?;

        Ok(Self {    // Setup
    let cfg: PapervoteConfig = confy::load(APP_NAME)?;
    let session_id = Uuid::new_v4();
    let ctx = CryptoContext::new()?;
    let commit_ctx = PedersenCtx::new(session_id.as_bytes(), ctx.clone(), 1);

    let api = Api::new().await?;
    std::thread::spawn(move || api.start());

    open_session(&cfg, session_id.clone()).await?;

    let candidates = get_candidates();
    let mut trustees = create_trustees(&cfg, ctx.clone(), session_id.clone()).await?;
    let pubkey = trustees[0].pubkey();

    let ec = &mut trustees[0];
    ec.receive_voter_data(candidates.clone());
    time::delay_for(Duration::from_millis(200)).await;

    let candidates: Vec<_> = candidates.values().collect();

    println!("Sending vote data...");
    let mut handles = Vec::new();
    const N: usize = 50;
    for i in 0..N {
        let addr = ec.address();
        let voter = random_voter(session_id.clone(), pubkey.clone(), ctx.clone(), commit_ctx.clone(), &candidates)?;
        handles.push(tokio::spawn(run_voter(voter, cfg.api_url.clone(), addr)));

        // give the threads a slight break to push through
        if i > 0 && i % 500 == 0 {
            time::delay_for(Duration::from_millis(1000)).await;
        }
    }

    futures::future::join_all(handles).await;

    println!("Votes closing soon...");
    ec.close_votes(N).await?;
    time::delay_for(Duration::from_millis(500)).await;

    Ok(())

            api_base_addr,
            session_id,
            id,
            signing_keypair,
            trustee_info,
            generator,
            log: Hasher::sha_256(),
        })
    }

    pub fn session_id(&self) -> &Uuid {
        &self.session_id
    }

    pub fn verify_all(&self, messages: &[SignedMessage]) -> Result<bool, TrusteeError> {
        for message in messages {
            if let Some(info) = self.trustee_info.get(&message.sender_id) {
                if !message.verify(&info.pubkey)? {
                    return Ok(false);
                }
            } else {
                return Err(TrusteeError::NoSuchTrustee(message.sender_id));
            }
        }

        Ok(true)
    }

    pub fn gen_registration(&self) -> SignedMessage {
        let msg = TrusteeMessage::Info { info: self.trustee_info[&self.id].clone() };
        self.sign(msg)
    }

    pub fn add_info(&mut self, info: TrusteeInfo) {
        self.trustee_info.insert(info.id, info);
    }

    pub fn received_info(&self) -> bool {
        self.trustee_info.len() == self.generator.trustee_count()
    }

    pub fn gen_commitment(&self) -> SignedMessage {
        let commitment = self.generator.get_commitment();
        let msg = TrusteeMessage::KeygenCommit { commitment };
        self.sign(msg)
    }

    pub fn add_commitment(&mut self, id: &Uuid, commitment: &KeygenCommitment) -> Result<(), TrusteeError> {
        Ok(self.generator.receive_commitment(self.trustee_info[id].index, commitment)?)
    }

    pub fn received_commitments(&self) -> bool {
        self.generator.received_commitments()
    }

    pub fn gen_shares(&mut self) -> Result<HashMap<Uuid, Scalar>, TrusteeError> {
        let mut result = HashMap::new();
        for (id, info) in self.trustee_info.iter() {
            let share = self.generator.get_polynomial_share(info.index)?;
            if self.id == *id {
                self.generator.receive_share(info.index, &share)?;
            } else {
                result.insert(id.clone(), share);
            }
        }

        Ok(result)
    }

    pub async fn receive_shares(&mut self) -> Result<(), TrusteeError> {
        let index = self.trustee_info[&self.id].index;
        let addr = &self.trustee_info[&self.id].address;

        // Accept connections
        let mut listener = TcpListener::bind(addr).await?;

        while let Some(stream) = listener.next().await {
            if let Ok(mut stream) = stream {
                // Read entire stream
                let mut buffer = String::new();
                stream.read_to_string(&mut buffer).await?;

                // Decode message
                if let Ok(msg) = serde_json::from_str::<SignedMessage>(&buffer) {
                    // Check signature
                    if let Some(info) = self.trustee_info.get(&msg.sender_id) {
                        if msg.verify(&info.pubkey)? {
                            if let TrusteeMessage::KeygenShare { share } = msg.inner {
                                self.generator.receive_share(info.index, &share)?;
                            } else {
                                eprintln!("#{}: unexpected message type", index);
                            }
                        } else {
                            eprintln!("#{}: failed verifying signature from #{}", index, info.index);
                        }
                    } else {
                        eprintln!("#{}: unknown sender id: {}", index, msg.sender_id);
                    }
                } else {
                    eprintln!("#{}: received malformed message", index);
                }
            }

            // Check if we received all shares
            if self.generator.is_complete() {
                break;
            }
        }

        Ok(())
    }

    // Sign the given message
    fn sign(&self, message: TrusteeMessage) -> SignedMessage {
        let data = serde_json::to_string(&message).unwrap().as_bytes().to_vec();
        let signature = self.signing_keypair.sign(&data).as_ref().to_vec();

        SignedMessage {
            inner: message,
            signature,
            sender_id: self.id,
        }
    }

    async fn send_share(address: String, msg: SignedMessage) -> Result<(), TrusteeError> {
        loop {
            // Wait a moment for the socket to open
            time::delay_for(Duration::from_millis(200)).await;
            if let Ok(mut stream) = TcpStream::connect(&address).await {
                stream.write_all(serde_json::to_string(&msg)?.as_ref()).await?;
                return Ok(());
            }
        }
    }

    async fn get_registrations(&mut self, my_registration: &SignedMessage, client: &Client) -> Result<(), TrusteeError> {
        loop {
            // Wait a moment for other registrations
            time::delay_for(Duration::from_millis(200)).await;
            let res: WrappedResponse = client.get(&format!("{}/{}/trustee/all", &self.api_base_addr, &self.session_id))
                .send().await?
                .json().await?;

            // Check signatures
            if let Response::ResultSet(results) = res.msg {
                // Make sure our message is in there
                if !results.contains(my_registration) {
                    return Err(TrusteeError::MissingCommitment)?;
                }

                for result in results {
                    if let TrusteeMessage::Info { info } = &result.inner {
                        self.log.update(serde_json::to_string(&result.clone()).unwrap().as_bytes());
                        if result.verify(&info.pubkey)? {
                            self.add_info(info.clone());
                        }
                    }
                }
                break;
            } else {
                eprintln!("unexpected response: {:?}", res.msg);
            }
        }

        Ok(())
    }

    async fn get_commitments(&mut self, my_commit: &SignedMessage, client: &Client) -> Result<(), TrusteeError> {
        loop {
            // Wait a moment for other registrations
            time::delay_for(Duration::from_millis(200)).await;
            let res: WrappedResponse = client.get(&format!("{}/{}/keygen/commitment/all", self.api_base_addr, self.session_id))
                .send().await?
                .json().await?;

            // Check signatures
            if let Response::ResultSet(results) = res.msg {
                if self.verify_all(&results)? {
                    // Make sure our message is in there
                    if !results.contains(my_commit) {
                        return Err(TrusteeError::MissingCommitment)?;
                    }

                    for result in results {
                        if let TrusteeMessage::KeygenCommit { commitment } = &result.inner {
                            self.log.update(serde_json::to_string(&result.clone()).unwrap().as_bytes());
                            self.add_commitment(&result.sender_id, &commitment)?;
                        } else {
                            return Err(TrusteeError::InvalidResponse)?;
                        }
                    }
                    return Ok(());
                } else {
                    return Err(TrusteeError::InvalidSignature)?;
                }
            } else {
                eprintln!("unexpected response: {:?}", res.msg);
            }
        }
    }

    async fn get_signatures(&mut self, my_sig: &SignedMessage, client: &Client) -> Result<(), TrusteeError> {
        loop {
            // Wait a moment for other registrations
            time::delay_for(Duration::from_millis(200)).await;
            let res: WrappedResponse = client.get(&format!("{}/{}/keygen/sign/all", &self.api_base_addr, &self.session_id))
                .send().await?
                .json().await?;

            // Check signatures
            if let Response::ResultSet(results) = res.msg {
                if self.verify_all(&results)? {
                    // Make sure our message is in there
                    if !results.contains(my_sig) {
                        return Err(TrusteeError::MissingSignature)?;
                    }

                    for result in results {
                        if let TrusteeMessage::KeygenSign { .. } = &result.inner {
                            self.log.update(serde_json::to_string(&result.clone()).unwrap().as_bytes());
                        } else {
                            return Err(TrusteeError::InvalidResponse)?;
                        }
                    }
                    return Ok(());
                } else {
                    return Err(TrusteeError::InvalidSignature)?;
                }
            } else {
                eprintln!("unexpected response: {:?}", res.msg);
            }
        }
    }
}

pub struct Trustee {
    info: InternalInfo,
    _trustee_info: HashMap<Uuid, TrusteeInfo>,
    received_votes: Arc<Mutex<Vec<SignedMessage>>>,
    party: ThresholdParty,
    abort_handle: Option<AbortHandle>,
    log: Hasher,
}

#[derive(Clone)]
struct InternalInfo {
    api_base_addr: String,
    address: String,
    index: usize,
    id: Uuid,
    session_id: Uuid,
    client: Client,
    signing_keypair: Arc<SigningKeypair>,
    ctx: CryptoContext,
    pubkey: PublicKey,
}

impl Trustee {
    pub async fn new(api_base_addr: String,
                     session_id: Uuid,
                     ctx: CryptoContext,
                     index: usize,
                     min_trustees: usize,
                     trustee_count: usize) -> Result<Trustee, TrusteeError> {
        let mut trustee = GeneratingTrustee::new(api_base_addr.clone(), session_id.clone(), &ctx, index, min_trustees, trustee_count)?;
        let client = reqwest::Client::new();

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
        let msg = trustee.sign(TrusteeMessage::KeygenSign { pubkey: party.pubkey() });
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
            pubkey: party.pubkey(),
        };

        // TODO: Store on disk.
        Ok(Trustee {
            info,
            _trustee_info: trustee.trustee_info,
            received_votes: Arc::new(Mutex::new(Vec::new())),
            party,
            abort_handle: None,
            log: trustee.log,
        })
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
        let (future, handle) = futures::future::abortable(Self::receive_voter_data_task(self.info.clone(), self.received_votes.clone(), candidates));
        self.abort_handle = Some(handle);
        tokio::spawn(future);
    }

    async fn receive_voter_data_task(info: InternalInfo,
                                     received_votes: Arc<Mutex<Vec<SignedMessage>>>,
                                     candidates: Arc<HashMap<usize, Candidate>>) -> Result<(), TrusteeError> {
        let mut listener = TcpListener::bind(&info.address).await?;

        while let Some(stream) = listener.next().await {
            if let Ok(stream) = stream {
                tokio::spawn(Self::receive_voter_data_inner(stream, info.clone(), received_votes.clone(), candidates.clone()));
            }
        }

        Ok(())
    }

    async fn receive_voter_data_inner(mut stream: TcpStream,
                                      info: InternalInfo,
                                      received_votes: Arc<Mutex<Vec<SignedMessage>>>,
                                      candidates: Arc<HashMap<usize, Candidate>>) -> Result<(), TrusteeError> {
        // Read entire stream
        let mut buffer = String::new();
        stream.read_to_string(&mut buffer).await?;

        if let Ok(msg) = serde_json::from_str::<VoterMessage>(&buffer) {
            match msg {
                VoterMessage::EcCommit { voter_id, enc_mac, enc_vote, prf_know_mac, prf_know_vote } => {
                    tokio::spawn((async move || {
                        if let Err(e) = Self::handle_ec_commit(info.clone(), voter_id, enc_mac, enc_vote, prf_know_mac, prf_know_vote).await {
                            eprintln!("#{}: error handling commit: {}", info.index, e);
                        }
                    })());
                },
                VoterMessage::Ballot(ballot) => {
                    tokio::spawn((async move || {
                        if let Err(e) = Self::handle_ballot(info.clone(), received_votes.clone(), candidates.clone(), ballot).await {
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

    async fn handle_ec_commit(mut info: InternalInfo,
                              voter_id: VoterId,
                              enc_mac: Ciphertext,
                              enc_vote: Ciphertext,
                              prf_know_mac: PrfKnowDlog,
                              prf_know_vote: PrfKnowDlog) -> Result<(), TrusteeError> {
        // Check the proofs
        if !prf_know_mac.verify()? {
            eprintln!("#{}: failed to verify MAC proof-of-knowledge", info.index);
            return Ok(());
        }
        if !prf_know_vote.verify()? {
            eprintln!("#{}: failed to verify vote proof-of-knowledge", info.index);
            return Ok(());
        }

        // Re-randomise encryptions
        let r = info.ctx.random_power();
        let enc_mac = info.pubkey.rerand(&info.ctx, &enc_mac, &r);
        let r = info.ctx.random_power();
        let enc_vote = info.pubkey.rerand(&info.ctx, &enc_vote, &r);

        // Construct message
        let inner = TrusteeMessage::EcCommit { voter_id, enc_mac, enc_vote };
        let data = serde_json::to_string(&inner)?.as_bytes().to_vec();
        let signature = info.signing_keypair.sign(&data).as_ref().to_vec();

        let msg = SignedMessage {
            inner,
            signature,
            sender_id: info.id,
        };

        // Post to WBB
        let response: WrappedResponse = info.client.post(&format!("{}/{}/cast/commit", &info.api_base_addr, &info.session_id))
            .json(&msg).send().await?
            .json().await?;

        if !response.status {
            eprintln!("error submitting ident: {:?}", response.msg);
        }

        Ok(())
    }

    async fn handle_ballot(mut info: InternalInfo,
                           received_votes: Arc<Mutex<Vec<SignedMessage>>>,
                           candidates: Arc<HashMap<usize, Candidate>>,
                           ballot: Ballot) -> Result<(), TrusteeError> {
        // Check the proofs
        if !ballot.p1_prf_a.verify()? {
            eprintln!("#{}: failed to verify proof-of-knowledge for a", info.index);
            return Ok(());
        }
        if !ballot.p1_prf_b.verify()? {
            eprintln!("#{}: failed to verify proof-of-knowledge for b", info.index);
            return Ok(());
        }
        if !ballot.p1_prf_r_a.verify()? {
            eprintln!("#{}: failed to verify proof-of-knowledge for r_a", info.index);
            return Ok(());
        }
        if !ballot.p1_prf_r_b.verify()? {
            eprintln!("#{}: failed to verify proof-of-knowledge for r_b", info.index);
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
        let r = info.ctx.random_power();
        let enc_id = info.pubkey.rerand(&info.ctx, &ballot.p2_enc_id, &r);
        let r = info.ctx.random_power();
        let enc_a = info.pubkey.rerand(&info.ctx, &ballot.p1_enc_a, &r);
        let r = info.ctx.random_power();
        let enc_b = info.pubkey.rerand(&info.ctx, &ballot.p1_enc_b, &r);
        let r = info.ctx.random_power();
        let enc_r_a = info.pubkey.rerand(&info.ctx, &ballot.p1_enc_r_a, &r);
        let r = info.ctx.random_power();
        let enc_r_b = info.pubkey.rerand(&info.ctx, &ballot.p1_enc_r_b, &r);

        let vote = ballot.p1_vote;
        let vote_value = u128::from_str_radix(&vote, 10)
            .map_err(|_| TrusteeError::Decode)?;
        let vote_value: Scalar = vote_value.into();
        let prf_enc_vote = info.ctx.random_power();
        let enc_vote = info.pubkey.encrypt(&info.ctx, &CurveElem::try_encode(vote_value)?, &prf_enc_vote);

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
}