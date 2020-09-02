use uuid::Uuid;
use common::sign::{SigningKeypair, SignedMessage};
use common::net::{TrusteeInfo, TrusteeMessage, WrappedResponse, Response};
use std::collections::HashMap;
use cryptid::threshold::{ThresholdGenerator, KeygenCommitment, Threshold, PubkeyProof};
use cryptid::{Hasher, CryptoError, Scalar};
use cryptid::elgamal::CryptoContext;
use crate::TrusteeError;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Duration;
use tokio::time;
use reqwest::Client;
use tokio::prelude::io::{AsyncWriteExt, AsyncReadExt};
use tokio::stream::StreamExt;

pub struct GeneratingTrustee {
    api_base_addr: String,
    session_id: Uuid,
    pub(crate) id: Uuid,
    pub(crate) signing_keypair: SigningKeypair,
    pub(crate) trustee_info: HashMap<Uuid, TrusteeInfo>,
    pub(crate) generator: ThresholdGenerator,
    pub(crate) log: Hasher,
}

impl GeneratingTrustee {
    pub fn new(
        api_base_addr: String,
        advertised_addr: String,
        session_id: Uuid,
        ctx: &CryptoContext,
        index: usize,
        k: usize,
        n: usize
    ) -> Result<GeneratingTrustee, CryptoError> {
        let mut ctx = ctx.clone();
        let id = Uuid::new_v4();

        // Generate a signature keypair
        let signing_keypair = SigningKeypair::new(&ctx);

        // Create identification for this trustee
        let port = 14000 + index;
        let mut trustee_info = HashMap::new();
        let my_info = TrusteeInfo {
            id,
            pubkey: signing_keypair.public_key().into(),
            pubkey_proof: None,
            index,
            address: format!("{}:{}", advertised_addr, port),
        };
        trustee_info.insert(id, my_info);

        let generator = ThresholdGenerator::new(&mut ctx, index, k, n);

        Ok(Self {
            api_base_addr,
            session_id,
            id,
            signing_keypair,
            trustee_info,
            generator,
            log: Hasher::sha_256(),
        })
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
    pub fn from_seed(
        api_base_addr: String,
        advertised_addr: String,
        session_id: Uuid,
        ctx: &CryptoContext,
        index: usize,
        k: usize,
        n: usize,
        pubkey_proof: PubkeyProof,
        seed: &[u8],
        id: Uuid,
    ) -> Result<GeneratingTrustee, CryptoError> {
        let mut ctx = ctx.clone();

        // Generate a signature keypair
        let signing_keypair = SigningKeypair::from_seed(seed);

        // Create identification for this trustee
        let port = 14000 + index;
        let mut trustee_info = HashMap::new();
        let my_info = TrusteeInfo {
            id,
            pubkey: signing_keypair.public_key().into(),
            pubkey_proof: Some(pubkey_proof),
            index,
            address: format!("{}:{}", advertised_addr, port),
        };
        trustee_info.insert(id, my_info);

        let generator = ThresholdGenerator::new(&mut ctx, index, k, n);

        Ok(Self {
            api_base_addr,
            session_id,
            id,
            signing_keypair,
            trustee_info,
            generator,
            log: Hasher::sha_256(),
        })
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
    pub(crate) fn sign(&self, message: TrusteeMessage) -> SignedMessage {
        let data = serde_json::to_string(&message).unwrap().as_bytes().to_vec();
        let signature = self.signing_keypair.sign(&data);

        SignedMessage {
            inner: message,
            signature,
            sender_id: self.id,
        }
    }

    pub(crate) async fn send_share(address: String, msg: SignedMessage) -> Result<(), TrusteeError> {
        loop {
            // Wait a moment for the socket to open
            time::delay_for(Duration::from_millis(200)).await;
            if let Ok(mut stream) = TcpStream::connect(&address).await {
                stream.write_all(serde_json::to_string(&msg)?.as_ref()).await?;
                return Ok(());
            }
        }
    }

    pub(crate) async fn get_registrations(&mut self, my_info: &SignedMessage, client: &Client) -> Result<(), TrusteeError> {
        loop {
            let my_info = match &my_info.inner {
                TrusteeMessage::Info { info } => Ok(info),
                _ => Err(TrusteeError::InvalidState)
            }?;

            // Wait a moment for other registrations
            time::delay_for(Duration::from_millis(200)).await;
            let res: WrappedResponse = client.get(&format!("{}/{}/trustee/all", &self.api_base_addr, &self.session_id))
                .send().await?
                .json().await?;

            // Check signatures
            if let Response::ResultSet(results) = res.msg {
                // Make sure our message is in there
                if !results.iter().any(|msg| {
                    match &msg.inner {
                        TrusteeMessage::Info { info } => {
                            info.pubkey == my_info.pubkey && info.id == my_info.id
                        },
                        _ => false,
                    }
                }) {
                    return Err(TrusteeError::MissingRegistration)?;
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

    pub(crate) async fn get_commitments(&mut self, my_commit: &SignedMessage, client: &Client) -> Result<(), TrusteeError> {
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
                        return Err(TrusteeError::MissingKeygenCommitment)?;
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

    pub(crate) async fn get_signatures(&mut self, my_sig: &SignedMessage, client: &Client) -> Result<(), TrusteeError> {
        loop {
            let (my_pubkey, my_pubkey_proof) = match &my_sig.inner {
                TrusteeMessage::KeygenSign { pubkey, pubkey_proof } => Ok((pubkey, pubkey_proof)),
                _ => Err(TrusteeError::InvalidState)
            }?;
            // Wait a moment for other registrations
            time::delay_for(Duration::from_millis(200)).await;
            let res: WrappedResponse = client.get(&format!("{}/{}/keygen/sign/all", &self.api_base_addr, &self.session_id))
                .send().await?
                .json().await?;

            // Check signatures
            if let Response::ResultSet(results) = res.msg {
                if self.verify_all(&results)? {
                    // Make sure our message is in there
                    // if !results.contains(my_sig) {
                    //     return Err(TrusteeError::MissingSignature)?;
                    // }
                    // Make sure our message is in there
                    if !results.iter().any(|msg| {
                        match &msg.inner {
                            TrusteeMessage::KeygenSign { pubkey, pubkey_proof } => {
                                pubkey == my_pubkey && pubkey_proof == my_pubkey_proof
                            },
                            _ => false,
                        }
                    }) {
                        return Err(TrusteeError::MissingRegistration)?;
                    }

                    for result in results {
                        if let TrusteeMessage::KeygenSign { pubkey: _, pubkey_proof } = &result.inner {
                            self.log.update(serde_json::to_string(&result.clone()).unwrap().as_bytes());
                            self.trustee_info.get_mut(&result.sender_id).unwrap()
                                .pubkey_proof.replace(pubkey_proof.clone());
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