use std::convert::{TryInto, TryFrom};
use std::error::Error;
use std::fmt::{Display, Formatter};

use cryptid::{AsBase64, Scalar};
use cryptid::elgamal::{PublicKey, Ciphertext};
use cryptid::threshold::{KeygenCommitment, DecryptShare, PubkeyProof};
use tokio_postgres::Client;
use uuid::Uuid;

use common::APP_NAME;
use common::config::PapervoteConfig;
use common::sign::{SignedMessage, SigningPubKey};
use common::net::{TrusteeMessage, TrusteeInfo};
use common::vote::VoterId;
use cryptid::commit::Commitment;
use cryptid::shuffle::ShuffleProof;
use std::collections::HashMap;
use cryptid::zkp::PrfEqDlogs;

#[derive(Debug)]
pub enum DbError {
    Config(confy::ConfyError),
    Connect,
    Sql(tokio_postgres::Error),
    SchemaFailure(&'static str),
    InsertAlreadyExists,
    NotEnoughRows,
}

impl From<confy::ConfyError> for DbError {
    fn from(e: confy::ConfyError) -> Self {
        Self::Config(e)
    }
}

impl From<tokio_postgres::Error> for DbError {
    fn from(e: tokio_postgres::Error) -> Self {
        Self::Sql(e)
    }
}

impl Display for DbError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for DbError {}

pub struct DbClient {
    client: Client,
}

impl DbClient {
    pub async fn new() -> Result<Self, DbError> {
        let cfg: PapervoteConfig = confy::load(APP_NAME)?;
        let (client, conn) = tokio_postgres::Config::new()
            .host(&cfg.db_host)
            .user(&cfg.db_user)
            .password(&cfg.db_pass)
            .dbname(&cfg.db_name)
            .connect(tokio_postgres::NoTls)
            .await
            .map_err(|_| DbError::Connect)?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                eprintln!("connection error: {}", e);
            }
        });

        let client = Self { client };
        client.reset().await?;
        client.init().await?;

        Ok(client)
    }

    async fn init(&self) -> Result<(), DbError> {
        self.client.batch_execute("
            CREATE TABLE IF NOT EXISTS trustees (
                id              SERIAL PRIMARY KEY,
                session         UUID NOT NULL,
                uuid            UUID NOT NULL,
                pubkey          TEXT NOT NULL UNIQUE,
                index           SMALLINT NOT NULL,
                address         TEXT NOT NULL,
                signature       TEXT NOT NULL UNIQUE,
                CONSTRAINT      unique_trustee UNIQUE(session, uuid),
                CONSTRAINT      unique_index UNIQUE(session, index),
                CONSTRAINT      unique_address UNIQUE(session, address)
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id              SERIAL PRIMARY KEY,
                uuid            UUID NOT NULL UNIQUE,
                min_trustees    SMALLINT NOT NULL,
                trustee_count   SMALLINT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS parameters (
                id              SERIAL PRIMARY KEY,
                session         UUID NOT NULL UNIQUE,
                pubkey          TEXT NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS parameter_signatures (
                id              SERIAL PRIMARY KEY,
                session         UUID NOT NULL,
                trustee         UUID NOT NULL,
                pubkey_proof    TEXT NOT NULL UNIQUE,
                signature       TEXT NOT NULL UNIQUE,
                CONSTRAINT      unqiue_trustee_keygen_sig UNIQUE(session, trustee)
            );
            CREATE TABLE IF NOT EXISTS keygen_commitments (
                id              SERIAL PRIMARY KEY,
                session         UUID NOT NULL,
                trustee         UUID NOT NULL,
                commitment      TEXT NOT NULL UNIQUE,
                signature       TEXT NOT NULL UNIQUE,
                CONSTRAINT      unique_trustee_keygen_commit UNIQUE(session, trustee)
            );
            CREATE TABLE IF NOT EXISTS wbb_idents (
                id              SERIAL PRIMARY KEY,
                session         UUID NOT NULL,
                voter_id        TEXT NOT NULL,
                c_a             TEXT NOT NULL UNIQUE,
                c_b             TEXT NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS wbb_commits (
                id              SERIAL PRIMARY KEY,
                session         UUID NOT NULL,
                voter_id        TEXT NOT NULL,
                enc_mac         TEXT UNIQUE NOT NULL,
                enc_vote        TEXT UNIQUE NOT NULL,
                signed_by       UUID NOT NULL,
                signature       TEXT UNIQUE NOT NULL
            );
            CREATE TABLE IF NOT EXISTS wbb_votes (
                id              SERIAL PRIMARY KEY,
                session         UUID NOT NULL,
                vote            TEXT NOT NULL,
                enc_vote        TEXT UNIQUE NOT NULL,
                prf_enc_vote    TEXT UNIQUE NOT NULL,
                enc_voter_id    TEXT UNIQUE NOT NULL,
                enc_param_a     TEXT UNIQUE NOT NULL,
                enc_param_b     TEXT UNIQUE NOT NULL,
                enc_param_r_a   TEXT UNIQUE NOT NULL,
                enc_param_r_b   TEXT UNIQUE NOT NULL,
                signed_by       UUID NOT NULL,
                signature       TEXT UNIQUE NOT NULL
            );
            CREATE TABLE IF NOT EXISTS wbb_votes_mix (
                id              SERIAL PRIMARY KEY,
                session         UUID NOT NULL,
                mix_index       SMALLINT NOT NULL,
                index           INTEGER NOT NULL,
                enc_vote        TEXT UNIQUE NOT NULL,
                enc_voter_id    TEXT UNIQUE NOT NULL,
                enc_param_a     TEXT UNIQUE NOT NULL,
                enc_param_b     TEXT UNIQUE NOT NULL,
                enc_param_r_a   TEXT UNIQUE NOT NULL,
                enc_param_r_b   TEXT UNIQUE NOT NULL,
                CONSTRAINT      unique_wbb_votes_mix_session_index UNIQUE(session, mix_index, index)
            );
            CREATE TABLE IF NOT EXISTS wbb_votes_mix_proofs (
                id              SERIAL PRIMARY KEY,
                session         UUID NOT NULL,
                mix_index       SMALLINT NOT NULL,
                proof           TEXT NOT NULL,
                signed_by       UUID NOT NULL,
                signature       TEXT UNIQUE NOT NULL,
                CONSTRAINT      unique_wbb_votes_mix_proofs_session_index UNIQUE(session, mix_index),
                CONSTRAINT      unique_wbb_votes_mix_proofs_session_signer UNIQUE(session, signed_by)
            );
            CREATE TABLE IF NOT EXISTS wbb_votes_decrypt (
                id              SERIAL PRIMARY KEY,
                session         UUID NOT NULL,
                index           INTEGER NOT NULL,
                trustee         UUID NOT NULL,
                signature       TEXT UNIQUE NOT NULL,
                share           TEXT UNIQUE NOT NULL,
                CONSTRAINT      unique_wbb_votes_decrypt UNIQUE(session, index, trustee)
            );
            CREATE TABLE IF NOT EXISTS wbb_pet_commits (
                id              SERIAL PRIMARY KEY,
                session         UUID NOT NULL,
                trustee         UUID NOT NULL,
                voter_id        TEXT NOT NULL,
                vote_commit     TEXT UNIQUE NOT NULL,
                mac_commit      TEXT UNIQUE NOT NULL,
                signature       TEXT UNIQUE NOT NULL,
                CONSTRAINT      unique_wbb_pet_commits UNIQUE(session, trustee, voter_id)
            );
        ").await?;

        Ok(())
    }

    // TODO: Prepared statements
    pub async fn insert_session(&self, uuid: &Uuid, min_trustees: usize, trustee_count: usize) -> Result<(), DbError> {
        let result = self.client.execute("
            INSERT INTO sessions(uuid, min_trustees, trustee_count)
            VALUES($1, $2, $3);
        ", &[&uuid, &(min_trustees as i16), &(trustee_count as i16)]).await?;
        if result > 0 {
            Ok(())
        } else {
            Err(DbError::InsertAlreadyExists)
        }
    }

    pub async fn insert_trustee(&self, session: &Uuid, uuid: &Uuid, pubkey: &SigningPubKey, index: usize, address: &str, signature: &[u8]) -> Result<(), DbError> {
        let result = self.client.execute("
            INSERT INTO trustees(session, uuid, pubkey, index, address, signature)
            VALUES($1, $2, $3, $4, $5, $6);
        ", &[
            &session,
            &uuid,
            &pubkey.to_string(),
            &(index as i16),
            &address.to_string(),
            &base64::encode(signature)
        ]).await?;

        if result > 0 {
            Ok(())
        } else {
            Err(DbError::InsertAlreadyExists)
        }
    }
    
    pub async fn insert_commitment(&self, session: &Uuid, trustee: &Uuid, commitment: &KeygenCommitment, signature: &[u8]) -> Result<(), DbError> {
        let result = self.client.execute("
            INSERT INTO keygen_commitments(session, trustee, commitment, signature)
            VALUES($1, $2, $3, $4);
        ", &[
            &session,
            &trustee,
            &commitment.to_string(),
            &base64::encode(signature)
        ]).await?;

        if result > 0 {
            Ok(())
        } else {
            Err(DbError::InsertAlreadyExists)
        }
    }

    pub async fn insert_pubkey_sig(&self, session: &Uuid, trustee: &Uuid, pubkey: &PublicKey, pubkey_proof: &PubkeyProof, signature: &[u8]) -> Result<(), DbError> {
        // For conflicts, don't worry because we only care about the signatures
        self.client.execute("
            INSERT INTO parameters(session, pubkey)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
        ", &[&session, &pubkey.as_base64()]).await?;

        let result = self.client.execute("
            INSERT INTO parameter_signatures(session, trustee, pubkey_proof, signature)
            VALUES($1, $2, $3, $4);
        ", &[
            &session,
            &trustee,
            &pubkey_proof.as_base64(),
            &base64::encode(signature)
        ]).await?;

        if result > 0 {
            Ok(())
        } else {
            Err(DbError::InsertAlreadyExists)
        }
    }

    pub async fn insert_ident(&self,
                              session: &Uuid,
                              voter_id: VoterId,
                              c_a: &Commitment,
                              c_b: &Commitment
    ) -> Result<(), DbError> {
        let result = self.client.execute("
            INSERT INTO wbb_idents(session, voter_id, c_a, c_b)
            VALUES ($1, $2, $3, $4);
        ", &[session, &voter_id.to_string(), &c_a.to_string(), &c_b.to_string()]).await?;

        if result > 0 {
            Ok(())
        } else {
            Err(DbError::InsertAlreadyExists)
        }
    }

    pub async fn insert_ec_commit(&self,
                                  session: &Uuid,
                                  voter_id: VoterId,
                                  enc_mac: &Ciphertext,
                                  enc_vote: &Ciphertext,
                                  signed_by: &Uuid,
                                  signature: &[u8]
    ) -> Result<(), DbError> {
        let result = self.client.execute("
            INSERT INTO wbb_commits(session, voter_id, enc_mac, enc_vote, signed_by, signature)
            VALUES ($1, $2, $3, $4, $5, $6);
        ", &[session, &voter_id.to_string(), &enc_mac.to_string(), &enc_vote.to_string(), signed_by, &base64::encode(signature)]).await?;

        if result > 0 {
            Ok(())
        } else {
            Err(DbError::InsertAlreadyExists)
        }
    }

    pub async fn insert_ec_vote(&self,
                                session: &Uuid,
                                vote: String,
                                enc_vote: &Ciphertext,
                                prf_enc_vote: &Scalar,
                                enc_id: &Ciphertext,
                                enc_a: &Ciphertext,
                                enc_b: &Ciphertext,
                                enc_r_a: &Ciphertext,
                                enc_r_b: &Ciphertext,
                                signed_by: &Uuid,
                                signature: &[u8]) -> Result<(), DbError> {
        let result = self.client.execute("
            INSERT INTO wbb_votes(session, vote, enc_vote, prf_enc_vote, enc_voter_id, enc_param_a, enc_param_b, enc_param_r_a, enc_param_r_b, signed_by, signature)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);
        ", &[session, &vote, &enc_vote.to_string(), &prf_enc_vote.as_base64(), &enc_id.to_string(), &enc_a.to_string(), &enc_b.to_string(),
            &enc_r_a.to_string(), &enc_r_b.to_string(), signed_by, &base64::encode(signature)]).await?;

        if result > 0 {
            Ok(())
        } else {
            Err(DbError::InsertAlreadyExists)
        }
    }

    pub async fn insert_ec_vote_mix(&self,
                                    session: &Uuid,
                                    mix_index: i16,
                                    enc_votes: &[Ciphertext],
                                    enc_voter_ids: &[Ciphertext],
                                    enc_as: &[Ciphertext],
                                    enc_bs: &[Ciphertext],
                                    enc_r_as: &[Ciphertext],
                                    enc_r_bs: &[Ciphertext],
                                    proof: &ShuffleProof,
                                    signed_by: &Uuid,
                                    signature: &[u8]
    ) -> Result<(), DbError> {
        for i in 0..enc_votes.len() {
            if self.client.execute("
                INSERT INTO wbb_votes_mix(session, mix_index, index, enc_vote, enc_voter_id, enc_param_a, enc_param_b, enc_param_r_a, enc_param_r_b)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ", &[session, &mix_index, &(i as i32), &enc_votes[i].to_string(),
                         &enc_voter_ids[i].to_string(), &enc_as[i].to_string(),
                         &enc_bs[i].to_string(), &enc_r_as[i].to_string(),
                         &enc_r_bs[i].to_string()]).await? == 0 {
                return Err(DbError::InsertAlreadyExists);
            }
        }
        let result = self.client.execute("
            INSERT INTO wbb_votes_mix_proofs(session, mix_index, proof, signed_by, signature)
            VALUES ($1, $2, $3, $4, $5);
        ", &[session, &mix_index, &proof.to_string(), signed_by, &base64::encode(signature)]).await?;

        if result > 0 {
            Ok(())
        } else {
            Err(DbError::InsertAlreadyExists)
        }
    }

    pub async fn insert_ec_vote_decrypt(&self,
                                        session: &Uuid,
                                        trustee: &Uuid,
                                        signatures: &[Vec<u8>],
                                        shares: &[Vec<DecryptShare>]
    ) -> Result<(), DbError> {
        for i in 0..shares.len() {
            if self.client.execute("
                INSERT INTO wbb_votes_decrypt(session, index, trustee, signature, share)
                VALUES ($1, $2, $3, $4, $5);
            ", &[session, &(i as i32), trustee, &base64::encode(&signatures[i]),
                &serde_json::to_string(&shares[i])
                    .map_err(|_| DbError::SchemaFailure("share"))?
            ]).await? == 0 {
                return Err(DbError::InsertAlreadyExists);
            }
        }

        Ok(())
    }

    pub async fn insert_ec_pet_commits(&self,
                                       session: &Uuid,
                                       trustee: &Uuid,
                                       voter_ids: &[VoterId],
                                       vote_commits: &[(Commitment, Commitment)],
                                       mac_commits: &[(Commitment, Commitment)],
                                       signatures: &[Vec<u8>]
    ) -> Result<(), DbError> {
        for i in 0..signatures.len() {
            if self.client.execute("
                INSERT INTO wbb_pet_commits(session, trustee, voter_id, vote_commit_1, vote_commit_2, mac_commit_1, mac_commit_2, signature)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8);
            ", &[session, trustee, &voter_ids[i].to_string(), &vote_commits[i].0.to_string(),
                &vote_commits[i].1.to_string(), &mac_commits[i].0.to_string(),
                &mac_commits[i].1.to_string(), &base64::encode(&signatures[i])])
            .await? == 0 {
                return Err(DbError::InsertAlreadyExists);
            }
        }

        Ok(())

    }

    pub async fn count_trustees(&self, session: &Uuid) -> Result<usize, DbError> {
        let result = self.client.query_one("
            SELECT COUNT(1) FROM trustees WHERE session=$1;
        ", &[&session]).await?;
        let count: i64 = result.get(0);
        Ok(count as usize)
    }

    pub async fn count_commitments(&self, session: &Uuid) -> Result<usize, DbError> {
        let result = self.client.query_one("
            SELECT COUNT(1) FROM keygen_commitments WHERE session=$1;
        ", &[&session]).await?;
        let count: i64 = result.get(0);
        Ok(count as usize)
    }

    pub async fn get_trustee_count(&self, session: &Uuid) -> Result<usize, DbError> {
        // Below only errors if not found
        let result = self.client.query_one("
            SELECT trustee_count FROM sessions WHERE uuid=$1;
        ", &[&session]).await.map_err(|_| DbError::NotEnoughRows)?;

        let count: i16 = result.get(0);
        Ok(count as usize)
    }

    pub async fn get_one_trustee_info(&self, session: &Uuid, uuid: &Uuid) -> Result<TrusteeInfo, DbError> {
        let rows = self.client.query("
            SELECT pubkey, index, address
            FROM trustees
            WHERE session=$1 AND uuid=$2;
        ", &[&session, &uuid]).await?;
        
        if rows.len() > 0 {
            let row = rows.first().ok_or(DbError::NotEnoughRows)?;
            let pubkey: String = row.get("pubkey");
            let pubkey: SigningPubKey = pubkey.try_into().map_err(|_| DbError::SchemaFailure("pubkey"))?;
            let index: i16 = row.get("index");
            let address: String = row.get("address");

            let info = TrusteeInfo {
                id: uuid.clone(),
                pubkey,
                pubkey_proof: None, // Assume this isn't being used
                index: index as usize,
                address
            };
            Ok(info)
        } else {
            Err(DbError::NotEnoughRows)
        }
    }

    pub async fn get_all_trustee_info(&self, session: &Uuid) -> Result<Vec<SignedMessage>, DbError> {
        let rows = self.client.query("
            SELECT uuid, pubkey, index, address, signature
            FROM trustees
            WHERE session=$1;
        ", &[&session]).await?;

        let mut result = Vec::with_capacity(rows.len());
        for row in rows.into_iter() {
            let id: Uuid = row.get("uuid");
            let pubkey: String = row.get("pubkey");
            let pubkey: SigningPubKey = pubkey.try_into().map_err(|_| DbError::SchemaFailure("pubkey"))?;
            let index: i16 = row.get("index");
            let address: String = row.get("address");
            let signature: String = row.get("signature");

            let info = TrusteeInfo {
                id,
                pubkey,
                pubkey_proof: None,
                index: index as usize,
                address
            };
            result.push(info.into_signed_msg(signature).map_err(|_| DbError::SchemaFailure("result"))?);
        }

        Ok(result)
    }

    pub async fn get_all_commitments(&self, session: &Uuid) -> Result<Vec<SignedMessage>, DbError> {
        let rows = self.client.query("
            SELECT trustee, commitment, signature
            FROM keygen_commitments
            WHERE session=$1;
        ", &[&session]).await?;

        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let sender_id: Uuid = row.get("trustee");
            let commitment: String = row.get("commitment");
            let commitment = commitment.try_into().map_err(|_| DbError::SchemaFailure("commitment"))?;
            let signature: String = row.get("signature");
            let signature: Vec<u8> = base64::decode(&signature).map_err(|_| DbError::SchemaFailure("signature"))?;
            let inner = TrusteeMessage::KeygenCommit { commitment };

            result.push(SignedMessage {
                inner,
                signature,
                sender_id,
            });
        }

        Ok(result)
    }

    pub async fn get_all_pubkey_sigs(&self, session: &Uuid) -> Result<Vec<SignedMessage>, DbError> {
        let row = self.client.query_one("
            SELECT pubkey FROM parameters WHERE session=$1;
        ", &[&session]).await.map_err(|_| DbError::NotEnoughRows)?;
        let pubkey: String = row.get("pubkey");
        let pubkey = PublicKey::try_from_base64(pubkey.as_str())
            .map_err(|_| DbError::SchemaFailure("pubkey"))?;

        let rows = self.client.query("
            SELECT trustee, pubkey_proof, signature
            FROM parameter_signatures
            WHERE session=$1;
        ", &[&session]).await?;

        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let sender_id: Uuid = row.get("trustee");
            let signature: String = row.get("signature");
            let signature: Vec<u8> = base64::decode(&signature)
                .map_err(|_| DbError::SchemaFailure("signature"))?;
            let pubkey_proof: String = row.get("pubkey_proof");
            let pubkey_proof = PubkeyProof::try_from_base64(pubkey_proof.as_str())
                .map_err(|_| DbError::SchemaFailure("pubkey_proof"))?;

            let inner = TrusteeMessage::KeygenSign { pubkey, pubkey_proof };

            result.push(SignedMessage {
                inner,
                signature,
                sender_id,
            });
        }

        Ok(result)
    }

    pub async fn get_all_enc_votes(&self, session: &Uuid) -> Result<Vec<Vec<Ciphertext>>, DbError> {
        let rows = self.client.query("
            SELECT enc_vote, enc_voter_id, enc_param_a, enc_param_b, enc_param_r_a, enc_param_r_b
            FROM wbb_votes
            WHERE session=$1
            ORDER BY id
        ", &[session]).await?;

        let mut result = Vec::new();
        for row in rows {
            let s: String = row.get(0);
            let vote = Ciphertext::try_from(s).map_err(|_| DbError::SchemaFailure("vote"))?;
            let s: String = row.get(1);
            let id = Ciphertext::try_from(s).map_err(|_| DbError::SchemaFailure("voter id"))?;
            let s: String = row.get(2);
            let a = Ciphertext::try_from(s).map_err(|_| DbError::SchemaFailure("a"))?;
            let s: String = row.get(3);
            let b = Ciphertext::try_from(s).map_err(|_| DbError::SchemaFailure("b"))?;
            let s: String = row.get(4);
            let r_a = Ciphertext::try_from(s).map_err(|_| DbError::SchemaFailure("r_a"))?;
            let s: String = row.get(5);
            let r_b = Ciphertext::try_from(s).map_err(|_| DbError::SchemaFailure("r_b"))?;
            result.push(vec![vote, id, a, b, r_a, r_b]);
        }

        Ok(result)
    }

    pub async fn get_mix_votes(&self, session: &Uuid, mix_index: i16) -> Result<Vec<Vec<Ciphertext>>, DbError> {
        let rows = self.client.query("
            SELECT enc_vote, enc_voter_id, enc_param_a, enc_param_b, enc_param_r_a, enc_param_r_b
            FROM wbb_votes_mix
            WHERE session=$1 AND mix_index=$2
            ORDER BY index;
        ", &[session, &mix_index]).await?;

        let mut result = Vec::new();
        for row in rows {
            let s: String = row.get(0);
            let vote = Ciphertext::try_from(s).map_err(|_| DbError::SchemaFailure("vote"))?;
            let s: String = row.get(1);
            let id = Ciphertext::try_from(s).map_err(|_| DbError::SchemaFailure("voter id"))?;
            let s: String = row.get(2);
            let a = Ciphertext::try_from(s).map_err(|_| DbError::SchemaFailure("a"))?;
            let s: String = row.get(3);
            let b = Ciphertext::try_from(s).map_err(|_| DbError::SchemaFailure("b"))?;
            let s: String = row.get(4);
            let r_a = Ciphertext::try_from(s).map_err(|_| DbError::SchemaFailure("r_a"))?;
            let s: String = row.get(5);
            let r_b = Ciphertext::try_from(s).map_err(|_| DbError::SchemaFailure("r_b"))?;
            result.push(vec![vote, id, a, b, r_a, r_b]);
        }

        Ok(result)
    }

    pub async fn get_decrypt(&self, session: &Uuid) -> Result<Vec<Vec<(Uuid, Vec<u8>, Vec<DecryptShare>)>>, DbError> {
        let rows = self.client.query("
            SELECT trustee, signature, share, index
            FROM wbb_votes_decrypt
            WHERE session=$1
            ORDER BY index;
        ", &[session]).await?;

        let mut share_map = HashMap::new();

        for row in rows {
            let trustee = row.get("trustee");

            let signature: String = row.get("signature");
            let signature = base64::decode(signature)
                .map_err(|_| DbError::SchemaFailure("signature"))?;

            let share: String = row.get("share");
            let share: Vec<DecryptShare> = serde_json::from_str(share.as_str())
                .map_err(|_| DbError::SchemaFailure("share"))?;

            let index: i32 = row.get("index");
            share_map.entry(index).or_insert(Vec::new())
                .push((trustee, signature, share));
        }

        let mut indices = share_map.keys().collect::<Vec<_>>();
        indices.sort();

        let mut result = Vec::new();
        for index in indices.into_iter() {
            result.push(share_map[index].clone());
        }

        Ok(result)
    }

    pub async fn get_all_idents(&self, session: &Uuid) -> Result<Vec<(VoterId, Commitment, Commitment)>, DbError> {
        // Below only errors if not found
        let rows = self.client.query("
            SELECT voter_id, c_a, c_b FROM wbb_idents WHERE session=$1;
        ", &[session]).await.map_err(|_| DbError::NotEnoughRows)?;

        let mut result = Vec::new();
        for row in rows {
            let voter_id: String = row.get("voter_id");
            let voter_id = VoterId::from(voter_id);

            let c_a: String = row.get("c_a");
            let c_a = Commitment::try_from(c_a)
                .map_err(|_| DbError::SchemaFailure("c_a"))?;

            let c_b: String = row.get("c_b");
            let c_b = Commitment::try_from(c_b)
                .map_err(|_| DbError::SchemaFailure("c_b"))?;

            result.push((voter_id, c_a, c_b));
        }

        Ok(result)
    }

    pub async fn get_all_ec_commits(&self, session: &Uuid) -> Result<Vec<SignedMessage>, DbError> {
        let rows = self.client.query("
            SELECT voter_id, enc_mac, enc_vote, signed_by, signature FROM wbb_commits WHERE session=$1;
        ", &[session]).await?;

        let mut result = Vec::new();
        for row in rows {
            let voter_id: String = row.get("voter_id");
            let voter_id = VoterId::from(voter_id);

            let enc_mac: String = row.get("enc_mac");
            let enc_mac = Ciphertext::try_from(enc_mac)
                .map_err(|_| DbError::SchemaFailure("enc_mac"))?;

            let enc_vote: String = row.get("enc_vote");
            let enc_vote = Ciphertext::try_from(enc_vote)
                .map_err(|_| DbError::SchemaFailure("enc_vote"))?;

            let sender_id = row.get("signed_by");

            let signature: String = row.get("signature");
            let signature = base64::decode(signature)
                .map_err(|_| DbError::SchemaFailure("signature"))?;

            let inner = TrusteeMessage::EcCommit { voter_id, enc_mac, enc_vote };

            result.push(SignedMessage {
                inner,
                signature,
                sender_id,
            });
        }

        Ok(result)
    }

    pub async fn get_all_ec_pet_commits(&self, session: &Uuid) -> Result<HashMap<Uuid, TrusteeMessage>, DbError> {
        let rows = self.client.query("
        SELECT trustee, voter_id, vote_commit_1, vote_commit_2, mac_commit_1, mac_commit_2, signature
        FROM wbb_pet_commits
        WHERE session=$1;", &[session]).await?;

        let mut voter_ids = HashMap::new();
        let mut vote_commits = HashMap::new();
        let mut mac_commits = HashMap::new();
        let mut signatures = HashMap::new();

        for row in rows {
            let trustee: Uuid = row.get("trustee");

            let voter_id: String = row.get("voter_id");
            let voter_id = VoterId::from(voter_id);

            let mac_commit_1: String = row.get("mac_commit_1");
            let mac_commit_1 = Commitment::try_from(mac_commit_1)
                .map_err(|_| DbError::SchemaFailure("mac_commit_1"))?;

            let mac_commit_2: String = row.get("mac_commit_2");
            let mac_commit_2 = Commitment::try_from(mac_commit_2)
                .map_err(|_| DbError::SchemaFailure("mac_commit_2"))?;

            let vote_commit_1: String = row.get("vote_commit_1");
            let vote_commit_1 = Commitment::try_from(vote_commit_1)
                .map_err(|_| DbError::SchemaFailure("vote_commit_1"))?;

            let vote_commit_2: String = row.get("vote_commit_2");
            let vote_commit_2 = Commitment::try_from(vote_commit_2)
                .map_err(|_| DbError::SchemaFailure("vote_commit_2"))?;

            let signature: String = row.get("signature");
            let signature = base64::decode(signature)
                .map_err(|_| DbError::SchemaFailure("signature"))?;

            voter_ids.entry(trustee)
                .or_insert(Vec::new())
                .push(voter_id);

            vote_commits.entry(trustee)
                .or_insert(Vec::new())
                .push((vote_commit_1, vote_commit_2));

            mac_commits.entry(trustee)
                .or_insert(Vec::new())
                .push((mac_commit_1, mac_commit_2));

            signatures.entry(trustee)
                .or_insert(Vec::new())
                .push(signature);
        }

        let mut messages = HashMap::new();

        // Collect trustees from hashmap
        let mut trustees = Vec::new();
        for trustee in voter_ids.keys() {
            trustees.push(trustee.clone());
        }

        for trustee in trustees {
            let msg = TrusteeMessage::EcPetCommit {
                voter_ids: voter_ids.remove(&trustee).unwrap(),
                vote_commits: vote_commits.remove(&trustee).unwrap(),
                mac_commits: mac_commits.remove(&trustee).unwrap(),
                signatures: signatures.remove(&trustee).unwrap(),
            };

            messages.insert(trustee, msg);
        }

        Ok(messages)

    }

    pub async fn find_ec_commit(&self, session: &Uuid, voter: String) -> Result<bool, DbError> {
        let row = self.client.query_one("
            SELECT EXISTS(SELECT 1 FROM wbb_commits WHERE session=$1 AND voter_id=$2);
        ", &[session, &voter]).await?;

        Ok(row.get(0))
    }

    async fn reset(&self) -> Result<(), DbError> {
        self.client.execute("
            DROP TABLE IF EXISTS
                trustees, sessions, parameters, parameter_signatures, keygen_commitments,
                wbb_idents, wbb_commits, wbb_votes, wbb_votes_mix, wbb_votes_mix_proofs,
                wbb_votes_decrypt, wbb_failed_votes
            CASCADE;
        ", &[]).await?;

        Ok(())
    }
}
