use std::convert::TryInto;
use std::error::Error;
use std::fmt::{Display, Formatter};

use cryptid::{AsBase64, Scalar};
use cryptid::elgamal::{PublicKey, Ciphertext};
use cryptid::threshold::KeygenCommitment;
use tokio_postgres::Client;
use uuid::Uuid;

use common::APP_NAME;
use common::commit::Commitment;
use common::config::PapervoteConfig;
use common::sign::{SignedMessage, SigningPubKey};
use common::net::{TrusteeMessage, TrusteeInfo};
use common::vote::VoterId;

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
                pubkey_sig      TEXT NOT NULL UNIQUE,
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

    pub async fn insert_pubkey_sig(&self, session: &Uuid, trustee: &Uuid, pubkey: &PublicKey, signature: &[u8]) -> Result<(), DbError> {
        // For conflicts, don't worry because we only care about the signatures
        self.client.execute("
            INSERT INTO parameters(session, pubkey)
            VALUES ($1, $2)
            ON CONFLICT DO NOTHING
        ", &[&session, &pubkey.as_base64()]).await?;

        let result = self.client.execute("
            INSERT INTO parameter_signatures(session, trustee, pubkey_sig)
            VALUES($1, $2, $3);
        ", &[
            &session,
            &trustee,
            &base64::encode(signature)
        ]).await?;

        if result > 0 {
            Ok(())
        } else {
            Err(DbError::InsertAlreadyExists)
        }
    }

    pub async fn insert_ident(&self, session: &Uuid, voter_id: VoterId, c_a: &Commitment, c_b: &Commitment) -> Result<(), DbError> {
        let result = self.client.execute("
            INSERT INTO wbb_idents(session, voter_id, c_a, c_b)
            VALUES ($1, $2, $3, $4);
        ", &[session, &voter_id.to_string(), &c_a.as_base64(), &c_b.as_base64()]).await?;

        if result > 0 {
            Ok(())
        } else {
            Err(DbError::InsertAlreadyExists)
        }
    }

    pub async fn insert_ec_commit(&self, session: &Uuid, voter_id: VoterId, enc_mac: &Ciphertext, enc_vote: &Ciphertext, signed_by: &Uuid, signature: &[u8]) -> Result<(), DbError> {
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
        let pubkey: PublicKey = PublicKey::try_from_base64(pubkey.as_str()).map_err(|_| DbError::SchemaFailure("pubkey"))?;

        let rows = self.client.query("
            SELECT trustee, pubkey_sig
            FROM parameter_signatures
            WHERE session=$1;
        ", &[&session]).await?;

        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let sender_id: Uuid = row.get("trustee");
            let signature: String = row.get("pubkey_sig");
            let signature: Vec<u8> = base64::decode(&signature).map_err(|_| DbError::SchemaFailure("signature"))?;
            let inner = TrusteeMessage::KeygenSign { pubkey };

            result.push(SignedMessage {
                inner,
                signature,
                sender_id,
            });
        }

        Ok(result)
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
                wbb_idents, wbb_commits, wbb_votes
            CASCADE;
        ", &[]).await?;

        Ok(())
    }
}