use std::path::{Path, PathBuf};

use axum::{body::Body, extract::Request};
use color_eyre::eyre::{Result, eyre};
use http_body_util::BodyExt;
use hyper::{Method, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

use crate::server::{
    ServerResult,
    message::{CryptData, MsgData, UnlockData},
};

/// Minivault client with Unix socket.
pub struct MVClient {
    socket: PathBuf,
    pub machine_readable: bool,
}

impl MVClient {
    /// Create a new minivault client against a UNIX socket.
    pub fn new<P: AsRef<Path>>(socket: P) -> MVClient {
        let s = socket.as_ref().to_path_buf();
        MVClient {
            socket: s,
            machine_readable: false,
        }
    }

    /// Make an HTTP request against the socket.
    async fn make_request(
        &self,
        method: Method,
        uri: String,
        body: Option<MsgData>,
    ) -> Result<ServerResult> {
        let stream = TokioIo::new(UnixStream::connect(&self.socket).await?);
        match hyper::client::conn::http1::handshake(stream).await {
            Ok((mut sender, conn)) => {
                tokio::task::spawn(async move {
                    if let Err(e) = conn.await {
                        eprintln!("connection failed: {e:#}");
                    }
                });
                let req_builder = Request::builder()
                    .method(method)
                    .uri(format!("http://minivault{}", uri))
                    .header("Content-Type", "application/json");
                let response = if body.is_some() {
                    sender
                        .send_request(req_builder.body(Body::from(body.unwrap().to_string()))?)
                        .await?
                } else {
                    sender
                        .send_request(req_builder.body(Body::empty())?)
                        .await?
                };
                if response.status() != StatusCode::OK {
                    return Err(eyre!("failed: {}", response.status().as_str()));
                }
                let body = response.collect().await?.to_bytes();
                let body: ServerResult = serde_json::from_slice(&body)?;
                Ok(body)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Unlock minivault with a username and password.
    pub async fn unlock(&self, username: String, password: String) -> Result<()> {
        match self
            .make_request(
                Method::POST,
                "/unlock".to_string(),
                Some(MsgData::Unlock(UnlockData { username, password })),
            )
            .await
        {
            Ok(s) => {
                if s.is_success() {
                    return Ok(());
                }
                Err(eyre!("unable to unlock minivault"))
            }
            Err(e) => Err(e),
        }
    }

    /// Lock minivault.
    pub async fn lock(&self) -> Result<()> {
        match self
            .make_request(Method::GET, "/lock".to_string(), None)
            .await
        {
            Ok(s) => {
                if s.is_success() {
                    return Ok(());
                }
                Err(eyre!("unable to lock minivault"))
            }
            Err(e) => Err(e),
        }
    }

    /// Decrypt a minivault string.
    #[inline]
    pub async fn decrypt(&self, data: String) -> Result<()> {
        match self
            .make_request(
                Method::POST,
                "/decrypt".to_string(),
                Some(MsgData::Decrypt(CryptData { data })),
            )
            .await
        {
            Ok(s) => {
                if s.is_success() {
                    if !self.machine_readable {
                        println!("decrypted: {}", s.msg);
                    } else {
                        println!("{}", s.msg);
                    }
                    return Ok(());
                }
                Err(eyre!(s.msg))
            }
            Err(e) => Err(e),
        }
    }

    /// Encrypt base64 data with minivault.
    #[inline]
    pub async fn encrypt(&self, data: String) -> Result<()> {
        match self
            .make_request(
                Method::POST,
                "/encrypt".to_string(),
                Some(MsgData::Encrypt(CryptData { data })),
            )
            .await
        {
            Ok(s) => {
                if s.is_success() {
                    if !self.machine_readable {
                        println!("encrypted: {}", s.msg);
                    } else {
                        println!("{}", s.msg);
                    }
                    return Ok(());
                }
                Err(eyre!(s.msg))
            }
            Err(e) => Err(e),
        }
    }
}
