use std::{
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, connect_info},
    routing::{get, post},
    serve::IncomingStream,
};
use color_eyre::eyre::Result;
use serde::{Deserialize, Serialize};
use tokio::{
    net::{UnixListener, unix::UCred},
    sync::RwLock,
};

use crate::vault::Vault;
use message::MsgData;

pub mod message;

#[derive(Serialize, Deserialize, Debug)]
pub struct ServerResult {
    status: String,
    pub msg: String,
}

impl ServerResult {
    fn success(msg: &str) -> ServerResult {
        ServerResult {
            status: "success".to_string(),
            msg: msg.to_string(),
        }
    }

    fn fail(msg: &str) -> ServerResult {
        ServerResult {
            status: "fail".to_string(),
            msg: msg.to_string(),
        }
    }

    pub fn is_success(&self) -> bool {
        self.status == "success"
    }
}

static VAULT: OnceLock<RwLock<Vault>> = OnceLock::new();
fn vault_data() -> &'static RwLock<Vault> {
    VAULT.get().unwrap()
}

/// Run server on a UNIX socket.
pub async fn start_server(socket: &PathBuf, data_file: &PathBuf) -> Result<()> {
    // setup vault
    let v = Vault::from(data_file)?;
    VAULT.set(RwLock::new(v)).unwrap();
    // setup unix socket
    let listener = UnixListener::bind(socket)?;
    // define paths
    let app = Router::new()
        .route("/unlock", post(handle_unlock))
        .route("/lock", get(handle_lock))
        .route("/encrypt", post(handle_encrypt))
        .route("/decrypt", post(handle_decrypt))
        .layer(DefaultBodyLimit::max(10000000000)) // 10 GB
        .into_make_service_with_connect_info::<UdsConnectInfo>();
    axum::serve(listener, app).await?;
    Ok(())
}

/* BEGIN HANDLERS */
async fn handle_unlock(
    ConnectInfo(_): ConnectInfo<UdsConnectInfo>,
    Json(payload): Json<MsgData>,
) -> Json<ServerResult> {
    if let MsgData::Unlock(data) = payload {
        if cfg!(debug_assertions) {
            println!("received: {:?}", data);
        }
        let mut vault = vault_data().write().await;
        if vault.unlock(data.username, data.password).is_ok() {
            return Json(ServerResult::success("unlocked"));
        }
        return Json(ServerResult::fail("failed to unlock vault"));
    }
    Json(ServerResult::fail("invalid data"))
}

async fn handle_lock(ConnectInfo(_): ConnectInfo<UdsConnectInfo>) -> Json<ServerResult> {
    if cfg!(debug_assertions) {
        println!("locking..");
    }
    let mut vault = vault_data().write().await;
    vault.lock();
    Json(ServerResult::success("locked"))
}

async fn handle_encrypt(
    ConnectInfo(_): ConnectInfo<UdsConnectInfo>,
    Json(payload): Json<MsgData>,
) -> Json<ServerResult> {
    if let MsgData::Encrypt(ref data) = payload {
        if cfg!(debug_assertions) {
            println!("encrypting {:?}..", payload);
        }
        let vault = vault_data().read().await;
        if let Ok(encrypted) = vault.encrypt_from_base64(&data.data) {
            return Json(ServerResult::success(&encrypted));
        }
        if !vault.is_unlocked() {
            return Json(ServerResult::fail("vault is locked"));
        }
    }
    Json(ServerResult::fail("invalid data"))
}

async fn handle_decrypt(
    ConnectInfo(_): ConnectInfo<UdsConnectInfo>,
    Json(payload): Json<MsgData>,
) -> Json<ServerResult> {
    if let MsgData::Decrypt(ref data) = payload {
        if cfg!(debug_assertions) {
            println!("decrypting {:?}..", payload);
        }
        let vault = vault_data().read().await;
        if let Ok(decrypted) = vault.decrypt_to_base64(&data.data) {
            return Json(ServerResult::success(&decrypted));
        }
        if !vault.is_unlocked() {
            return Json(ServerResult::fail("vault is locked"));
        }
    }
    Json(ServerResult::fail("invalid data"))
}
/* END HANDLERS */

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct UdsConnectInfo {
    peer_addr: Arc<tokio::net::unix::SocketAddr>,
    peer_cred: UCred,
}

impl connect_info::Connected<IncomingStream<'_, UnixListener>> for UdsConnectInfo {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        let peer_addr = stream.io().peer_addr().unwrap();
        let peer_cred = stream.io().peer_cred().unwrap();

        Self {
            peer_addr: Arc::new(peer_addr),
            peer_cred,
        }
    }
}
