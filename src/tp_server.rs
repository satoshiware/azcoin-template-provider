//! SV2 Template Provider (**0.2.0** stable): Noise, `SetupConnection`, Template Distribution, live
//! roll-forward, and `SubmitSolution` → full block → [`crate::rpc::RpcClient::submit_block`].
//!
//! # Role in the mining path
//!
//! - After Noise NX: common-message [`SetupConnection`] for Template Distribution (protocol version 2).
//! - Pool sends [`CoinbaseOutputConstraints`]; we reply with [`NewTemplate`] then [`SetNewPrevHash`]
//!   from the latest [`AzcoinTemplate`].
//! - Ongoing template updates arrive via `broadcast` (see [`crate::poller`]); a **dedicated writer task**
//!   with its own [`codec_sv2::State`] sends `NewTemplate`/`SetNewPrevHash` without blocking on the
//!   **read loop** (which uses a clone of transport state). This split fixed writer starvation where
//!   the pool mined stale work.
//! - Inbound [`SubmitSolution`] (`msg_type` **118**) is decoded; `block_bytes_from_submit_solution`
//!   builds consensus-serialized bytes using the **template-id cache** so the solved block matches the
//!   GBT snapshot for that template, not only the newest poll.
//!
//! # Coinbase / consensus details in `NewTemplate`
//!
//! - [`encode_bip34_height_prefix`] — BIP34 height in `coinbase_prefix`.
//! - When `default_witness_commitment` is present, a zero-value witness-commitment [`TxOut`] is included
//!   in the placeholder coinbase outputs.
//!
//! [`CoinbaseOutputConstraints`]: template_distribution_sv2::CoinbaseOutputConstraints
//! [`NewTemplate`]: template_distribution_sv2::NewTemplate
//! [`SetNewPrevHash`]: template_distribution_sv2::SetNewPrevHash
//! [`SubmitSolution`]: template_distribution_sv2::SubmitSolution
//! [`SetupConnection`]: common_messages_sv2::SetupConnection
//! [`AzcoinTemplate`]: crate::template::AzcoinTemplate
//! [`TxOut`]: bitcoin::blockdata::transaction::TxOut

use std::collections::HashMap;
use std::convert::TryInto;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use binary_sv2::{from_bytes, GetSize, Seq0255, Seq064K, Serialize, Str0255, B016M, B064K, U256};
use bitcoin::blockdata::block::{Block, Header as BlockHeader, Version};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::pow::CompactTarget;
use bitcoin::{Amount, BlockHash, ScriptBuf, Transaction, TxMerkleNode, TxOut};
use codec_sv2::{Error as CodecError, NoiseEncoder, StandardNoiseDecoder};
use common_messages_sv2::{
    Protocol, SetupConnection, SetupConnectionError, SetupConnectionSuccess,
    MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
    MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
};
use framing_sv2::framing::{Frame, Sv2Frame};
use framing_sv2::header::Header;
use noise_sv2::Responder;
use std::sync::Arc;
use template_distribution_sv2::{
    CoinbaseOutputConstraints, NewTemplate, RequestTransactionData, RequestTransactionDataError,
    RequestTransactionDataSuccess, SetNewPrevHash, SubmitSolution,
    MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS, MESSAGE_TYPE_NEW_TEMPLATE,
    MESSAGE_TYPE_REQUEST_TRANSACTION_DATA, MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR,
    MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS, MESSAGE_TYPE_SET_NEW_PREV_HASH,
    MESSAGE_TYPE_SUBMIT_SOLUTION,
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, watch};
use tracing::{debug, error, info, trace, warn};

use crate::rpc::RpcClient;
use crate::template::{AzcoinTemplate, TemplateSnapshot, TemplateUpdatePayload};

/// Certificate validity period used when constructing the Noise responder.
const CERT_VALIDITY: Duration = Duration::from_secs(86400);

/// Upstream protocol version we negotiate (SV2).
const SUPPORTED_MIN_VERSION: u16 = 2;
const SUPPORTED_MAX_VERSION: u16 = 2;

/// Common-message framing: `SetupConnection` / `SetupConnectionSuccess` / `SetupConnectionError`
/// use `extension_type == 0` (subprotocol is carried in the payload's `protocol` field).
const COMMON_MSG_EXTENSION_TYPE: u16 = 0;

/// Recent GBT snapshots keyed by SV2 `template_id`, for `SubmitSolution` assembly and
/// `RequestTransactionData` responses after newer templates were already pushed on this session.
const TEMPLATE_ID_CACHE_CAP: usize = 32;

type TemplateIdCache = Arc<std::sync::Mutex<HashMap<u64, TemplateSnapshot>>>;

/// Per-session canonical form of the latest decoded [`CoinbaseOutputConstraints`].
///
/// Only the two protocol-defined values are persisted. Defaults (all zero) mean "no
/// additional output space / sigops reserved by the pool" — the conservative case before
/// the first `CoinbaseOutputConstraints` has been received on this session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SessionConstraints {
    coinbase_output_max_additional_size: u32,
    coinbase_output_max_additional_sigops: u16,
}

impl SessionConstraints {
    fn from_sv2(c: &CoinbaseOutputConstraints) -> Self {
        Self {
            coinbase_output_max_additional_size: c.coinbase_output_max_additional_size,
            coinbase_output_max_additional_sigops: c.coinbase_output_max_additional_sigops,
        }
    }
}

/// Shared per-session storage for the latest `CoinbaseOutputConstraints`.
type SessionConstraintsState = Arc<std::sync::Mutex<SessionConstraints>>;

enum SessionWriteCommand {
    RequestTransactionDataSuccess(RequestTransactionDataSuccess<'static>),
    RequestTransactionDataError(RequestTransactionDataError<'static>),
}

fn store_session_constraints(state: &SessionConstraintsState, next: SessionConstraints) {
    let mut g = state.lock().expect("session constraints lock");
    *g = next;
}

fn load_session_constraints(state: &SessionConstraintsState) -> SessionConstraints {
    *state.lock().expect("session constraints lock")
}

/// Size in bytes of the TP-side fixed coinbase outputs for this template, matching the
/// construction used in [`send_template_pair`] (zero-value witness-commitment `TxOut` when
/// `default_witness_commitment` is set, otherwise empty).
fn fixed_coinbase_outputs_bytes_len(tmpl: &AzcoinTemplate) -> Result<usize> {
    if let Some(dwc) = tmpl.default_witness_commitment.as_deref() {
        let script_pubkey = ScriptBuf::from_bytes(
            hex::decode(dwc.trim()).context("hex-decode default_witness_commitment")?,
        );
        let coinbase_tx_out = TxOut {
            value: Amount::from_sat(0),
            script_pubkey,
        };
        Ok(serialize(&coinbase_tx_out).len())
    } else {
        Ok(0)
    }
}

/// Conservative upper bound on serialized block size (non-witness) when assembling a block
/// from `tmpl`'s non-coinbase transactions plus a coinbase that reserves the full
/// pool-requested additional coinbase-output bytes and a maximally-sized 100-byte coinbase
/// script field.
fn estimate_block_size_bytes(
    tmpl: &AzcoinTemplate,
    constraints: &SessionConstraints,
    fixed_coinbase_outputs_len: usize,
) -> u64 {
    const HEADER_BYTES: u64 = 80;
    const TX_COUNT_VARINT_MAX: u64 = 9;
    const OUTPUT_COUNT_VARINT_MAX: u64 = 9;
    const COINBASE_SCRIPT_MAX: u64 = 100;
    const COINBASE_VERSION: u64 = 4;
    const COINBASE_INPUT_COUNT_VARINT: u64 = 1;
    const COINBASE_PREV_OUT: u64 = 32 + 4;
    const COINBASE_INPUT_SCRIPT_LEN_VARINT: u64 = 1;
    const COINBASE_SEQUENCE: u64 = 4;
    const COINBASE_LOCKTIME: u64 = 4;

    let mut total: u64 = 0;
    total = total.saturating_add(HEADER_BYTES);
    total = total.saturating_add(TX_COUNT_VARINT_MAX);

    for tx in &tmpl.transactions {
        let hex_len = tx.data.trim().len() as u64;
        total = total.saturating_add(hex_len / 2);
    }

    total = total.saturating_add(COINBASE_VERSION);
    total = total.saturating_add(COINBASE_INPUT_COUNT_VARINT);
    total = total.saturating_add(COINBASE_PREV_OUT);
    total = total.saturating_add(COINBASE_INPUT_SCRIPT_LEN_VARINT);
    total = total.saturating_add(COINBASE_SCRIPT_MAX);
    total = total.saturating_add(COINBASE_SEQUENCE);
    total = total.saturating_add(OUTPUT_COUNT_VARINT_MAX);
    total = total.saturating_add(fixed_coinbase_outputs_len as u64);
    total = total.saturating_add(constraints.coinbase_output_max_additional_size as u64);
    total = total.saturating_add(COINBASE_LOCKTIME);

    total
}

/// Conservative estimate of total block sigops: sum of non-coinbase tx sigops plus the
/// pool-requested additional coinbase-output sigops. TP-side fixed coinbase outputs
/// currently contribute zero (witness-commitment is `OP_RETURN`-style and carries no
/// countable sigops).
fn estimate_block_sigops(tmpl: &AzcoinTemplate, constraints: &SessionConstraints) -> u64 {
    let tx_sigops: u64 = tmpl.transactions.iter().map(|t| t.sigops).sum();
    tx_sigops.saturating_add(constraints.coinbase_output_max_additional_sigops as u64)
}

/// Conservative validation gate: returns a human-readable reason when a template cannot be
/// safely sent under the persisted per-session constraints. Honors `size_limit` / `sigop_limit`
/// only when non-zero (GBT may omit them on AZCOIN).
fn validate_template_under_constraints(
    tmpl: &AzcoinTemplate,
    constraints: &SessionConstraints,
) -> std::result::Result<(), String> {
    let fixed_out_len = fixed_coinbase_outputs_bytes_len(tmpl)
        .map_err(|e| format!("failed to compute fixed coinbase outputs: {e:#}"))?;

    let est_size = estimate_block_size_bytes(tmpl, constraints, fixed_out_len);
    let est_sigops = estimate_block_sigops(tmpl, constraints);

    if tmpl.size_limit != 0 && est_size > tmpl.size_limit {
        return Err(format!(
            "estimated_block_size={} exceeds size_limit={} (tx_count={}, fixed_coinbase_outputs_len={}, max_additional_size={}, coinbase_script_max=100)",
            est_size,
            tmpl.size_limit,
            tmpl.transactions.len(),
            fixed_out_len,
            constraints.coinbase_output_max_additional_size,
        ));
    }

    if tmpl.sigop_limit != 0 && est_sigops > tmpl.sigop_limit {
        return Err(format!(
            "estimated_block_sigops={} exceeds sigop_limit={} (tx_count={}, max_additional_sigops={})",
            est_sigops,
            tmpl.sigop_limit,
            tmpl.transactions.len(),
            constraints.coinbase_output_max_additional_sigops,
        ));
    }

    Ok(())
}

fn template_id_for_cache(snapshot: &TemplateSnapshot) -> u64 {
    snapshot.template_id
}

fn insert_template_id_cache(cache: &TemplateIdCache, snapshot: &TemplateSnapshot) {
    let tid = template_id_for_cache(snapshot);
    let mut m = cache.lock().expect("template_id cache lock");
    m.insert(tid, snapshot.clone());
    while m.len() > TEMPLATE_ID_CACHE_CAP {
        if let Some(k) = m.keys().min().copied() {
            m.remove(&k);
        } else {
            break;
        }
    }
    let len = m.len();
    drop(m);
    debug!(
        template_id = tid,
        cache_len = len,
        height = snapshot.template.height,
        "template_id cache: inserted snapshot"
    );
}

/// Parse hex-encoded authority keys and start the Noise-authenticated TCP
/// listener.  Each accepted connection performs a full Noise NX handshake
/// before handling `SetupConnection`.
pub async fn run(
    listen_addr: &str,
    authority_public_key_hex: &str,
    authority_secret_key_hex: &str,
    template_rx: watch::Receiver<Option<TemplateSnapshot>>,
    template_push_tx: broadcast::Sender<TemplateUpdatePayload>,
    rpc: Arc<RpcClient>,
) -> Result<()> {
    let pub_key = decode_key(authority_public_key_hex, "authority_public_key")?;
    let sec_key = decode_key(authority_secret_key_hex, "authority_secret_key")?;
    let authority_public_key_for_pool = hex::encode(pub_key);

    Responder::from_authority_kp(&pub_key, &sec_key, CERT_VALIDITY)
        .map_err(|e| anyhow!("authority keypair is invalid: {:?}", e))?;

    let listener = TcpListener::bind(listen_addr).await?;
    let local_addr = listener.local_addr()?;

    info!(address = %local_addr, "SV2 Template Provider listening (Noise-authenticated)");
    info!(
        public_key = %authority_public_key_for_pool,
        pool_config_path = "[template_provider_type.Sv2Tp].public_key",
        encoding = "hex-encoded 32-byte secp256k1 x-only public key",
        "pool_sv2 authority public key"
    );

    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                debug!(peer = %peer, "Incoming TCP connection");
                let pk = pub_key;
                let sk = sec_key;
                let rx = template_rx.clone();
                let push = template_push_tx.clone();
                let rpc_c = rpc.clone();
                tokio::spawn(async move {
                    match handle_connection(stream, peer, &pk, &sk, rx, push, rpc_c).await {
                        Ok(()) => {}
                        Err(e) => warn!(
                            peer = %peer,
                            event = "pool_disconnected",
                            reason = "session_error",
                            "SV2 session ended: {:#}",
                            e
                        ),
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept TCP connection: {}", e);
            }
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    authority_pub: &[u8; 32],
    authority_sec: &[u8; 32],
    mut template_rx: watch::Receiver<Option<TemplateSnapshot>>,
    template_push_tx: broadcast::Sender<TemplateUpdatePayload>,
    rpc: Arc<RpcClient>,
) -> Result<()> {
    let template_cache: TemplateIdCache = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let session_constraints: SessionConstraintsState =
        Arc::new(std::sync::Mutex::new(SessionConstraints::default()));

    // ---- Noise NX handshake (responder side) --------------------------------

    trace!(peer = %peer, "Noise handshake: creating responder");

    let mut responder = Responder::from_authority_kp(authority_pub, authority_sec, CERT_VALIDITY)
        .map_err(|e| anyhow!("failed to create Noise responder: {:?}", e))?;

    trace!(peer = %peer, "Noise handshake: waiting for initiator ephemeral key");
    let mut initiator_ephemeral = [0u8; noise_sv2::ELLSWIFT_ENCODING_SIZE];
    stream
        .read_exact(&mut initiator_ephemeral)
        .await
        .context("failed to read initiator ephemeral key")?;

    trace!(peer = %peer, "Noise handshake: computing response");
    let (response, noise_codec) = responder
        .step_1(initiator_ephemeral)
        .map_err(|e| anyhow!("Noise handshake step_1 failed: {:?}", e))?;

    stream
        .write_all(&response)
        .await
        .context("failed to send Noise response")?;
    stream.flush().await?;

    trace!(peer = %peer, "Noise handshake completed — encrypted transport established");

    let mut transport_state = codec_sv2::State::with_transport_mode(noise_codec);

    // ---- First encrypted SV2 frame: SetupConnection -------------------------

    let mut decoder = StandardNoiseDecoder::<SetupConnection>::new();

    trace!(peer = %peer, "SV2 application: waiting for first encrypted frame");
    let (header, mut payload_bytes, cipher_len) =
        read_encrypted_sv2_frame(&mut stream, &mut decoder, &mut transport_state, peer).await?;

    trace!(
        peer = %peer,
        cipher_bytes = cipher_len,
        msg_type = header.msg_type(),
        extension_type = header.ext_type(),
        channel_msg = header.channel_msg(),
        payload_len = payload_bytes.len(),
        "Raw frame: first post-Noise ciphertext assembled and decrypted to SV2 header + payload"
    );

    let reply_extension = header.ext_type_without_channel_msg();

    if header.msg_type() != MESSAGE_TYPE_SETUP_CONNECTION {
        warn!(
            peer = %peer,
            expected = MESSAGE_TYPE_SETUP_CONNECTION,
            got = header.msg_type(),
            "Frame-level reject: msg_type is not SetupConnection"
        );
        send_setup_connection_error(
            &mut stream,
            &mut transport_state,
            reply_extension,
            "unsupported-protocol",
            0,
        )
        .await?;
        return drain_encrypted_frames(
            &mut stream,
            &mut decoder,
            &mut transport_state,
            peer,
            rpc.clone(),
            template_rx.clone(),
            template_cache.clone(),
        )
        .await;
    }

    if header.channel_msg() {
        warn!(peer = %peer, "Frame-level reject: common SetupConnection must have channel_msg=false");
        send_setup_connection_error(
            &mut stream,
            &mut transport_state,
            reply_extension,
            "unsupported-protocol",
            0,
        )
        .await?;
        return drain_encrypted_frames(
            &mut stream,
            &mut decoder,
            &mut transport_state,
            peer,
            rpc.clone(),
            template_rx.clone(),
            template_cache.clone(),
        )
        .await;
    }

    if header.ext_type() != COMMON_MSG_EXTENSION_TYPE {
        warn!(
            peer = %peer,
            got = header.ext_type(),
            expected = COMMON_MSG_EXTENSION_TYPE,
            "Frame-level reject: SetupConnection must use common-message framing (extension_type=0)"
        );
        send_setup_connection_error(
            &mut stream,
            &mut transport_state,
            reply_extension,
            "unsupported-protocol",
            0,
        )
        .await?;
        return drain_encrypted_frames(
            &mut stream,
            &mut decoder,
            &mut transport_state,
            peer,
            rpc.clone(),
            template_rx.clone(),
            template_cache.clone(),
        )
        .await;
    }

    debug!(
        peer = %peer,
        "Frame-level validation passed (SetupConnection, extension_type=0, channel_msg=false)"
    );

    let setup: SetupConnection<'_> = match from_bytes(&mut payload_bytes) {
        Ok(m) => m,
        Err(e) => {
            error!(peer = %peer, "Decode error: SetupConnection payload: {:?}", e);
            send_setup_connection_error(
                &mut stream,
                &mut transport_state,
                COMMON_MSG_EXTENSION_TYPE,
                "unsupported-protocol",
                0,
            )
            .await?;
            return drain_encrypted_frames(
                &mut stream,
                &mut decoder,
                &mut transport_state,
                peer,
                rpc.clone(),
                template_rx.clone(),
                template_cache.clone(),
            )
            .await;
        }
    };

    debug!(peer = %peer, setup = %setup, "Decoded SetupConnection body");

    if setup.protocol != Protocol::TemplateDistributionProtocol {
        warn!(
            peer = %peer,
            protocol = ?setup.protocol,
            "Payload-level reject: SetupConnection.protocol is not Template Distribution (expected for this TP)"
        );
        send_setup_connection_error(
            &mut stream,
            &mut transport_state,
            COMMON_MSG_EXTENSION_TYPE,
            "unsupported-protocol",
            0,
        )
        .await?;
        return drain_encrypted_frames(
            &mut stream,
            &mut decoder,
            &mut transport_state,
            peer,
            rpc.clone(),
            template_rx.clone(),
            template_cache.clone(),
        )
        .await;
    }

    debug!(
        peer = %peer,
        "Payload-level validation passed (SetupConnection.protocol = Template Distribution)"
    );

    let used_version = match setup.get_version(SUPPORTED_MIN_VERSION, SUPPORTED_MAX_VERSION) {
        Some(v) => v,
        None => {
            warn!(
                peer = %peer,
                min_version = setup.min_version,
                max_version = setup.max_version,
                "Rejected SetupConnection: protocol version mismatch"
            );
            send_setup_connection_error(
                &mut stream,
                &mut transport_state,
                COMMON_MSG_EXTENSION_TYPE,
                "protocol-version-mismatch",
                0,
            )
            .await?;
            return drain_encrypted_frames(
                &mut stream,
                &mut decoder,
                &mut transport_state,
                peer,
                rpc.clone(),
                template_rx.clone(),
                template_cache.clone(),
            )
            .await;
        }
    };

    let success = SetupConnectionSuccess {
        used_version,
        flags: 0,
    };

    let reply = Sv2Frame::from_message(
        success,
        MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
        COMMON_MSG_EXTENSION_TYPE,
        false,
    )
    .ok_or_else(|| anyhow!("SetupConnectionSuccess frame construction failed"))?;

    let mut encoder = NoiseEncoder::<SetupConnectionSuccess>::new();
    let encrypted = encoder
        .encode(Frame::Sv2(reply), &mut transport_state)
        .map_err(|e| anyhow!("Noise encode SetupConnectionSuccess: {:?}", e))?;

    stream
        .write_all(encrypted.as_ref())
        .await
        .context("failed to send SetupConnectionSuccess")?;
    stream.flush().await?;

    info!(
        peer = %peer,
        event = "pool_connected",
        negotiated_version = used_version,
        extension_type = COMMON_MSG_EXTENSION_TYPE,
        "Response sent: SetupConnectionSuccess (common-message frame; template distribution negotiated in payload)"
    );

    match run_template_distribution_init(
        &mut stream,
        &mut decoder,
        &mut transport_state,
        peer,
        &mut template_rx,
        template_cache.clone(),
        session_constraints.clone(),
    )
    .await
    {
        Ok(()) => {
            let upd_rx = template_push_tx.subscribe();
            debug!(
                peer = %peer,
                receiver_count = template_push_tx.receiver_count(),
                "SV2 live template push: subscribed Receiver for this session"
            );
            let (read_half, write_half) = stream.into_split();
            drain_encrypted_frames_with_live_updates(
                read_half,
                write_half,
                &mut decoder,
                transport_state,
                peer,
                upd_rx,
                rpc.clone(),
                template_rx.clone(),
                template_cache.clone(),
                session_constraints.clone(),
            )
            .await
        }
        Err(e) => {
            warn!(
                peer = %peer,
                "Template distribution init failed (pool may retry or disconnect): {:#}",
                e
            );
            drain_encrypted_frames(
                &mut stream,
                &mut decoder,
                &mut transport_state,
                peer,
                rpc.clone(),
                template_rx.clone(),
                template_cache.clone(),
            )
            .await
        }
    }
}

/// After `SetupConnectionSuccess`, read [`CoinbaseOutputConstraints`] (`msg_type` **0x70 / 112**)
/// and reply with [`NewTemplate`] then [`SetNewPrevHash`] from the latest polled template.
async fn run_template_distribution_init(
    stream: &mut TcpStream,
    decoder: &mut StandardNoiseDecoder<SetupConnection<'_>>,
    transport_state: &mut codec_sv2::State,
    peer: SocketAddr,
    template_rx: &mut watch::Receiver<Option<TemplateSnapshot>>,
    template_cache: TemplateIdCache,
    session_constraints: SessionConstraintsState,
) -> Result<()> {
    debug!(
        peer = %peer,
        "Waiting for first Template Distribution message after SetupConnectionSuccess"
    );

    let (header, mut payload, cipher_len) =
        read_encrypted_sv2_frame(stream, decoder, transport_state, peer).await?;

    let mt = header.msg_type();
    trace!(
        peer = %peer,
        cipher_bytes = cipher_len,
        msg_type = mt,
        extension_type = header.ext_type(),
        channel_msg = header.channel_msg(),
        payload_len = payload.len(),
        "Inbound frame (post-SetupConnection)"
    );

    anyhow::ensure!(
        header.ext_type() == COMMON_MSG_EXTENSION_TYPE && !header.channel_msg(),
        "expected first post-SetupConnection TD-init frame: extension_type=0, channel_msg=false (got ext={}, channel_msg={})",
        header.ext_type(),
        header.channel_msg()
    );

    trace!(
        peer = %peer,
        extension_type = COMMON_MSG_EXTENSION_TYPE,
        channel_msg = false,
        "Frame-level acceptance: post-SetupConnection frame (common extension, non-channel)"
    );

    anyhow::ensure!(
        mt == MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS,
        "expected first TD message CoinbaseOutputConstraints (MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS = 0x70 = 112), got {}",
        mt
    );

    trace!(
        peer = %peer,
        msg_type = mt,
        "TD dispatch by msg_type: CoinbaseOutputConstraints"
    );

    let constraints: CoinbaseOutputConstraints = from_bytes(&mut payload)
        .map_err(|e| anyhow!("decode CoinbaseOutputConstraints: {:?}", e))?;

    debug!(
        peer = %peer,
        inbound = %constraints,
        msg_type = mt,
        msg_type_decimal = mt as u16,
        msg_type_hex = "0x70",
        constant = "MESSAGE_TYPE_COINBASE_OUTPUT_CONSTRAINTS",
        "Decoded CoinbaseOutputConstraints payload"
    );

    let persisted = SessionConstraints::from_sv2(&constraints);
    store_session_constraints(&session_constraints, persisted);
    debug!(
        peer = %peer,
        coinbase_output_max_additional_size = persisted.coinbase_output_max_additional_size,
        coinbase_output_max_additional_sigops = persisted.coinbase_output_max_additional_sigops,
        "CoinbaseOutputConstraints persisted to per-session state"
    );

    let snapshot = wait_for_template(template_rx).await?;
    let tmpl = &snapshot.template;

    let current = load_session_constraints(&session_constraints);
    match validate_template_under_constraints(tmpl, &current) {
        Ok(()) => {
            send_template_pair(stream, transport_state, &snapshot, peer).await?;
            insert_template_id_cache(&template_cache, &snapshot);

            debug!(
                peer = %peer,
                template_id = snapshot.template_id,
                height = tmpl.height,
                prev_hash_rpc_hex = %tmpl.previous_block_hash,
                outbound = "NewTemplate then SetNewPrevHash",
                "Initial template + prevhash sent to pool"
            );
        }
        Err(reason) => {
            warn!(
                peer = %peer,
                height = tmpl.height,
                template_id = snapshot.template_id,
                prev_hash_rpc_hex = %tmpl.previous_block_hash,
                size_limit = tmpl.size_limit,
                sigop_limit = tmpl.sigop_limit,
                tx_count = tmpl.transactions.len(),
                coinbase_output_max_additional_size = current.coinbase_output_max_additional_size,
                coinbase_output_max_additional_sigops = current.coinbase_output_max_additional_sigops,
                reason = %reason,
                "Initial template rejected by CoinbaseOutputConstraints gate; skipping NewTemplate/SetNewPrevHash and keeping session alive"
            );
        }
    }

    Ok(())
}

async fn wait_for_template(
    rx: &mut watch::Receiver<Option<TemplateSnapshot>>,
) -> Result<TemplateSnapshot> {
    loop {
        if let Some(t) = rx.borrow().clone() {
            return Ok(t);
        }
        rx.changed()
            .await
            .map_err(|_| anyhow!("template watch channel closed before first template"))?;
    }
}

/// BIP34 push of block height, used as the start of `NewTemplate.coinbase_prefix` (SV2 placeholder coinbase).
fn encode_bip34_height_prefix(height: u64) -> Result<Vec<u8>> {
    let mut encoded_height = Vec::new();
    let mut value = u32::try_from(height)
        .map_err(|_| anyhow!("template height {} exceeds BIP34 helper range", height))?;
    while value > 0 {
        encoded_height.push((value & 0xff) as u8);
        value >>= 8;
    }
    if encoded_height
        .last()
        .map(|byte| byte & 0x80 != 0)
        .unwrap_or(false)
    {
        encoded_height.push(0x00);
    }

    let mut prefix = Vec::with_capacity(encoded_height.len() + 1);
    prefix.push(
        u8::try_from(encoded_height.len())
            .map_err(|_| anyhow!("encoded BIP34 height length does not fit in push opcode"))?,
    );
    prefix.extend_from_slice(&encoded_height);
    Ok(prefix)
}

/// Build and send `NewTemplate` then `SetNewPrevHash` for `tmpl` (ordering preserved).
async fn send_template_pair<W: AsyncWrite + Unpin>(
    stream: &mut W,
    transport_state: &mut codec_sv2::State,
    snapshot: &TemplateSnapshot,
    peer: SocketAddr,
) -> Result<()> {
    let tmpl = &snapshot.template;
    debug!(
        peer = %peer,
        template_id = snapshot.template_id,
        height = tmpl.height,
        "send_template_pair: start"
    );
    let template_id = snapshot.template_id;
    let prev =
        crate::template::prev_hash_bytes_from_rpc_hex(&tmpl.previous_block_hash).map_err(|e| {
            error!(
                peer = %peer,
                error = %e,
                error_debug = ?e,
                "send_template_pair: error building prev_hash"
            );
            e
        })?;
    let n_bits = crate::template::n_bits_from_bits_hex(&tmpl.bits).map_err(|e| {
        error!(
            peer = %peer,
            error = %e,
            error_debug = ?e,
            "send_template_pair: error parsing bits"
        );
        e
    })?;
    let target = crate::template::target_bytes_from_hex(&tmpl.target).map_err(|e| {
        error!(
            peer = %peer,
            error = %e,
            error_debug = ?e,
            "send_template_pair: error parsing target"
        );
        e
    })?;

    let merkle_flat = tmpl.sv2_merkle_path_hashes().map_err(|e| {
        error!(
            peer = %peer,
            error = %e,
            error_debug = ?e,
            "send_template_pair: error building merkle path"
        );
        e
    })?;
    let merkle_path: Seq0255<U256<'static>> = merkle_flat
        .iter()
        .map(|b| U256::from(*b))
        .collect::<Vec<_>>()
        .into();

    let coinbase_prefix_bytes = encode_bip34_height_prefix(tmpl.height)?;
    let coinbase_prefix_hex = hex::encode(&coinbase_prefix_bytes);
    let coinbase_prefix: binary_sv2::B0255<'static> = coinbase_prefix_bytes
        .try_into()
        .map_err(|e| anyhow!("B0255 coinbase_prefix: {:?}", e))?;
    let (coinbase_tx_outputs_count, coinbase_tx_outputs_bytes, witness_commitment_included) =
        if let Some(default_witness_commitment) = tmpl.default_witness_commitment.as_deref() {
            let script_pubkey = ScriptBuf::from_bytes(
                hex::decode(default_witness_commitment.trim())
                    .with_context(|| "hex-decode default_witness_commitment")?,
            );
            let coinbase_tx_out = TxOut {
                value: Amount::from_sat(0),
                script_pubkey,
            };
            (1, serialize(&coinbase_tx_out), true)
        } else {
            (0, Vec::new(), false)
        };
    let coinbase_tx_outputs: binary_sv2::B064K<'static> = coinbase_tx_outputs_bytes
        .try_into()
        .map_err(|e| anyhow!("B064K coinbase_tx_outputs: {:?}", e))?;

    debug!(
        peer = %peer,
        template_id,
        height = tmpl.height,
        witness_commitment_included,
        coinbase_tx_outputs_count,
        coinbase_prefix_hex = %coinbase_prefix_hex,
        "send_template_pair: built NewTemplate coinbase_prefix"
    );

    let new_t = NewTemplate {
        template_id,
        future_template: true,
        version: tmpl.version,
        coinbase_tx_version: 2,
        coinbase_prefix,
        coinbase_tx_input_sequence: 0xffff_ffff,
        coinbase_tx_value_remaining: tmpl.coinbase_value,
        coinbase_tx_outputs_count,
        coinbase_tx_outputs,
        coinbase_tx_locktime: 0,
        merkle_path,
    };

    trace!(
        peer = %peer,
        template_id,
        msg_type = MESSAGE_TYPE_NEW_TEMPLATE,
        "send_template_pair: calling write_td_frame for NewTemplate"
    );
    write_td_frame(
        stream,
        transport_state,
        new_t,
        MESSAGE_TYPE_NEW_TEMPLATE,
        peer,
        "NewTemplate sent",
    )
    .await
    .map_err(|e| {
        error!(
            peer = %peer,
            template_id,
            error = %e,
            error_debug = ?e,
            "send_template_pair: error during NewTemplate write_td_frame"
        );
        e
    })?;
    trace!(
        peer = %peer,
        template_id,
        "send_template_pair: NewTemplate wire phase complete"
    );

    let set_prev = SetNewPrevHash {
        template_id,
        prev_hash: U256::from(prev),
        header_timestamp: tmpl.curtime as u32,
        n_bits,
        target: U256::from(target),
    };

    trace!(
        peer = %peer,
        template_id,
        msg_type = MESSAGE_TYPE_SET_NEW_PREV_HASH,
        "send_template_pair: calling write_td_frame for SetNewPrevHash"
    );
    write_td_frame(
        stream,
        transport_state,
        set_prev,
        MESSAGE_TYPE_SET_NEW_PREV_HASH,
        peer,
        "SetNewPrevHash sent",
    )
    .await
    .map_err(|e| {
        error!(
            peer = %peer,
            template_id,
            error = %e,
            error_debug = ?e,
            "send_template_pair: error during SetNewPrevHash write_td_frame"
        );
        e
    })?;
    trace!(
        peer = %peer,
        template_id,
        "send_template_pair: SetNewPrevHash wire phase complete"
    );

    info!(
        peer = %peer,
        template_id,
        height = tmpl.height,
        previous_block_hash = %tmpl.previous_block_hash,
        coinbase_tx_outputs_placeholder_count = coinbase_tx_outputs_count,
        witness_commitment_included,
        event = "template_sent",
        "NewTemplate and SetNewPrevHash sent to pool (Template Distribution)"
    );
    Ok(())
}

async fn write_td_frame<T, W: AsyncWrite + Unpin>(
    stream: &mut W,
    transport_state: &mut codec_sv2::State,
    payload: T,
    msg_type: u8,
    peer: SocketAddr,
    log_message: &'static str,
) -> Result<()>
where
    T: Serialize + GetSize,
{
    let ext = COMMON_MSG_EXTENSION_TYPE;
    trace!(
        peer = %peer,
        msg_type,
        extension_type = ext,
        phase = "before_from_message",
        "write_td_frame: begin (encode + Noise encrypt + TCP write)"
    );
    let frame = match Sv2Frame::from_message(payload, msg_type, ext, false) {
        Some(f) => f,
        None => {
            let e = anyhow!("Sv2Frame::from_message failed ({log_message})");
            error!(
                peer = %peer,
                msg_type,
                extension_type = ext,
                error = %e,
                error_debug = ?e,
                "write_td_frame: Sv2Frame::from_message returned None"
            );
            return Err(e);
        }
    };
    let mut enc = NoiseEncoder::<T>::new();
    let bytes = match enc.encode(Frame::Sv2(frame), transport_state) {
        Ok(b) => b,
        Err(e) => {
            let err = anyhow!("Noise encode {log_message}: {:?}", e);
            error!(
                peer = %peer,
                msg_type,
                codec_error = ?e,
                error = %err,
                error_debug = ?err,
                "write_td_frame: NoiseEncoder::encode failed"
            );
            return Err(err);
        }
    };
    trace!(
        peer = %peer,
        msg_type,
        phase = "before_tcp_write",
        "write_td_frame: encoded; writing to socket"
    );
    if let Err(e) = stream.write_all(bytes.as_ref()).await {
        error!(
            peer = %peer,
            msg_type,
            error = %e,
            error_debug = ?e,
            "write_td_frame: TcpStream::write_all failed"
        );
        return Err(e.into());
    }
    if let Err(e) = stream.flush().await {
        error!(
            peer = %peer,
            msg_type,
            error = %e,
            error_debug = ?e,
            "write_td_frame: TcpStream::flush failed"
        );
        return Err(e.into());
    }
    trace!(
        peer = %peer,
        msg_type,
        extension_type = ext,
        "{}", log_message
    );
    Ok(())
}

fn build_request_transaction_data_success(
    snapshot: &TemplateSnapshot,
) -> Result<RequestTransactionDataSuccess<'static>> {
    let excess_data_bytes = match snapshot.template.default_witness_commitment.as_deref() {
        Some(value) => {
            hex::decode(value.trim()).context("hex-decode default_witness_commitment")?
        }
        None => Vec::new(),
    };
    let excess_data: B064K<'static> = excess_data_bytes
        .try_into()
        .map_err(|e| anyhow!("B064K excess_data: {:?}", e))?;

    let mut txs = Vec::with_capacity(snapshot.template.transactions.len());
    for tx in &snapshot.template.transactions {
        let raw = hex::decode(tx.data.trim()).context("hex-decode GBT transaction.data")?;
        let tx_bytes: B016M<'static> = raw
            .try_into()
            .map_err(|e| anyhow!("B016M transaction bytes: {:?}", e))?;
        txs.push(tx_bytes);
    }
    let transaction_list: Seq064K<'static, B016M<'static>> = txs.into();

    Ok(RequestTransactionDataSuccess {
        template_id: snapshot.template_id,
        excess_data,
        transaction_list,
    })
}

fn build_request_transaction_data_error(
    template_id: u64,
    error_code: &str,
) -> Result<RequestTransactionDataError<'static>> {
    let error_code: Str0255<'static> = String::from(error_code)
        .try_into()
        .map_err(|e| anyhow!("invalid RequestTransactionData error_code: {:?}", e))?;
    Ok(RequestTransactionDataError {
        template_id,
        error_code,
    })
}

fn decode_bip34_coinbase_height(script_sig: &[u8]) -> Option<u32> {
    let (push_len, prefix_len) = match *script_sig.first()? {
        0x00 => return Some(0),
        n @ 0x01..=0x4b => (n as usize, 1usize),
        0x4c => (*script_sig.get(1)? as usize, 2usize),
        0x4d => (
            u16::from_le_bytes([*script_sig.get(1)?, *script_sig.get(2)?]) as usize,
            3usize,
        ),
        0x4e => (
            u32::from_le_bytes([
                *script_sig.get(1)?,
                *script_sig.get(2)?,
                *script_sig.get(3)?,
                *script_sig.get(4)?,
            ]) as usize,
            5usize,
        ),
        _ => return None,
    };
    if push_len == 0 || push_len > 5 || script_sig.len() < prefix_len + push_len {
        return None;
    }
    let data = &script_sig[prefix_len..prefix_len + push_len];
    let negative = data.last().map(|b| b & 0x80 != 0).unwrap_or(false);
    if negative {
        return None;
    }
    let mut value = 0u64;
    for (idx, byte) in data.iter().enumerate() {
        let byte = if idx + 1 == data.len() {
            byte & 0x7f
        } else {
            *byte
        };
        value |= (byte as u64) << (8 * idx);
    }
    u32::try_from(value).ok()
}

/// Builds consensus-encoded block bytes for [`crate::rpc::RpcClient::submit_block`].
///
/// Expects `snapshot` to be the cached template snapshot for `sol_template_id`. Recomputes merkle
/// root from coinbase + GBT transactions; header fields come from the solution except merkle root
/// (derived).
fn block_bytes_from_submit_solution(
    sol_template_id: u64,
    header_version: u32,
    header_timestamp: u32,
    header_nonce: u32,
    coinbase_raw: &[u8],
    snapshot: &TemplateSnapshot,
) -> Result<Vec<u8>> {
    let snapshot_tid = snapshot.template_id;
    if sol_template_id != snapshot_tid {
        anyhow::bail!(
            "SubmitSolution.template_id {} does not match resolved snapshot template_id {}",
            sol_template_id,
            snapshot_tid
        );
    }
    let tmpl = &snapshot.template;
    let coinbase: Transaction =
        deserialize(coinbase_raw).context("deserialize SubmitSolution.coinbase_tx")?;
    debug!(
        submitted_template_id = sol_template_id,
        resolved_template_height = tmpl.height,
        resolved_previous_block_hash = %tmpl.previous_block_hash,
        header_version = header_version,
        header_timestamp = header_timestamp,
        header_nonce = header_nonce,
        bits = %tmpl.bits,
        coinbase_len = coinbase_raw.len(),
        "SubmitSolution block assembly inputs"
    );
    let first_input = coinbase.input.first();
    let first_input_script_sig = first_input
        .map(|txin| hex::encode(txin.script_sig.as_bytes()))
        .unwrap_or_default();
    let first_input_prevout = first_input
        .map(|txin| txin.previous_output.to_string())
        .unwrap_or_else(|| "missing".to_string());
    let first_input_prevout_is_null = first_input
        .map(|txin| txin.previous_output.is_null())
        .unwrap_or(false);
    let decoded_coinbase_height =
        first_input.and_then(|txin| decode_bip34_coinbase_height(txin.script_sig.as_bytes()));
    trace!(
        coinbase_txid = %coinbase.compute_txid(),
        is_coinbase = coinbase.is_coinbase(),
        first_input_prevout = %first_input_prevout,
        first_input_prevout_is_null = first_input_prevout_is_null,
        first_input_script_sig = %first_input_script_sig,
        expected_block_height = tmpl.height,
        decoded_coinbase_height = ?decoded_coinbase_height,
        "SubmitSolution coinbase diagnostics"
    );
    if decoded_coinbase_height.map(u64::from) != Some(tmpl.height) {
        warn!(
            expected_block_height = tmpl.height,
            decoded_coinbase_height = ?decoded_coinbase_height,
            "SubmitSolution coinbase height mismatch"
        );
    }
    let mut txdata = vec![coinbase];
    for tx in &tmpl.transactions {
        let raw = hex::decode(tx.data.trim()).context("hex-decode GBT transaction.data")?;
        txdata.push(deserialize(&raw).context("deserialize GBT transaction")?);
    }
    let bits_u32 = crate::template::n_bits_from_bits_hex(&tmpl.bits)?;
    let prev_inner = crate::template::prev_hash_bytes_from_rpc_hex(&tmpl.previous_block_hash)?;
    let prev_blockhash = BlockHash::from_byte_array(prev_inner);
    let version = Version::from_consensus(header_version as i32);
    let bits = CompactTarget::from_consensus(bits_u32);
    let wip_header = BlockHeader {
        version,
        prev_blockhash,
        merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
        time: header_timestamp,
        bits,
        nonce: header_nonce,
    };
    let wip = Block {
        header: wip_header,
        txdata: txdata.clone(),
    };
    let merkle_root = wip
        .compute_merkle_root()
        .ok_or_else(|| anyhow!("compute_merkle_root returned None"))?;
    let header = BlockHeader {
        version,
        prev_blockhash,
        merkle_root,
        time: header_timestamp,
        bits,
        nonce: header_nonce,
    };
    let block = Block { header, txdata };
    Ok(serialize(&block))
}

/// Decrypt path dispatch: handles Template Distribution [`SubmitSolution`] (`msg_type` 118) by
/// resolving `template_id` in the cache, assembling the block, and calling `submitblock`; other
/// message types are logged only.
#[allow(clippy::too_many_arguments)]
async fn log_and_dispatch_post_init_sv2_frame(
    peer: SocketAddr,
    h: Header,
    mut payload: Vec<u8>,
    cipher_bytes: usize,
    rpc: Arc<RpcClient>,
    template_rx: &watch::Receiver<Option<TemplateSnapshot>>,
    template_cache: TemplateIdCache,
    writer_tx: Option<&mpsc::UnboundedSender<SessionWriteCommand>>,
) {
    let msg_type = h.msg_type();
    let ext_type = h.ext_type();
    let channel_msg = h.channel_msg();
    if ext_type == COMMON_MSG_EXTENSION_TYPE
        && !channel_msg
        && msg_type == MESSAGE_TYPE_REQUEST_TRANSACTION_DATA
    {
        trace!(
            peer = %peer,
            msg_type,
            msg_type_hex = "0x73",
            extension_type = ext_type,
            channel_msg = channel_msg,
            payload_len = payload.len(),
            cipher_bytes = cipher_bytes,
            constant = "MESSAGE_TYPE_REQUEST_TRANSACTION_DATA",
            "TD RequestTransactionData frame recognized (msg_type=115)"
        );
        match from_bytes::<RequestTransactionData>(&mut payload) {
            Ok(req) => {
                let template_id = req.template_id;
                let snapshot = {
                    let m = template_cache.lock().expect("template_id cache lock");
                    m.get(&template_id).cloned()
                };
                match snapshot {
                    Some(snapshot) => {
                        let response = match build_request_transaction_data_success(&snapshot) {
                            Ok(response) => response,
                            Err(e) => {
                                warn!(
                                    peer = %peer,
                                    template_id,
                                    error = %e,
                                    error_debug = ?e,
                                    "RequestTransactionData: failed to build success response"
                                );
                                return;
                            }
                        };
                        debug!(
                            peer = %peer,
                            template_id,
                            tx_count = snapshot.template.transactions.len(),
                            excess_data_len = response.excess_data.inner_as_ref().len(),
                            "RequestTransactionData resolved template_id from cache"
                        );
                        match writer_tx {
                            Some(tx) => {
                                if let Err(e) = tx.send(
                                    SessionWriteCommand::RequestTransactionDataSuccess(response),
                                ) {
                                    warn!(
                                        peer = %peer,
                                        template_id,
                                        error = ?e,
                                        "RequestTransactionData: writer task unavailable; could not send success response"
                                    );
                                }
                            }
                            None => {
                                warn!(
                                    peer = %peer,
                                    template_id,
                                    "RequestTransactionData: no writer path available for response"
                                );
                            }
                        }
                    }
                    None => {
                        let latest_id = template_rx.borrow().as_ref().map(template_id_for_cache);
                        warn!(
                            peer = %peer,
                            requested_template_id = template_id,
                            latest_known_template_id = ?latest_id,
                            "RequestTransactionData: no cached template for template_id"
                        );
                        match (
                            writer_tx,
                            build_request_transaction_data_error(
                                template_id,
                                "template-id-not-found",
                            ),
                        ) {
                            (Some(tx), Ok(response)) => {
                                if let Err(e) = tx.send(
                                    SessionWriteCommand::RequestTransactionDataError(response),
                                ) {
                                    warn!(
                                        peer = %peer,
                                        template_id,
                                        error = ?e,
                                        "RequestTransactionData: writer task unavailable; could not send error response"
                                    );
                                }
                            }
                            (Some(_), Err(e)) => {
                                warn!(
                                    peer = %peer,
                                    template_id,
                                    error = %e,
                                    error_debug = ?e,
                                    "RequestTransactionData: failed to build error response"
                                );
                            }
                            (None, _) => {
                                warn!(
                                    peer = %peer,
                                    template_id,
                                    "RequestTransactionData: no writer path available for error response"
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                warn!(
                    peer = %peer,
                    msg_type = msg_type,
                    decode_ok = false,
                    error = ?e,
                    "RequestTransactionData decode failed"
                );
            }
        }
        return;
    }
    if ext_type == COMMON_MSG_EXTENSION_TYPE
        && !channel_msg
        && msg_type == MESSAGE_TYPE_SUBMIT_SOLUTION
    {
        trace!(
            peer = %peer,
            msg_type = msg_type,
            msg_type_hex = "0x76",
            extension_type = ext_type,
            channel_msg = channel_msg,
            payload_len = payload.len(),
            cipher_bytes = cipher_bytes,
            constant = "MESSAGE_TYPE_SUBMIT_SOLUTION",
            "TD SubmitSolution frame recognized (msg_type=118)"
        );
        match from_bytes::<SubmitSolution>(&mut payload) {
            Ok(sol) => {
                let coinbase_raw = sol.coinbase_tx.inner_as_ref().to_vec();
                let template_id = sol.template_id;
                let header_version = sol.version;
                let header_timestamp = sol.header_timestamp;
                let header_nonce = sol.header_nonce;
                info!(
                    event = "solution_received",
                    peer = %peer,
                    template_id = template_id,
                    header_version = header_version,
                    header_timestamp = header_timestamp,
                    header_nonce = header_nonce,
                    coinbase_len = coinbase_raw.len(),
                    "SubmitSolution decoded from pool"
                );
                let snapshot = {
                    let m = template_cache.lock().expect("template_id cache lock");
                    m.get(&template_id).cloned()
                };
                let snapshot = match snapshot {
                    Some(snapshot) => {
                        debug!(
                            peer = %peer,
                            submitted_template_id = template_id,
                            resolved_height = snapshot.template.height,
                            cache_hit = true,
                            "SubmitSolution resolved template_id from cache"
                        );
                        snapshot
                    }
                    None => {
                        let latest_id = template_rx.borrow().as_ref().map(|s| s.template_id);
                        warn!(
                            event = "submitblock_result",
                            peer = %peer,
                            template_id,
                            outcome = "template_cache_miss",
                            cache_miss = true,
                            latest_known_template_id = ?latest_id,
                            "Skipped submitblock — no cached template for template_id"
                        );
                        return;
                    }
                };
                let block_res = block_bytes_from_submit_solution(
                    template_id,
                    header_version,
                    header_timestamp,
                    header_nonce,
                    &coinbase_raw,
                    &snapshot,
                );
                let block_bytes = match block_res {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        warn!(
                            event = "submitblock_result",
                            peer = %peer,
                            template_id,
                            outcome = "block_assembly_failed",
                            error = %e,
                            error_debug = ?e,
                            "SubmitSolution: failed to assemble block bytes"
                        );
                        return;
                    }
                };
                let block_hash = deserialize::<Block>(&block_bytes)
                    .map(|b| b.block_hash().to_string())
                    .ok();

                info!(
                    event = "submitblock_called",
                    peer = %peer,
                    template_id,
                    block_hash = ?block_hash,
                    serialized_block_bytes = block_bytes.len(),
                    "Invoking submitblock JSON-RPC"
                );
                let block_hex = hex::encode(&block_bytes);
                match rpc.submit_block(&block_hex).await {
                    Ok(None) => {
                        info!(
                            peer = %peer,
                            event = "submitblock_result",
                            template_id,
                            outcome = "accepted",
                            accepted = true,
                            block_hash = ?block_hash,
                            "submitblock succeeded (null result — block accepted)"
                        );
                    }
                    Ok(Some(reason)) => {
                        info!(
                            peer = %peer,
                            event = "submitblock_result",
                            template_id,
                            outcome = "rejected_by_node",
                            accepted = false,
                            reject_reason = %reason,
                            block_hash = ?block_hash,
                            "submitblock returned rejection reason string"
                        );
                    }
                    Err(e) => {
                        warn!(
                            peer = %peer,
                            event = "submitblock_result",
                            template_id,
                            outcome = "rpc_transport_or_envelope_failure",
                            block_hash = ?block_hash,
                            error = %e,
                            error_debug = ?e,
                            "submitblock RPC call failed after assembly (see also azcoin_rpc_error from client)"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    peer = %peer,
                    msg_type = msg_type,
                    decode_ok = false,
                    error = ?e,
                    "SubmitSolution decode failed"
                );
            }
        }
        return;
    }

    trace!(
        peer = %peer,
        cipher_bytes = cipher_bytes,
        msg_type = msg_type,
        extension_type = ext_type,
        payload_len = payload.len(),
        "Received encrypted SV2 frame (not handled at application layer)"
    );
}

/// Post-init session: **split TCP** into read vs write halves. The read loop uses `read_transport_state`
/// (clone of Noise codec state); a spawned task owns `write_transport_state` for live `NewTemplate` /
/// `SetNewPrevHash` so encoding outbound frames never blocks decryption of inbound `SubmitSolution`.
#[allow(clippy::too_many_arguments)]
async fn drain_encrypted_frames_with_live_updates(
    mut read_half: tokio::net::tcp::OwnedReadHalf,
    write_half: tokio::net::tcp::OwnedWriteHalf,
    decoder: &mut StandardNoiseDecoder<SetupConnection<'_>>,
    transport_state: codec_sv2::State,
    peer: SocketAddr,
    mut upd_rx: broadcast::Receiver<TemplateUpdatePayload>,
    rpc: Arc<RpcClient>,
    template_rx: watch::Receiver<Option<TemplateSnapshot>>,
    template_cache: TemplateIdCache,
    session_constraints: SessionConstraintsState,
) -> Result<()> {
    let mut read_transport_state = transport_state.clone();
    let peer_w = peer;
    let tc_writer = template_cache.clone();
    let sc_writer = session_constraints.clone();
    let (write_cmd_tx, mut write_cmd_rx) = mpsc::unbounded_channel::<SessionWriteCommand>();

    tokio::spawn(async move {
        debug!(
            peer = %peer_w,
            "SV2 live template writer task started with dedicated write codec state"
        );
        let mut wh = write_half;
        let mut write_transport_state = transport_state;
        let mut write_cmd_closed = false;
        loop {
            tokio::select! {
                cmd = write_cmd_rx.recv(), if !write_cmd_closed => {
                    match cmd {
                        Some(SessionWriteCommand::RequestTransactionDataSuccess(response)) => {
                            let template_id = response.template_id;
                            if let Err(e) = write_td_frame(
                                &mut wh,
                                &mut write_transport_state,
                                response,
                                MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_SUCCESS,
                                peer_w,
                                "RequestTransactionDataSuccess sent",
                            )
                            .await
                            {
                                warn!(
                                    peer = %peer_w,
                                    template_id,
                                    error = %e,
                                    error_debug = ?e,
                                    "SV2 writer: failed to send RequestTransactionDataSuccess"
                                );
                                break;
                            }
                        }
                        Some(SessionWriteCommand::RequestTransactionDataError(response)) => {
                            let template_id = response.template_id;
                            if let Err(e) = write_td_frame(
                                &mut wh,
                                &mut write_transport_state,
                                response,
                                MESSAGE_TYPE_REQUEST_TRANSACTION_DATA_ERROR,
                                peer_w,
                                "RequestTransactionDataError sent",
                            )
                            .await
                            {
                                warn!(
                                    peer = %peer_w,
                                    template_id,
                                    error = %e,
                                    error_debug = ?e,
                                    "SV2 writer: failed to send RequestTransactionDataError"
                                );
                                break;
                            }
                        }
                        None => {
                            write_cmd_closed = true;
                        }
                    }
                }
                recv_result = upd_rx.recv() => match recv_result {
                Ok(payload) => {
                    trace!(
                        peer = %peer_w,
                        template_id = payload.snapshot.template_id,
                        height = payload.snapshot.template.height,
                        prev_hash = %payload.snapshot.template.previous_block_hash,
                        "SV2 live template writer: received broadcast payload"
                    );
                    let first_template_id = payload.snapshot.template_id;
                    let first_height = payload.snapshot.template.height;
                    let mut latest_payload = payload;
                    let mut drained_after_first = 0u64;
                    let mut exit_after_send = false;
                    loop {
                        match upd_rx.try_recv() {
                            Ok(payload) => {
                                drained_after_first += 1;
                                latest_payload = payload;
                            }
                            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => break,
                            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(skipped)) => {
                                warn!(
                                    peer = %peer_w,
                                    skipped,
                                    "SV2 template update receiver lagged"
                                );
                            }
                            Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                                exit_after_send = true;
                                break;
                            }
                        }
                    }
                    let latest_template_id = latest_payload.snapshot.template_id;
                    trace!(
                        peer = %peer_w,
                        first_template_id,
                        first_height,
                        latest_template_id,
                        latest_height = latest_payload.snapshot.template.height,
                        skipped_intermediate = drained_after_first.saturating_sub(1),
                        "SV2 live writer: coalesced queued template updates"
                    );
                    trace!(
                        peer = %peer_w,
                        template_id = latest_template_id,
                        height = latest_payload.snapshot.template.height,
                        prev_hash = %latest_payload.snapshot.template.previous_block_hash,
                        "Template update dequeued for SV2 session"
                    );
                    trace!(
                        peer = %peer_w,
                        template_id = latest_template_id,
                        height = latest_payload.snapshot.template.height,
                        "SV2 live writer: using dedicated write codec state"
                    );
                    trace!(
                        peer = %peer_w,
                        template_id = latest_template_id,
                        height = latest_payload.snapshot.template.height,
                        "SV2 live writer: invoking send_template_pair"
                    );
                    let current_constraints = load_session_constraints(&sc_writer);
                    if let Err(reason) = validate_template_under_constraints(
                        &latest_payload.snapshot.template,
                        &current_constraints,
                    ) {
                        warn!(
                            peer = %peer_w,
                            height = latest_payload.snapshot.template.height,
                            template_id = latest_template_id,
                            prev_hash_rpc_hex = %latest_payload.snapshot.template.previous_block_hash,
                            size_limit = latest_payload.snapshot.template.size_limit,
                            sigop_limit = latest_payload.snapshot.template.sigop_limit,
                            tx_count = latest_payload.snapshot.template.transactions.len(),
                            coinbase_output_max_additional_size = current_constraints.coinbase_output_max_additional_size,
                            coinbase_output_max_additional_sigops = current_constraints.coinbase_output_max_additional_sigops,
                            reason = %reason,
                            "Live template rejected by CoinbaseOutputConstraints gate; skipping NewTemplate/SetNewPrevHash"
                        );
                        if exit_after_send {
                            debug!(
                                peer = %peer_w,
                                reason = "broadcast_closed",
                                "SV2 live template writer task: recv loop exiting"
                            );
                            break;
                        }
                        continue;
                    }
                    match send_template_pair(
                        &mut wh,
                        &mut write_transport_state,
                        &latest_payload.snapshot,
                        peer_w,
                    )
                    .await
                    {
                        Ok(()) => {
                            insert_template_id_cache(&tc_writer, &latest_payload.snapshot);
                            trace!(
                                peer = %peer_w,
                                template_id = latest_template_id,
                                height = latest_payload.snapshot.template.height,
                                "SV2 live writer: send_template_pair completed Ok"
                            );
                            if exit_after_send {
                                debug!(
                                    peer = %peer_w,
                                    reason = "broadcast_closed",
                                    "SV2 live template writer task: recv loop exiting"
                                );
                                break;
                            }
                        }
                        Err(e) => {
                            error!(
                                peer = %peer_w,
                                template_id = latest_template_id,
                                height = latest_payload.snapshot.template.height,
                                error = %e,
                                error_debug = ?e,
                                "SV2 live writer: send_template_pair returned error (full error)"
                            );
                            warn!(
                                peer = %peer_w,
                                "SV2 live template push failed: {:#}",
                                e
                            );
                            debug!(
                                peer = %peer_w,
                                reason = "send_template_pair_error_after_live_payload",
                                template_id = latest_template_id,
                                height = latest_payload.snapshot.template.height,
                                "SV2 live template writer task: recv loop exiting"
                            );
                            break;
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(
                        peer = %peer_w,
                        skipped,
                        "SV2 template update receiver lagged"
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    debug!(
                        peer = %peer_w,
                        reason = "broadcast_closed",
                        "SV2 live template writer task: recv loop exiting"
                    );
                    break;
                }
            }
            }
        }
        debug!(
            peer = %peer_w,
            "SV2 live template writer task ended"
        );
    });

    debug!(
        peer = %peer,
        "Session read loop with live template push (post-SetupConnection); using dedicated read codec state"
    );

    loop {
        let frame_result =
            read_encrypted_sv2_frame(&mut read_half, decoder, &mut read_transport_state, peer)
                .await;
        match frame_result {
            Ok((h, payload, cipher_len)) => {
                log_and_dispatch_post_init_sv2_frame(
                    peer,
                    h,
                    payload,
                    cipher_len,
                    rpc.clone(),
                    &template_rx,
                    template_cache.clone(),
                    Some(&write_cmd_tx),
                )
                .await;
            }
            Err(e) => {
                if is_unexpected_eof(&e) {
                    info!(
                        peer = %peer,
                        event = "pool_disconnected",
                        reason = "tcp_closed",
                        detail = "unexpected_eof_on_read",
                        "Session read loop exiting (SV2 client disconnected)"
                    );
                    return Ok(());
                }
                warn!(
                    peer = %peer,
                    reason = "read_or_decode_error",
                    event = "pool_disconnected",
                    "Session read loop exiting on error: {:#}",
                    e
                );
                return Err(e);
            }
        }
    }
}

/// Read one Noise-encrypted SV2 frame; copies payload into an owned buffer for decoding.
async fn read_encrypted_sv2_frame<R: AsyncRead + Unpin>(
    stream: &mut R,
    decoder: &mut StandardNoiseDecoder<SetupConnection<'_>>,
    state: &mut codec_sv2::State,
    peer: SocketAddr,
) -> Result<(Header, Vec<u8>, usize)> {
    let mut cipher_total = 0usize;

    loop {
        let w = decoder.writable();
        if !w.is_empty() {
            stream
                .read_exact(w)
                .await
                .with_context(|| format!("peer {peer}: read encrypted SV2 chunk"))?;
            cipher_total += w.len();
        }

        match decoder.next_frame(state) {
            Ok(Frame::Sv2(mut fr)) => {
                let header = fr
                    .get_header()
                    .ok_or_else(|| anyhow!("decoded frame missing header"))?;
                let payload = fr.payload().to_vec();
                return Ok((header, payload, cipher_total));
            }
            Ok(Frame::HandShake(_)) => {
                return Err(anyhow!("unexpected HandShake frame after Noise transport"));
            }
            Err(CodecError::MissingBytes(n)) => {
                debug!(peer = %peer, need = n, "Noise decoder needs more ciphertext bytes");
                continue;
            }
            Err(e) => {
                error!(peer = %peer, "SV2 Noise decode error: {:?}", e);
                return Err(anyhow!("SV2 Noise decode failed: {:?}", e));
            }
        }
    }
}

async fn send_setup_connection_error(
    stream: &mut TcpStream,
    state: &mut codec_sv2::State,
    extension_type_base: u16,
    error_code: &str,
    flags: u32,
) -> Result<()> {
    let code: Str0255<'static> = String::from(error_code)
        .try_into()
        .map_err(|e| anyhow!("invalid error_code string: {:?}", e))?;

    let err = SetupConnectionError {
        flags,
        error_code: code,
    };

    let frame = Sv2Frame::from_message(
        err,
        MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
        extension_type_base,
        false,
    )
    .ok_or_else(|| anyhow!("SetupConnectionError frame construction failed"))?;

    let mut encoder = NoiseEncoder::<SetupConnectionError>::new();
    let encrypted = encoder
        .encode(Frame::Sv2(frame), state)
        .map_err(|e| anyhow!("Noise encode SetupConnectionError: {:?}", e))?;

    stream
        .write_all(encrypted.as_ref())
        .await
        .context("failed to send SetupConnectionError")?;
    stream.flush().await?;
    debug!(
        extension_type = extension_type_base,
        error_code = %error_code,
        flags,
        "Response sent: SetupConnectionError"
    );
    Ok(())
}

/// Keep the TCP session alive: decrypt further SV2 frames and log headers only.
async fn drain_encrypted_frames(
    stream: &mut TcpStream,
    decoder: &mut StandardNoiseDecoder<SetupConnection<'_>>,
    state: &mut codec_sv2::State,
    peer: SocketAddr,
    rpc: Arc<RpcClient>,
    template_rx: watch::Receiver<Option<TemplateSnapshot>>,
    template_cache: TemplateIdCache,
) -> Result<()> {
    debug!(
        peer = %peer,
        "Session idle read loop (post-SetupConnection; payloads not decoded)"
    );

    loop {
        match read_encrypted_sv2_frame(stream, decoder, state, peer).await {
            Ok((h, payload, cipher_len)) => {
                log_and_dispatch_post_init_sv2_frame(
                    peer,
                    h,
                    payload,
                    cipher_len,
                    rpc.clone(),
                    &template_rx,
                    template_cache.clone(),
                    None,
                )
                .await;
            }
            Err(e) => {
                if is_unexpected_eof(&e) {
                    info!(
                        peer = %peer,
                        event = "pool_disconnected",
                        reason = "tcp_closed",
                        detail = "unexpected_eof_on_idle_drain",
                        "SV2 client disconnected"
                    );
                    return Ok(());
                }
                warn!(peer = %peer, "SV2 read/decode error: {:#}", e);
                return Err(e);
            }
        }
    }
}

fn is_unexpected_eof(e: &anyhow::Error) -> bool {
    let mut cur: &(dyn std::error::Error + 'static) = e.as_ref();
    loop {
        if let Some(io) = cur.downcast_ref::<std::io::Error>() {
            if io.kind() == std::io::ErrorKind::UnexpectedEof {
                return true;
            }
        }
        match cur.source() {
            Some(s) => cur = s,
            None => return false,
        }
    }
}

fn decode_key(hex_str: &str, name: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).with_context(|| format!("{name} is not valid hex"))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| anyhow!("{name} must be 32 bytes (64 hex chars), got {}", v.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::{AzcoinTemplate, TemplateSnapshot, TemplateTx};

    fn make_tmpl(
        transactions: Vec<TemplateTx>,
        size_limit: u64,
        sigop_limit: u64,
        default_witness_commitment: Option<String>,
    ) -> AzcoinTemplate {
        AzcoinTemplate {
            height: 1_234,
            version: 0x2000_0000,
            previous_block_hash: "aaaa0000bbbb1111cccc2222dddd3333eeee4444ffff5555aaaa0000bbbb1111"
                .into(),
            bits: "207fffff".into(),
            target: "7fffff0000000000000000000000000000000000000000000000000000000000".into(),
            curtime: 1_700_000_100,
            mintime: 1_700_000_000,
            coinbase_value: 5_000_000_000,
            size_limit,
            weight_limit: 0,
            sigop_limit,
            default_witness_commitment,
            transactions,
        }
    }

    fn make_tx(data_byte_len: usize, sigops: u64) -> TemplateTx {
        TemplateTx {
            txid: "00".repeat(32),
            fee: 1_000,
            weight: 400,
            sigops,
            // Each byte is 2 hex chars; content is arbitrary (we only look at length).
            data: "ab".repeat(data_byte_len),
        }
    }

    fn make_snapshot(
        template_id: u64,
        transactions: Vec<TemplateTx>,
        default_witness_commitment: Option<String>,
    ) -> TemplateSnapshot {
        TemplateSnapshot {
            template_id,
            template: make_tmpl(
                transactions,
                /*size_limit*/ 4_000_000,
                /*sigop_limit*/ 80_000,
                default_witness_commitment,
            ),
        }
    }

    #[test]
    fn persisted_constraints_overwrite_previous() {
        let state: SessionConstraintsState =
            Arc::new(std::sync::Mutex::new(SessionConstraints::default()));
        assert_eq!(
            load_session_constraints(&state),
            SessionConstraints::default()
        );

        let first = SessionConstraints {
            coinbase_output_max_additional_size: 100,
            coinbase_output_max_additional_sigops: 5,
        };
        store_session_constraints(&state, first);
        assert_eq!(load_session_constraints(&state), first);

        let second = SessionConstraints {
            coinbase_output_max_additional_size: 250,
            coinbase_output_max_additional_sigops: 9,
        };
        store_session_constraints(&state, second);
        assert_eq!(
            load_session_constraints(&state),
            second,
            "latest store must overwrite previous"
        );
        assert_ne!(load_session_constraints(&state), first);
    }

    #[test]
    fn validate_passes_with_ample_headroom() {
        let txs = vec![make_tx(250, 1), make_tx(300, 1)];
        let tmpl = make_tmpl(
            txs, /*size_limit*/ 1_000_000, /*sigop_limit*/ 80_000, None,
        );
        let constraints = SessionConstraints {
            coinbase_output_max_additional_size: 1_000,
            coinbase_output_max_additional_sigops: 100,
        };
        assert_eq!(
            validate_template_under_constraints(&tmpl, &constraints),
            Ok(())
        );
    }

    #[test]
    fn validate_fails_when_size_headroom_insufficient() {
        let txs = vec![make_tx(500, 1)];
        let tmpl = make_tmpl(
            txs, /*size_limit*/ 900, /*sigop_limit*/ 80_000, None,
        );
        let constraints = SessionConstraints {
            coinbase_output_max_additional_size: 10_000,
            coinbase_output_max_additional_sigops: 0,
        };
        let res = validate_template_under_constraints(&tmpl, &constraints);
        let err = res.expect_err("should fail due to size");
        assert!(
            err.contains("exceeds size_limit"),
            "expected size error, got: {err}"
        );
        assert!(
            err.contains("max_additional_size=10000"),
            "error should mention max_additional_size, got: {err}"
        );
    }

    #[test]
    fn validate_fails_when_sigops_headroom_insufficient() {
        let txs = vec![make_tx(100, 5), make_tx(100, 5)];
        let tmpl = make_tmpl(
            txs, /*size_limit*/ 4_000_000, /*sigop_limit*/ 20, None,
        );
        let constraints = SessionConstraints {
            coinbase_output_max_additional_size: 0,
            coinbase_output_max_additional_sigops: 50,
        };
        let res = validate_template_under_constraints(&tmpl, &constraints);
        let err = res.expect_err("should fail due to sigops");
        assert!(
            err.contains("exceeds sigop_limit"),
            "expected sigop error, got: {err}"
        );
        assert!(
            err.contains("max_additional_sigops=50"),
            "error should mention max_additional_sigops, got: {err}"
        );
    }

    #[test]
    fn validate_default_constraints_passes_when_limits_nonzero() {
        let txs = vec![make_tx(100, 1), make_tx(120, 1)];
        let tmpl = make_tmpl(
            txs, /*size_limit*/ 4_000_000, /*sigop_limit*/ 80_000, None,
        );
        assert_eq!(
            validate_template_under_constraints(&tmpl, &SessionConstraints::default()),
            Ok(()),
            "default constraints against a normal template must not be rejected"
        );
    }

    #[test]
    fn validate_skips_limits_when_zero() {
        // Both limits zero (as for an AZCOIN GBT that omits them) must never reject, even with
        // large reservations.
        let txs = vec![make_tx(50, 10)];
        let tmpl = make_tmpl(txs, /*size_limit*/ 0, /*sigop_limit*/ 0, None);
        let constraints = SessionConstraints {
            coinbase_output_max_additional_size: u32::MAX,
            coinbase_output_max_additional_sigops: u16::MAX,
        };
        assert_eq!(
            validate_template_under_constraints(&tmpl, &constraints),
            Ok(())
        );
    }

    #[test]
    fn request_transaction_data_success_preserves_snapshot_transactions() {
        let snapshot = make_snapshot(42, vec![make_tx(3, 1), make_tx(5, 2)], Some("6a".into()));
        let response =
            build_request_transaction_data_success(&snapshot).expect("success response builds");

        assert_eq!(response.template_id, 42);
        assert_eq!(response.excess_data.inner_as_ref(), &[0x6a]);

        let txs = response.transaction_list.into_inner();
        assert_eq!(txs.len(), 2);
        assert_eq!(txs[0].inner_as_ref(), &[0xab; 3]);
        assert_eq!(txs[1].inner_as_ref(), &[0xab; 5]);
    }

    #[test]
    fn request_transaction_data_error_uses_template_id_not_found_code() {
        let response = build_request_transaction_data_error(77, "template-id-not-found")
            .expect("error response builds");

        assert_eq!(response.template_id, 77);
        assert_eq!(
            response.error_code.as_utf8_or_hex(),
            "template-id-not-found"
        );
    }
}
