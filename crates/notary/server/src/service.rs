pub mod axum_websocket;
pub mod tcp;
pub mod websocket;

use axum::{
    extract::{rejection::JsonRejection, FromRequestParts, Query, State},
    http::{header, request::Parts, StatusCode},
    response::{IntoResponse, Json, Response},
};
use axum_macros::debug_handler;
use eyre::eyre;
use std::time::Duration;
use tlsn_common::config::ProtocolConfigValidator;
use tlsn_core::attestation::AttestationConfig;
use tlsn_verifier::{Verifier, VerifierConfig};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::timeout,
};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{debug, error, info, trace};
use uuid::Uuid;
use tlsn_core::{presentation::{Presentation,PresentationOutput},signing::VerifyingKey};
use crate::{
    domain::notary::{
        NotarizationRequestQuery, NotarizationSessionRequest, NotarizationSessionResponse,
        NotaryGlobals,VerifyPresentationRequest,VerifyPresentationResponse
    },
    error::NotaryServerError,
    service::{
        axum_websocket::{header_eq, WebSocketUpgrade},
        tcp::{tcp_notarize, TcpUpgrade},
        websocket::websocket_notarize,
    },
};

/// A wrapper enum to facilitate extracting TCP connection for either WebSocket
/// or TCP clients, so that we can use a single endpoint and handler for
/// notarization for both types of clients
pub enum ProtocolUpgrade {
    Tcp(TcpUpgrade),
    Ws(WebSocketUpgrade),
}

impl<S> FromRequestParts<S> for ProtocolUpgrade
where
    S: Send + Sync,
{
    type Rejection = NotaryServerError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Extract tcp connection for websocket client
        if header_eq(&parts.headers, header::UPGRADE, "websocket") {
            let extractor = WebSocketUpgrade::from_request_parts(parts, state)
                .await
                .map_err(|err| NotaryServerError::BadProverRequest(err.to_string()))?;
            Ok(Self::Ws(extractor))
        // Extract tcp connection for tcp client
        } else if header_eq(&parts.headers, header::UPGRADE, "tcp") {
            let extractor = TcpUpgrade::from_request_parts(parts, state)
                .await
                .map_err(|err| NotaryServerError::BadProverRequest(err.to_string()))?;
            Ok(Self::Tcp(extractor))
        } else {
            Err(NotaryServerError::BadProverRequest(
                "Upgrade header is not set for client".to_string(),
            ))
        }
    }
}

/// Handler to upgrade protocol from http to either websocket or underlying tcp
/// depending on the type of client the session_id parameter is also extracted
/// here to fetch the configuration parameters that have been submitted in the
/// previous request to /session made by the same client
pub async fn upgrade_protocol(
    protocol_upgrade: ProtocolUpgrade,
    State(notary_globals): State<NotaryGlobals>,
    Query(params): Query<NotarizationRequestQuery>,
) -> Response {
    info!("Received upgrade protocol request");
    let session_id = params.session_id;
    // Check if session_id exists in the store, this also removes session_id from
    // the store as each session_id can only be used once
    if notary_globals
        .store
        .lock()
        .unwrap()
        .remove(&session_id)
        .is_none()
    {
        let err_msg = format!("Session id {} does not exist", session_id);
        error!(err_msg);
        return NotaryServerError::BadProverRequest(err_msg).into_response();
    };
    // This completes the HTTP Upgrade request and returns a successful response to
    // the client, meanwhile initiating the websocket or tcp connection
    match protocol_upgrade {
        ProtocolUpgrade::Ws(ws) => {
            ws.on_upgrade(move |socket| websocket_notarize(socket, notary_globals, session_id))
        }
        ProtocolUpgrade::Tcp(tcp) => {
            tcp.on_upgrade(move |stream| tcp_notarize(stream, notary_globals, session_id))
        }
    }
}

/// Handler to initialize and configure notarization for both TCP and WebSocket
/// clients
#[debug_handler(state = NotaryGlobals)]
pub async fn initialize(
    State(notary_globals): State<NotaryGlobals>,
    payload: Result<Json<NotarizationSessionRequest>, JsonRejection>,
) -> impl IntoResponse {
    info!(
        ?payload,
        "Received request for initializing a notarization session"
    );

    // Parse the body payload
    let payload = match payload {
        Ok(payload) => payload,
        Err(err) => {
            error!("Malformed payload submitted for initializing notarization: {err}");
            return NotaryServerError::BadProverRequest(err.to_string()).into_response();
        }
    };

    // Ensure that the max_sent_data, max_recv_data submitted is not larger than the
    // global max limits configured in notary server
    if payload.max_sent_data.is_some() || payload.max_recv_data.is_some() {
        if payload.max_sent_data.unwrap_or_default()
            > notary_globals.notarization_config.max_sent_data
        {
            error!(
                "Max sent data requested {:?} exceeds the global maximum threshold {:?}",
                payload.max_sent_data.unwrap_or_default(),
                notary_globals.notarization_config.max_sent_data
            );
            return NotaryServerError::BadProverRequest(
                "Max sent data requested exceeds the global maximum threshold".to_string(),
            )
            .into_response();
        }
        if payload.max_recv_data.unwrap_or_default()
            > notary_globals.notarization_config.max_recv_data
        {
            error!(
                "Max recv data requested {:?} exceeds the global maximum threshold {:?}",
                payload.max_recv_data.unwrap_or_default(),
                notary_globals.notarization_config.max_recv_data
            );
            return NotaryServerError::BadProverRequest(
                "Max recv data requested exceeds the global maximum threshold".to_string(),
            )
            .into_response();
        }
    }

    let prover_session_id = Uuid::new_v4().to_string();

    // Store the configuration data in a temporary store
    notary_globals
        .store
        .lock()
        .unwrap()
        .insert(prover_session_id.clone(), ());

    trace!("Latest store state: {:?}", notary_globals.store);

    // Return the session id in the response to the client
    (
        StatusCode::OK,
        Json(NotarizationSessionResponse {
            session_id: prover_session_id,
        }),
    )
        .into_response()
}

/// Run the notarization
pub async fn notary_service<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: T,
    notary_globals: NotaryGlobals,
    session_id: &str,
) -> Result<(), NotaryServerError> {
    debug!(?session_id, "Starting notarization...");

    let crypto_provider = notary_globals.crypto_provider.clone();

    let att_config = AttestationConfig::builder()
        .supported_signature_algs(Vec::from_iter(crypto_provider.signer.supported_algs()))
        .build()
        .map_err(|err| NotaryServerError::Notarization(Box::new(err)))?;

    let config = VerifierConfig::builder()
        .protocol_config_validator(
            ProtocolConfigValidator::builder()
                .max_sent_data(notary_globals.notarization_config.max_sent_data)
                .max_recv_data(notary_globals.notarization_config.max_recv_data)
                .build()?,
        )
        .crypto_provider(crypto_provider)
        .build()?;

    timeout(
        Duration::from_secs(notary_globals.notarization_config.timeout),
        Verifier::new(config).notarize(socket.compat(), &att_config),
    )
    .await
    .map_err(|_| eyre!("Timeout reached before notarization completes"))??;

    Ok(())
}

#[debug_handler(state = NotaryGlobals)]
pub async fn verify_presentation(
    // State(notary_globals): State<NotaryGlobals>,
    payload: Result<Json<VerifyPresentationRequest>, JsonRejection>,
) -> impl IntoResponse {
    // Parse the body payload
    let payload = match payload {
        Ok(payload) => payload,
        Err(err) => {
            error!("Malformed payload submitted for verify_presentation : {err}");
            return NotaryServerError::BadProverRequest(err.to_string()).into_response();
        }
    };

    let data_hex = &payload.data;
    let data_bytes = match hex::decode(data_hex){
        Ok(bytes) => bytes,
        Err(err) => {
            return NotaryServerError::BadProverRequest(format!(
                "Invalid hex data: {}",
                err
            ))
            .into_response();
        }
    };

    let presentation: Presentation = match bincode::deserialize(&data_bytes){
        Ok(presentation) => presentation,
        Err(err) => {
            return NotaryServerError::BadProverRequest(format!(
                "Invalid presentation: {}",
                err
            ))
            .into_response();
        }
    };
        
    let provider = tlsn_core::CryptoProvider::default();

    let VerifyingKey {
        alg,
        data: key_data,
    } = presentation.verifying_key();
    let hex_key =hex::encode(key_data);
    // println!("alg:{:?},hex_key:{:?}",alg, hex_key);
    //todo check the key belong to self server

    let PresentationOutput {
        server_name,
        connection_info,
        transcript,
        ..
    } = presentation.verify(&provider).unwrap();

    let time = chrono::DateTime::UNIX_EPOCH + Duration::from_secs(connection_info.time);
    let server_name = server_name.unwrap();
    let mut partial_transcript = transcript.unwrap();
    // Set the unauthenticated bytes so they are distinguishable.
    partial_transcript.set_unauthed(b'X');

    let sent = String::from_utf8_lossy(partial_transcript.sent_unsafe()).to_string();
    let recv = String::from_utf8_lossy(partial_transcript.received_unsafe()).to_string();


    // Return the session id in the response to the client
    (
        StatusCode::OK,
        Json(VerifyPresentationResponse {
            sent: sent,
            recv: recv,
            server_name:server_name.to_string(),
            time: time.to_string(),
            verifying_key:hex_key,
        }),
    ).into_response()
}