//! Client for the `vaiexia-privd` unix socket.
//! Unix-only — package writes are delegated to the privileged daemon.

#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use vaiexia_priv_proto::{PrivRequest, PrivResponse};

use crate::backend::BackendError;

/// Default socket path for the vaiexia-privd daemon.
pub const PRIVD_SOCKET_PATH: &str = "/run/vaiexia/privd.sock";

/// Send a request to vaiexia-privd and return the response.
///
/// Uses length-prefixed framing: 4-byte big-endian length + JSON payload.
pub fn send_request(
    socket_path: &str,
    req: &PrivRequest,
) -> Result<PrivResponse, BackendError> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|_| BackendError::Unavailable)?;

    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| BackendError::Unavailable)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| BackendError::Unavailable)?;

    // Serialize request
    let payload = serde_json::to_vec(req)
        .map_err(|_| BackendError::Internal("serialize request".into()))?;

    if payload.len() > 1 << 20 {
        return Err(BackendError::Internal("request too large".into()));
    }

    // Write length-prefixed frame: 4-byte BE length + payload
    let len = payload.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .map_err(|_| BackendError::Unavailable)?;
    stream
        .write_all(&payload)
        .map_err(|_| BackendError::Unavailable)?;

    // Read length-prefixed response
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|_| BackendError::Unavailable)?;
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    if resp_len > 1 << 20 {
        return Err(BackendError::Internal("response too large".into()));
    }

    let mut resp_buf = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp_buf)
        .map_err(|_| BackendError::Unavailable)?;

    let resp: PrivResponse = serde_json::from_slice(&resp_buf)
        .map_err(|_| BackendError::Internal("deserialize response".into()))?;

    Ok(resp)
}

/// Map a `PrivResponse` to a `Result<(), BackendError>`.
pub fn response_to_result(resp: PrivResponse) -> Result<(), BackendError> {
    match resp {
        PrivResponse::Ok => Ok(()),
        PrivResponse::Error { message } => Err(BackendError::Internal(message)),
        other => Err(BackendError::Internal(format!("unexpected privd response: {other:?}"))),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use vaiexia_priv_proto::{PrivRequest, PrivResponse, PROTO_VERSION};

    /// Test the frame encoding/decoding in-memory using a pair of Unix pipes.
    #[test]
    fn frame_roundtrip_via_in_memory_pipe() {
        use std::os::unix::net::UnixStream;
        use std::io::{Read, Write};

        let (mut client, mut server) = UnixStream::pair().expect("socketpair");

        let req = PrivRequest::PkgInstall {
            name: vaiexia_priv_proto::PackageName::parse("nginx").unwrap(),
        };
        let payload = serde_json::to_vec(&req).unwrap();
        let len = payload.len() as u32;

        // Write frame (client → server)
        client.write_all(&len.to_be_bytes()).unwrap();
        client.write_all(&payload).unwrap();

        // Read frame (server side)
        let mut len_buf = [0u8; 4];
        server.read_exact(&mut len_buf).unwrap();
        let recv_len = u32::from_be_bytes(len_buf) as usize;
        let mut recv_buf = vec![0u8; recv_len];
        server.read_exact(&mut recv_buf).unwrap();

        let recv_req: PrivRequest = serde_json::from_slice(&recv_buf).unwrap();
        assert_eq!(recv_req, req);

        // Write response (server → client)
        let resp = PrivResponse::Ok;
        let resp_payload = serde_json::to_vec(&resp).unwrap();
        let resp_len = resp_payload.len() as u32;
        server.write_all(&resp_len.to_be_bytes()).unwrap();
        server.write_all(&resp_payload).unwrap();

        // Read response (client side)
        let mut rlen_buf = [0u8; 4];
        client.read_exact(&mut rlen_buf).unwrap();
        let rlen = u32::from_be_bytes(rlen_buf) as usize;
        let mut rbuf = vec![0u8; rlen];
        client.read_exact(&mut rbuf).unwrap();

        let recv_resp: PrivResponse = serde_json::from_slice(&rbuf).unwrap();
        assert_eq!(recv_resp, PrivResponse::Ok);
    }

    #[test]
    fn response_ok_maps_to_ok() {
        assert!(response_to_result(PrivResponse::Ok).is_ok());
    }

    #[test]
    fn response_error_maps_to_backend_error() {
        let result = response_to_result(PrivResponse::Error { message: "boom".into() });
        assert!(result.is_err());
    }

    #[test]
    fn response_pong_maps_to_unexpected_error() {
        let result = response_to_result(PrivResponse::Pong);
        assert!(result.is_err());
    }
}
