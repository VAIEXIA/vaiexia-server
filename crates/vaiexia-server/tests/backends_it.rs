// Live backend integration tests.
// These tests exercise real Linux system backends and require:
//   - Linux host
//   - Feature flag `--features system-it`
//   - Running as a user in the `systemd-journal` group (for journald)
//   - A supported distro (for package detect)
//
// Run on Linux CI:
//   cargo test --workspace --features system-it -- --ignored
//
// All tests are #[ignore] — they are never run on Windows or in normal CI.

#![cfg(all(target_os = "linux", feature = "system-it"))]

#[cfg(all(target_os = "linux", feature = "system-it"))]
mod journald_live {
    use vaiexia_server::backend::logs::JournaldLogs;
    use vaiexia_server::backend::{LogProvider, LogQuery};

    #[tokio::test]
    #[ignore = "requires Linux + systemd-journal group"]
    async fn journald_probe_returns_true_on_linux_with_journald() {
        assert!(
            JournaldLogs::probe().await,
            "JournaldLogs::probe() should return true on a real Linux system with journald"
        );
    }

    #[tokio::test]
    #[ignore = "requires Linux + systemd-journal group"]
    async fn journald_query_returns_some_entries() {
        let logs = JournaldLogs::new();
        let q = LogQuery {
            limit: 10,
            ..Default::default()
        };
        let page = logs.query(&q).await.expect("journald query should succeed");
        assert!(
            !page.items.is_empty(),
            "expected at least 1 log entry from journald"
        );
        for entry in &page.items {
            // Every real journald entry should have a non-empty cursor
            assert!(
                !entry.cursor.is_empty(),
                "entry cursor should not be empty: {entry:?}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires Linux + systemd-journal group"]
    async fn journald_query_with_unit_filter_works() {
        let logs = JournaldLogs::new();
        // Query systemd-journald itself — should always have entries on a live system
        let q = LogQuery {
            unit: Some("systemd-journald.service".to_string()),
            limit: 5,
            ..Default::default()
        };
        // May return 0 entries if the unit hasn't logged recently — just don't panic
        let page = logs.query(&q).await.expect("journald unit query should succeed");
        for entry in &page.items {
            // When filtering by unit, entries should match
            if let Some(ref unit) = entry.unit {
                assert!(
                    unit.contains("journald"),
                    "entry unit should match filter: {unit}"
                );
            }
        }
    }
}

#[cfg(all(target_os = "linux", feature = "system-it"))]
mod package_detect_live {
    use vaiexia_server::backend::packages::detect::{from_os_release, confirm};

    #[test]
    #[ignore = "requires Linux with a supported distro"]
    fn detect_matches_container_distro() {
        let content = std::fs::read_to_string("/etc/os-release")
            .expect("should be able to read /etc/os-release on Linux");

        let kind = from_os_release(&content).expect(
            "from_os_release should return Some on a supported distro (debian/fedora/arch/alpine)",
        );

        // Also confirm the binary exists
        assert!(
            confirm(kind, |p| p.exists()),
            "package manager binary should exist for detected kind {:?}",
            kind
        );
    }

    #[test]
    #[ignore = "requires Linux with a supported distro"]
    fn os_release_id_is_recognized() {
        let content = std::fs::read_to_string("/etc/os-release")
            .expect("/etc/os-release should exist on Linux");
        // Just check we can parse it without panic
        let _ = from_os_release(&content);
    }
}

#[cfg(all(target_os = "linux", feature = "system-it"))]
mod privd_exec_live {
    // These tests require vaiexia-privd to be running and connected.
    // They are documented here as the expected integration scenario.
    // Run manually when the full daemon stack is deployed.

    #[test]
    #[ignore = "requires vaiexia-privd running at /run/vaiexia/privd.sock"]
    fn privd_socket_reachable_for_ping() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        use vaiexia_priv_proto::{PrivRequest, PrivResponse};

        let socket_path = "/run/vaiexia/privd.sock";
        let mut stream = UnixStream::connect(socket_path)
            .expect("privd socket should be reachable");

        let req = PrivRequest::Ping;
        let payload = serde_json::to_vec(&req).unwrap();
        let len = payload.len() as u32;

        stream.write_all(&len.to_be_bytes()).unwrap();
        stream.write_all(&payload).unwrap();

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).unwrap();
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        let mut resp_buf = vec![0u8; resp_len];
        stream.read_exact(&mut resp_buf).unwrap();

        let resp: PrivResponse = serde_json::from_slice(&resp_buf).unwrap();
        assert_eq!(resp, PrivResponse::Pong, "Ping should return Pong");
    }
}
