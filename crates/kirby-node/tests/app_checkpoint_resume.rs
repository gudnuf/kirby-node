//! Portable app-checkpoint handoff proof.
//!
//! This boots a real genome twice: node 1 submits an app-level checkpoint, the
//! daemon stores it by content hash, then node 2 boots fresh with that checkpoint
//! in `GetSessionContext` and reports `checkpoint_restore_seen`. The same test
//! runs on Linux/Firecracker or macOS/VZ because the backend is selected by the
//! shared boot path.

use std::time::Duration;

use kirby_node::app_checkpoint_run::{self, AppCheckpointRunConfig};
use kirby_node::boot::{BootConfig, ImagePaths};

#[tokio::test]
async fn portable_app_checkpoint_handoff_boots_fresh_and_restores_logical_state() {
    let Some(image_dir) = std::env::var_os("KIRBY_GENOME_IMAGE") else {
        eprintln!(
            "SKIP portable_app_checkpoint_handoff...: set KIRBY_GENOME_IMAGE to run the real app-checkpoint handoff proof"
        );
        return;
    };
    let image = ImagePaths::from_dir(&std::path::PathBuf::from(image_dir))
        .expect("genome image (vmlinux + rootfs.squashfs)");
    let base = BootConfig {
        image,
        node_id: format!("appckpt-{}", std::process::id()),
        task: "app-checkpoint-test".to_string(),
        budget_sats: 1_000_000,
        initial_sats: 1_000_000,
        allow: vec!["mint.test.local".to_string()],
        guest_cid: 41,
        gateway_port: 5041,
        vcpu_count: 1,
        mem_size_mib: 128,
        hello_timeout: Duration::from_secs(40),
        workload: Some("app-checkpoint".to_string()),
        lockdown_egress: false,
        snapshot_capable: false,
        restore_checkpoint: None,
    };

    let mut config = AppCheckpointRunConfig::new(base);
    config.checkpoint_timeout = Duration::from_secs(40);
    config.restore_timeout = Duration::from_secs(40);

    let outcome = app_checkpoint_run::run(config)
        .await
        .expect("app-checkpoint handoff run");
    eprintln!("{}", app_checkpoint_run::evidence_line(&outcome));
    assert!(
        outcome.passed(),
        "app-checkpoint handoff did not satisfy the portable restore proof"
    );
}
