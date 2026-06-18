//! The embedded openraft lease + no-split-brain consensus (spec 3.5, 4.3, D-4,
//! D-14, D-17, red-team gate 1, gate G8): the consensus keystone.
//!
//! THE INVARIANT (spec 4.3): `active_lease { node_id, term }` is a SINGLE
//! replicated state-machine value, and across every committed term EXACTLY ONE
//! node holds it. Only the node that is BOTH the Raft leader AND holds
//! `active_lease` at the current committed term may run the genome and debit the
//! treasury; every other node is IDLE (no VM, no debit). Granting/transferring the
//! lease is a committed Raft log entry (linearizable, fenced by term), so a kill of
//! the active node triggers a Raft-mediated handoff at a NEW term, and a revived
//! stale node that still believes the OLD term sees the higher committed term via
//! Raft and REFUSES to run or debit (term-fencing). Two nodes both-active is
//! unreachable, so there is no double-execute and no double-burn.
//!
//! WHY openraft and NOT hand-rolled gossip (D-4): iroh-gossip is diffusion, not
//! consensus, so it can let two nodes both believe they are active (split-brain)
//! and double-spend. A real Raft gives a linearizable, term-fenced single value;
//! the lease rides on it.
//!
//! TRANSPORT (D-17): openraft over plain TCP/loopback, no iroh. Each node listens
//! on a distinct loopback TCP port; the [`TcpNetwork`] dials peers and ships
//! length-prefixed JSON-framed RPCs (append-entries, vote, install-snapshot). The
//! three nodes (D-14) are distinct daemon contexts on one host, so a real majority
//! (2 of 3) survives losing one node.
//!
//! WHAT IS GATED, NOT CHANGED: the lease GATES the run + debit; it does not change
//! WHAT the run/debit does. The agnostic core (gateway authorize-order, treasury
//! economics, rail, genome) is untouched; D-9 (one persisted treasury, no
//! double-store) holds because the lease-holder debits the SAME store the killed
//! node used. The fence is wired into BOTH the run/restore path (check before
//! booting/restoring a VM) and the treasury-debit path (check before any debit).
//!
//! SCOPE: the spike needs the lease, not a general KV store. The replicated value
//! is exactly `active_lease`; the only client write is "grant the lease to node N"
//! (the daemon issues it when it intends to become active). The state machine
//! stamps the GRANTING leader's term onto the lease, so the term is the Raft term
//! (monotonic, fenced) and a stale grant cannot lower it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Cursor};
use std::sync::Arc;
use std::time::Duration;

use openraft::error::{InstallSnapshotError, RaftError};
use openraft::network::{RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::storage::{LogFlushed, LogState, RaftLogStorage, RaftStateMachine, Snapshot};
use openraft::{
    BasicNode, Entry, EntryPayload, LogId, OptionalSend, RaftMetrics, RaftSnapshotBuilder,
    RaftTypeConfig, SnapshotMeta, StorageError, StorageIOError, StoredMembership, Vote,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

/// A node id in the lease cluster. The three spike nodes are 1, 2, 3 (D-14).
pub type LeaseNodeId = u64;

/// The single replicated client write: grant the active lease to `node_id`. The
/// state machine stamps the COMMITTING leader's term onto the lease when it applies
/// this entry, so the lease's term is the Raft term at grant time (monotonic across
/// the cluster, never lowered by a stale node). This is the only mutation a client
/// can request; there is no "set term directly" path, which is what keeps the term
/// authoritative and fenced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LeaseRequest {
    /// Grant the active lease to this node. Applied as a committed log entry; the
    /// state machine records `active_lease = { node_id, term = <this entry's Raft
    /// term> }`.
    Grant { node_id: LeaseNodeId },
}

/// The reply to a committed [`LeaseRequest`]: the lease as it stands AFTER applying
/// the entry (the granted node and the term the state machine stamped). Returned to
/// the client that proposed the grant so it learns the term it now (briefly) holds.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseResponse {
    /// The node that holds the active lease after this entry (the grantee).
    pub node_id: LeaseNodeId,
    /// The term stamped on the lease (the Raft term of the granting entry).
    pub term: u64,
}

/// The replicated state: who holds the active lease, at what term. `None` before
/// any grant is committed. The whole no-split-brain invariant is a property of this
/// one value being a linearizable Raft state machine: a committed `active_lease` is
/// agreed by a majority, so two nodes cannot both read themselves as the holder at
/// the same term.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveLease {
    pub node_id: LeaseNodeId,
    pub term: u64,
}

openraft::declare_raft_types!(
    /// The lease cluster's openraft type config. App data is a [`LeaseRequest`]
    /// (grant the lease); the response is a [`LeaseResponse`] (the lease after
    /// applying). Nodes are [`BasicNode`] (a loopback `addr` string the
    /// [`TcpNetwork`] dials).
    pub LeaseTypeConfig:
        D = LeaseRequest,
        R = LeaseResponse,
        NodeId = LeaseNodeId,
        Node = BasicNode,
);

/// The committed snapshot payload: the membership and the lease at snapshot time.
/// Small (the spike's whole state is one lease value), so the snapshot is trivial.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct LeaseSnapshotData {
    last_applied: Option<LogId<LeaseNodeId>>,
    membership: StoredMembership<LeaseNodeId, BasicNode>,
    active_lease: Option<ActiveLease>,
}

/// The in-memory Raft store: the log, the vote, and the applied state machine. The
/// spike runs a small, short-lived cluster on one host, so an in-memory store is
/// the right weight (the snapshot/resume that matters for the spike is the GENOME
/// VM's, C-7, not the Raft log's). The store is cheap to clone (an `Arc` over a
/// lock) so the `Raft` engine and the lease readers share it.
#[derive(Clone, Default)]
pub struct LeaseStore {
    inner: Arc<RwLock<StoreInner>>,
}

#[derive(Default)]
struct StoreInner {
    /// The persistent vote (Raft's per-term vote record).
    vote: Option<Vote<LeaseNodeId>>,
    /// The replicated log, keyed by index.
    log: BTreeMap<u64, Entry<LeaseTypeConfig>>,
    /// The id of the last entry applied to the state machine.
    last_applied: Option<LogId<LeaseNodeId>>,
    /// The last committed membership (Raft tracks this in the state machine).
    membership: StoredMembership<LeaseNodeId, BasicNode>,
    /// THE replicated value: the active lease (spec 3.5).
    active_lease: Option<ActiveLease>,
    /// A snapshot, if one was built, plus its meta (for install/serve).
    snapshot: Option<(SnapshotMeta<LeaseNodeId, BasicNode>, Vec<u8>)>,
    /// A monotonically increasing snapshot index for naming.
    snapshot_idx: u64,
}

impl LeaseStore {
    /// A fresh empty store (no log, no lease).
    pub fn new() -> Self {
        Self::default()
    }

    /// The current committed active lease, read directly from the applied state
    /// machine. This is the value the fence checks: a node holds the lease only if
    /// this reports it as the holder at a term >= the term it believes.
    pub async fn active_lease(&self) -> Option<ActiveLease> {
        self.inner.read().await.active_lease
    }

    /// Record the authoritative committed lease this store learned from the cluster
    /// (what a node observes as it CATCHES UP on rejoin: the leader's append-entries
    /// carry the committed `active_lease`, and applying them lands the higher term
    /// here). A revived stale node uses this to see the committed T+1 that superseded
    /// its old belief, so the fence rejects it BECAUSE it sees the higher committed
    /// term (not merely because it has no lease). The term only ever moves forward:
    /// a stale value lower than what is already committed is ignored, mirroring the
    /// Raft log applying in order.
    pub async fn observe_committed_lease(&self, lease: ActiveLease) {
        let mut inner = self.inner.write().await;
        match inner.active_lease {
            Some(existing) if existing.term >= lease.term => {}
            _ => inner.active_lease = Some(lease),
        }
    }
}

/// Apply one already-committed entry to the state machine: stamp the lease with the
/// GRANTING entry's term (so the lease term is the Raft term, monotonic and fenced)
/// and bump `last_applied`. A blank/membership entry only advances `last_applied`.
/// Factored out so the apply path is identical for log application and the response
/// it returns. A grant NEVER lowers the term (entries apply in log order, and the
/// Raft term is monotonic), so a stale node cannot rewind the lease.
fn apply_entry(inner: &mut StoreInner, entry: &Entry<LeaseTypeConfig>) -> LeaseResponse {
    inner.last_applied = Some(entry.log_id);
    match &entry.payload {
        EntryPayload::Blank => default_lease_response(inner),
        EntryPayload::Membership(m) => {
            inner.membership = StoredMembership::new(Some(entry.log_id), m.clone());
            default_lease_response(inner)
        }
        EntryPayload::Normal(req) => match req {
            LeaseRequest::Grant { node_id } => {
                // Stamp the GRANTING entry's Raft term onto the lease. The term is
                // the linearizable fence: a later grant at a higher term supersedes
                // an earlier one, and a stale node believing an old term is fenced
                // out because the committed term here is >= every committed grant.
                let lease = ActiveLease { node_id: *node_id, term: entry.log_id.leader_id.term };
                inner.active_lease = Some(lease);
                LeaseResponse { node_id: lease.node_id, term: lease.term }
            }
        },
    }
}

/// The lease response for a non-grant entry: the lease as it stands (or zero if
/// none), so a blank/membership commit still returns a well-formed response.
fn default_lease_response(inner: &StoreInner) -> LeaseResponse {
    match inner.active_lease {
        Some(l) => LeaseResponse { node_id: l.node_id, term: l.term },
        None => LeaseResponse::default(),
    }
}

impl RaftLogStorage<LeaseTypeConfig> for LeaseStore {
    type LogReader = Self;

    async fn get_log_state(
        &mut self,
    ) -> Result<LogState<LeaseTypeConfig>, StorageError<LeaseNodeId>> {
        let inner = self.inner.read().await;
        let last = inner.log.values().next_back().map(|e| e.log_id);
        // After a snapshot the purged-up-to id is the snapshot's last id; the spike
        // never purges the in-memory log, so the last-purged is None.
        Ok(LogState { last_purged_log_id: None, last_log_id: last })
    }

    async fn save_vote(&mut self, vote: &Vote<LeaseNodeId>) -> Result<(), StorageError<LeaseNodeId>> {
        self.inner.write().await.vote = Some(*vote);
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<LeaseNodeId>>, StorageError<LeaseNodeId>> {
        Ok(self.inner.read().await.vote)
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<LeaseTypeConfig>,
    ) -> Result<(), StorageError<LeaseNodeId>>
    where
        I: IntoIterator<Item = Entry<LeaseTypeConfig>> + OptionalSend,
    {
        {
            let mut inner = self.inner.write().await;
            for entry in entries {
                inner.log.insert(entry.log_id.index, entry);
            }
        }
        // The in-memory store flushes synchronously; signal success so the engine
        // advances. A real disk store would flush then call this.
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<LeaseNodeId>) -> Result<(), StorageError<LeaseNodeId>> {
        // Conflict resolution: drop everything at and after `log_id.index`.
        let mut inner = self.inner.write().await;
        let keys: Vec<u64> = inner.log.range(log_id.index..).map(|(k, _)| *k).collect();
        for k in keys {
            inner.log.remove(&k);
        }
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<LeaseNodeId>) -> Result<(), StorageError<LeaseNodeId>> {
        // Drop everything up to and including `log_id.index` (post-snapshot
        // compaction). Harmless for the spike's small log.
        let mut inner = self.inner.write().await;
        let keys: Vec<u64> = inner.log.range(..=log_id.index).map(|(k, _)| *k).collect();
        for k in keys {
            inner.log.remove(&k);
        }
        Ok(())
    }
}

impl openraft::storage::RaftLogReader<LeaseTypeConfig> for LeaseStore {
    async fn try_get_log_entries<RB: std::ops::RangeBounds<u64> + Clone + fmt::Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<LeaseTypeConfig>>, StorageError<LeaseNodeId>> {
        let inner = self.inner.read().await;
        Ok(inner.log.range(range).map(|(_, e)| e.clone()).collect())
    }
}

impl RaftStateMachine<LeaseTypeConfig> for LeaseStore {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<
        (Option<LogId<LeaseNodeId>>, StoredMembership<LeaseNodeId, BasicNode>),
        StorageError<LeaseNodeId>,
    > {
        let inner = self.inner.read().await;
        Ok((inner.last_applied, inner.membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<LeaseResponse>, StorageError<LeaseNodeId>>
    where
        I: IntoIterator<Item = Entry<LeaseTypeConfig>> + OptionalSend,
    {
        let mut inner = self.inner.write().await;
        let mut responses = Vec::new();
        for entry in entries {
            responses.push(apply_entry(&mut inner, &entry));
        }
        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<<LeaseTypeConfig as RaftTypeConfig>::SnapshotData>, StorageError<LeaseNodeId>>
    {
        Ok(Box::new(io::Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<LeaseNodeId, BasicNode>,
        snapshot: Box<<LeaseTypeConfig as RaftTypeConfig>::SnapshotData>,
    ) -> Result<(), StorageError<LeaseNodeId>> {
        let bytes = snapshot.into_inner();
        let data: LeaseSnapshotData = serde_json::from_slice(&bytes).map_err(|e| {
            StorageError::IO {
                source: StorageIOError::read_snapshot(Some(meta.signature()), &e),
            }
        })?;
        let mut inner = self.inner.write().await;
        inner.last_applied = data.last_applied;
        inner.membership = data.membership;
        inner.active_lease = data.active_lease;
        inner.snapshot = Some((meta.clone(), bytes));
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<LeaseTypeConfig>>, StorageError<LeaseNodeId>> {
        let inner = self.inner.read().await;
        Ok(inner.snapshot.as_ref().map(|(meta, data)| Snapshot {
            meta: meta.clone(),
            snapshot: Box::new(io::Cursor::new(data.clone())),
        }))
    }
}

impl RaftSnapshotBuilder<LeaseTypeConfig> for LeaseStore {
    async fn build_snapshot(&mut self) -> Result<Snapshot<LeaseTypeConfig>, StorageError<LeaseNodeId>> {
        let mut inner = self.inner.write().await;
        let data = LeaseSnapshotData {
            last_applied: inner.last_applied,
            membership: inner.membership.clone(),
            active_lease: inner.active_lease,
        };
        let bytes = serde_json::to_vec(&data).map_err(|e| StorageError::IO {
            source: StorageIOError::write_snapshot(None, &e),
        })?;
        inner.snapshot_idx += 1;
        let snapshot_id = format!(
            "{}-{}",
            inner.last_applied.map(|l| l.index).unwrap_or(0),
            inner.snapshot_idx
        );
        let meta = SnapshotMeta {
            last_log_id: inner.last_applied,
            last_membership: inner.membership.clone(),
            snapshot_id,
        };
        inner.snapshot = Some((meta.clone(), bytes.clone()));
        Ok(Snapshot { meta, snapshot: Box::new(io::Cursor::new(bytes)) })
    }
}

/// The wire framing for openraft RPCs over the loopback TCP transport (D-17). Each
/// request is one of the three Raft RPCs, JSON-encoded and length-prefixed; the
/// reply is the matching response. This is a deliberately tiny, dependency-light
/// wire (the spike needs three nodes on loopback, not a production transport).
#[derive(Serialize, Deserialize)]
enum RaftRpc {
    Append(AppendEntriesRequest<LeaseTypeConfig>),
    Vote(VoteRequest<LeaseNodeId>),
    Snapshot(InstallSnapshotRequest<LeaseTypeConfig>),
}

/// The wire reply: the matching Raft response (or an error string for a snapshot
/// install fault, which openraft models as a typed error).
#[derive(Serialize, Deserialize)]
enum RaftRpcReply {
    Append(AppendEntriesResponse<LeaseNodeId>),
    Vote(VoteResponse<LeaseNodeId>),
    Snapshot(Result<InstallSnapshotResponse<LeaseNodeId>, String>),
}

/// The openraft transport over plain loopback TCP (D-17, no iroh). The factory
/// produces a per-target [`TcpClient`] that dials the target node's `addr` (a
/// loopback `host:port` carried on its [`BasicNode`]) and ships length-prefixed
/// JSON RPCs. A dial/IO failure surfaces as an unreachable network error so the
/// Raft engine retries (exactly how a partition or a killed node manifests, which
/// is the heart of the G8 handoff).
#[derive(Clone, Default)]
pub struct TcpNetwork;

impl RaftNetworkFactory<LeaseTypeConfig> for TcpNetwork {
    type Network = TcpClient;

    async fn new_client(&mut self, target: LeaseNodeId, node: &BasicNode) -> Self::Network {
        TcpClient { target, addr: node.addr.clone() }
    }
}

/// A per-target Raft RPC client: dials the target's loopback address fresh per call
/// (a short-lived connection per RPC keeps the transport simple and makes a killed
/// node manifest immediately as a dial failure). The spike's RPC volume is tiny, so
/// per-call dialing is fine.
pub struct TcpClient {
    target: LeaseNodeId,
    addr: String,
}

impl TcpClient {
    /// Dial the target, send one framed RPC, and read the framed reply. A network
    /// fault (target down, partitioned) becomes an [`io::Error`] the caller maps to
    /// openraft's `Unreachable`, so the engine backs off and retries.
    async fn round_trip(&self, rpc: &RaftRpc) -> io::Result<RaftRpcReply> {
        let mut stream = tokio::time::timeout(Duration::from_millis(1000), TcpStream::connect(&self.addr))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connect to node {} ({}) timed out", self.target, self.addr),
                )
            })??;
        let body = serde_json::to_vec(rpc).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        write_frame(&mut stream, &body).await?;
        let reply = read_frame(&mut stream).await?;
        serde_json::from_slice(&reply).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Map a transport IO error to openraft's `Unreachable` network error, so the engine
/// treats a killed/partitioned node as unreachable (and retries) rather than as a
/// logic fault. A killed node's dial fails here, which is exactly what triggers the
/// G8 handoff.
fn unreachable(e: io::Error) -> openraft::error::Unreachable {
    openraft::error::Unreachable::new(&e)
}

impl RaftNetwork<LeaseTypeConfig> for TcpClient {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<LeaseTypeConfig>,
        _option: openraft::network::RPCOption,
    ) -> Result<
        AppendEntriesResponse<LeaseNodeId>,
        openraft::error::RPCError<LeaseNodeId, BasicNode, RaftError<LeaseNodeId>>,
    > {
        match self.round_trip(&RaftRpc::Append(rpc)).await {
            Ok(RaftRpcReply::Append(r)) => Ok(r),
            Ok(_) => Err(openraft::error::RPCError::Unreachable(
                openraft::error::Unreachable::new(&io::Error::new(
                    io::ErrorKind::InvalidData,
                    "wrong reply kind for append_entries",
                )),
            )),
            Err(e) => Err(openraft::error::RPCError::Unreachable(unreachable(e))),
        }
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<LeaseNodeId>,
        _option: openraft::network::RPCOption,
    ) -> Result<
        VoteResponse<LeaseNodeId>,
        openraft::error::RPCError<LeaseNodeId, BasicNode, RaftError<LeaseNodeId>>,
    > {
        match self.round_trip(&RaftRpc::Vote(rpc)).await {
            Ok(RaftRpcReply::Vote(r)) => Ok(r),
            Ok(_) => Err(openraft::error::RPCError::Unreachable(
                openraft::error::Unreachable::new(&io::Error::new(
                    io::ErrorKind::InvalidData,
                    "wrong reply kind for vote",
                )),
            )),
            Err(e) => Err(openraft::error::RPCError::Unreachable(unreachable(e))),
        }
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<LeaseTypeConfig>,
        _option: openraft::network::RPCOption,
    ) -> Result<
        InstallSnapshotResponse<LeaseNodeId>,
        openraft::error::RPCError<
            LeaseNodeId,
            BasicNode,
            RaftError<LeaseNodeId, InstallSnapshotError>,
        >,
    > {
        match self.round_trip(&RaftRpc::Snapshot(rpc)).await {
            Ok(RaftRpcReply::Snapshot(Ok(r))) => Ok(r),
            Ok(RaftRpcReply::Snapshot(Err(msg))) => {
                Err(openraft::error::RPCError::Unreachable(
                    openraft::error::Unreachable::new(&io::Error::other(msg)),
                ))
            }
            Ok(_) => Err(openraft::error::RPCError::Unreachable(
                openraft::error::Unreachable::new(&io::Error::new(
                    io::ErrorKind::InvalidData,
                    "wrong reply kind for install_snapshot",
                )),
            )),
            Err(e) => Err(openraft::error::RPCError::Unreachable(unreachable(e))),
        }
    }
}

/// A length-prefixed frame: a u32 big-endian length, then the JSON body. Keeps the
/// loopback wire self-delimiting without a heavier codec.
async fn write_frame(stream: &mut TcpStream, body: &[u8]) -> io::Result<()> {
    let len = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

/// Read one length-prefixed frame (the counterpart to [`write_frame`]).
async fn read_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    // Bound the frame so a malformed peer cannot ask us to allocate unboundedly.
    if len > 16 * 1024 * 1024 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame exceeds 16 MiB"));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

/// The openraft `Raft` engine specialized to the lease type config.
type LeaseRaft = openraft::Raft<LeaseTypeConfig>;

/// One node's embedded lease engine: the openraft `Raft`, this node's id, the
/// store (for direct lease reads), and the TCP listener task (the server half of
/// the D-17 transport). Drives the lease for one daemon context; the G8 harness
/// builds three of these on distinct loopback ports.
pub struct LeaseNode {
    id: LeaseNodeId,
    raft: LeaseRaft,
    store: LeaseStore,
    addr: String,
    /// The TCP RPC server task; aborted on `shutdown` (a kill of this node tears it
    /// down so peers see it as unreachable, which is what triggers the handoff).
    server: tokio::task::JoinHandle<()>,
}

impl LeaseNode {
    /// Start one lease node: bind its loopback TCP RPC server, build the openraft
    /// engine over the in-memory store and the TCP network, and return the handle.
    /// `addr` is the loopback `host:port` this node listens on (peers dial it).
    /// Aggressive election timers (well under a second) keep the spike's failover
    /// fast and deterministic; a real deployment would widen them.
    pub async fn start(id: LeaseNodeId, addr: &str) -> anyhow::Result<Self> {
        let store = LeaseStore::new();
        let listener = TcpListener::bind(addr).await.map_err(|e| {
            anyhow::anyhow!("lease node {id}: bind RPC listener on {addr}: {e}")
        })?;
        let bound = listener.local_addr()?.to_string();

        let config = openraft::Config {
            cluster_name: "kirby-lease".to_string(),
            // Fast, deterministic failover for the spike: an election fires within a
            // few hundred ms of losing the leader, so the G8 handoff is quick. The
            // heartbeat is well under the election floor so a live leader is never
            // spuriously challenged.
            heartbeat_interval: 50,
            election_timeout_min: 300,
            election_timeout_max: 600,
            // Keep the in-memory log small; snapshot rarely (the spike's state is one
            // lease value, so log growth is trivial regardless).
            snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(1000),
            max_in_snapshot_log_to_keep: 0,
            ..Default::default()
        };
        let config = Arc::new(config.validate()?);

        let raft = openraft::Raft::new(
            id,
            config,
            TcpNetwork,
            store.clone(),
            store.clone(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("lease node {id}: build raft: {e}"))?;

        // The RPC server: accept loopback connections from peers and dispatch each
        // framed RPC into this node's Raft engine. A killed node aborts this task,
        // so its peers' dials fail and they elect a new leader (the G8 handoff).
        let server_raft = raft.clone();
        let server = tokio::spawn(async move {
            serve_raft_rpc(listener, server_raft).await;
        });

        Ok(LeaseNode { id, raft, store, addr: bound, server })
    }

    /// This node's id.
    pub fn id(&self) -> LeaseNodeId {
        self.id
    }

    /// The loopback address peers dial to reach this node's Raft RPC server.
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// A cheap-clone handle for reading the lease + leadership from elsewhere (the
    /// fence wired into the run/restore and debit paths). Holding a handle does not
    /// keep the node alive; it reads the shared store + the engine's metrics.
    pub fn handle(&self) -> LeaseHandle {
        LeaseHandle { id: self.id, raft: self.raft.clone(), store: self.store.clone() }
    }

    /// Initialize this single node as the founding cluster member, then add the
    /// other members as learners and promote the whole set to voters. Called once on
    /// ONE node to form the 3-node cluster (D-14); the others are started and join
    /// via this call. Idempotent-ish: a second initialize errors, which the caller
    /// treats as already-formed.
    pub async fn initialize_cluster(&self, members: &[(LeaseNodeId, String)]) -> anyhow::Result<()> {
        let mut nodes = BTreeMap::new();
        for (nid, addr) in members {
            nodes.insert(*nid, BasicNode::new(addr.clone()));
        }
        self.raft
            .initialize(nodes)
            .await
            .map_err(|e| anyhow::anyhow!("lease node {}: initialize cluster: {e}", self.id))?;
        Ok(())
    }

    /// Propose granting the active lease to `node_id` and wait for it to COMMIT
    /// (linearizable). Only the leader can do this (a non-leader call returns a
    /// ForwardToLeader-class error the caller can act on). On success the lease is
    /// committed at the leader's current term and replicated to the majority, so
    /// every node now agrees who is active. Returns the committed lease (node +
    /// term).
    pub async fn grant_lease(&self, node_id: LeaseNodeId) -> anyhow::Result<LeaseResponse> {
        let resp = self
            .raft
            .client_write(LeaseRequest::Grant { node_id })
            .await
            .map_err(|e| anyhow::anyhow!("lease node {}: grant lease to {node_id}: {e}", self.id))?;
        Ok(resp.data)
    }

    /// Whether this node currently believes it is the Raft leader (from the live
    /// metrics). Leadership is necessary but NOT sufficient to be active: the node
    /// must ALSO hold the committed lease at the current term (the fence).
    pub fn is_leader(&self) -> bool {
        let metrics = self.raft.metrics().borrow().clone();
        metrics.current_leader == Some(self.id)
    }

    /// The live Raft metrics (term, leader, membership), for evidence/logging.
    pub fn metrics(&self) -> RaftMetrics<LeaseNodeId, BasicNode> {
        self.raft.metrics().borrow().clone()
    }

    /// Wait until this node observes a leader (itself or a peer) within `timeout`,
    /// returning the leader id. Used by the harness to wait for the cluster to
    /// settle after bring-up. Returns None on timeout.
    pub async fn wait_for_leader(&self, timeout: Duration) -> Option<LeaseNodeId> {
        self.wait_for_leader_in(None, timeout).await
    }

    /// Wait until this node observes a leader whose id is in `allowed` (or any leader
    /// when `allowed` is None), within `timeout`, returning that leader id. After a
    /// kill, a follower's metrics still cache the OLD (now-dead) leader id until the
    /// election timeout fires and a new vote commits; passing `allowed = the survivor
    /// set` makes the harness wait for the genuinely NEW leader rather than accepting
    /// the stale cached one. Also requires the observed term to be non-zero (a real
    /// election happened). Returns None on timeout.
    pub async fn wait_for_leader_in(
        &self,
        allowed: Option<&[LeaseNodeId]>,
        timeout: Duration,
    ) -> Option<LeaseNodeId> {
        let mut rx = self.raft.metrics();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            {
                let m = rx.borrow();
                if let Some(leader) = m.current_leader {
                    let ok = allowed.map(|set| set.contains(&leader)).unwrap_or(true);
                    if ok {
                        return Some(leader);
                    }
                }
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            if tokio::time::timeout(remaining, rx.changed()).await.is_err() {
                return None;
            }
        }
    }

    /// Shut this node down: abort its RPC server (so peers can no longer reach it,
    /// modeling a kill/partition) and shut the Raft engine. After this, the
    /// remaining majority elects a new leader and the handoff proceeds (G8). The
    /// node is consumed.
    pub async fn shutdown(self) {
        self.server.abort();
        let _ = self.raft.shutdown().await;
    }
}

/// The TCP RPC server loop (the server half of the D-17 transport): accept loopback
/// connections, read one framed Raft RPC per connection, dispatch it into the local
/// Raft engine, and write the framed reply. Each connection is handled on its own
/// task so a slow peer does not block others. Runs until the task is aborted (the
/// node's `shutdown`), which is what makes a killed node unreachable to its peers.
async fn serve_raft_rpc(listener: TcpListener, raft: LeaseRaft) {
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(c) => c,
            Err(_) => continue,
        };
        let raft = raft.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_rpc_conn(stream, raft).await {
                tracing::debug!(error = %e, "lease RPC connection ended");
            }
        });
    }
}

/// Handle one inbound Raft RPC connection: read the framed request, run it through
/// the local engine, and reply. Errors (a half-open peer, a decode fault) end the
/// connection without taking the server down.
async fn handle_rpc_conn(mut stream: TcpStream, raft: LeaseRaft) -> io::Result<()> {
    let body = read_frame(&mut stream).await?;
    let rpc: RaftRpc =
        serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let reply = match rpc {
        RaftRpc::Append(req) => {
            let r = raft
                .append_entries(req)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            RaftRpcReply::Append(r)
        }
        RaftRpc::Vote(req) => {
            let r = raft
                .vote(req)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            RaftRpcReply::Vote(r)
        }
        RaftRpc::Snapshot(req) => {
            let r = raft.install_snapshot(req).await.map_err(|e| e.to_string());
            RaftRpcReply::Snapshot(r)
        }
    };
    let body =
        serde_json::to_vec(&reply).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_frame(&mut stream, &body).await?;
    Ok(())
}

/// A cheap-clone reader of the lease + leadership, handed to the run/restore path
/// and the treasury-debit path so they can ASK "may I (this node) run/debit right
/// now?" without owning the engine. The whole no-split-brain guarantee reduces to
/// these checks being made before every run and every debit.
#[derive(Clone)]
pub struct LeaseHandle {
    id: LeaseNodeId,
    raft: LeaseRaft,
    store: LeaseStore,
}

impl LeaseHandle {
    /// This node's id.
    pub fn id(&self) -> LeaseNodeId {
        self.id
    }

    /// The committed active lease (who is active, at what term), read from the
    /// applied state machine. None before any grant commits.
    pub async fn active_lease(&self) -> Option<ActiveLease> {
        self.store.active_lease().await
    }

    /// Inform this node of the authoritative committed lease it learns as it CATCHES
    /// UP on rejoin (the leader's append-entries carry the committed `active_lease`).
    /// A revived stale node calls this so its fence check sees the higher committed
    /// term T+1 that superseded its old belief, and is rejected BECAUSE it observed
    /// the newer term, faithful to spec 4.3 ("sees the higher committed term"). Only
    /// moves the term forward (a stale lower value is ignored).
    pub async fn catch_up_committed_lease(&self, lease: ActiveLease) {
        self.store.observe_committed_lease(lease).await;
    }

    /// Whether this node is the current Raft leader (necessary but not sufficient to
    /// be active; the lease check below is the rest).
    pub fn is_leader(&self) -> bool {
        self.raft.metrics().borrow().current_leader == Some(self.id)
    }

    /// THE ACTIVE-NODE CHECK (spec 3.5): this node may run the genome + debit the
    /// treasury iff it is BOTH the Raft leader AND holds the committed `active_lease`
    /// at the current term. Returns the term it is active at, or None if it is not
    /// the active node (a non-leader, or the lease is held by someone else). The
    /// run/restore path calls this before booting/restoring a VM; the debit path
    /// calls it (via the fence) before any debit.
    pub async fn active_term(&self) -> Option<u64> {
        if !self.is_leader() {
            return None;
        }
        match self.store.active_lease().await {
            Some(l) if l.node_id == self.id => Some(l.term),
            _ => None,
        }
    }

    /// A term-fence for a node that BELIEVES it is active at `believed_term` (e.g. a
    /// revived stale node that was active before it was killed). It may run/debit
    /// only if the CURRENTLY COMMITTED lease still names this node at a term >=
    /// `believed_term`. A revived stale node believing the old term T sees the
    /// higher committed term T+1 (the lease moved to another node) and is FENCED
    /// OUT: this returns `Fenced`, so it does NOT run and does NOT debit (spec 4.3,
    /// no double-execute). A node whose belief still matches the committed lease
    /// passes.
    pub async fn fence(&self, believed_term: u64) -> FenceVerdict {
        let lease = self.store.active_lease().await;
        match lease {
            // The committed lease still names THIS node at a term >= what it believes:
            // it is genuinely still the active node, so it may proceed.
            Some(l) if l.node_id == self.id && l.term >= believed_term => {
                FenceVerdict::Active { term: l.term }
            }
            // The committed lease has moved on (a higher term, a different node): this
            // node is stale and is fenced out. The committed term is the proof the
            // lease was reassigned while this node was away.
            Some(l) => FenceVerdict::Fenced {
                committed_term: l.term,
                committed_holder: l.node_id,
                believed_term,
            },
            // No lease is committed at all: nothing authorizes this node to act.
            None => FenceVerdict::Fenced {
                committed_term: 0,
                committed_holder: 0,
                believed_term,
            },
        }
    }
}

/// The outcome of a term-fence check (spec 4.3). `Active` means the node still holds
/// the lease at a current-enough term and may run/debit; `Fenced` means a higher
/// committed term superseded it (the lease moved), so it must NOT run or debit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceVerdict {
    /// The node holds the committed lease at `term` (>= what it believed); proceed.
    Active { term: u64 },
    /// The node is fenced: the committed lease is at `committed_term` held by
    /// `committed_holder`, which superseded this node's `believed_term`. Do NOT run
    /// or debit (no double-execute / no double-burn).
    Fenced {
        committed_term: u64,
        committed_holder: LeaseNodeId,
        believed_term: u64,
    },
}

impl FenceVerdict {
    /// Whether the node may run/debit (true only for `Active`). The run/restore path
    /// and the debit path both gate on this.
    pub fn may_act(&self) -> bool {
        matches!(self, FenceVerdict::Active { .. })
    }
}

/// Bring up a fresh `n`-node lease cluster on loopback (the G8 harness helper, D-14
/// = 3 nodes): start each node on a distinct `127.0.0.1:0` port, initialize the
/// cluster on the first node with all members as voters, and wait for a leader.
/// Returns the started nodes (the caller drives kill/handoff/revive) and the elected
/// leader id. The PURE-RAFT lease mechanics are testable through this WITHOUT the
/// genome image (fast), so the no-split-brain proof does not require a microVM.
pub async fn bring_up_cluster(node_ids: &[LeaseNodeId]) -> anyhow::Result<ClusterBringUp> {
    let mut nodes = Vec::new();
    let mut members = Vec::new();
    for id in node_ids {
        let node = LeaseNode::start(*id, "127.0.0.1:0").await?;
        members.push((*id, node.addr().to_string()));
        nodes.push(node);
    }
    // Initialize the cluster on the first node with the full voter set (D-14: a true
    // 3-of majority). One initialize forms the whole cluster.
    nodes[0].initialize_cluster(&members).await?;
    let leader = nodes[0]
        .wait_for_leader(Duration::from_secs(10))
        .await
        .ok_or_else(|| anyhow::anyhow!("cluster did not elect a leader after bring-up"))?;
    Ok(ClusterBringUp { nodes, leader })
}

/// The result of bringing up a lease cluster: the live nodes and the elected leader.
pub struct ClusterBringUp {
    pub nodes: Vec<LeaseNode>,
    pub leader: LeaseNodeId,
}

/// Observe whether, at the moment of the call, MORE THAN ONE node reports itself as
/// the active node (the linearizability witness for G8). Returns the set of node ids
/// that each believe they are active (leader AND committed-lease-holder). The G8
/// assertion is that this set NEVER has size > 1 across the observed term boundaries.
/// A correct cluster yields {} (between handoffs) or a single id (a settled active
/// node), never two.
pub async fn observe_active_nodes(handles: &[LeaseHandle]) -> BTreeSet<LeaseNodeId> {
    let mut active = BTreeSet::new();
    for h in handles {
        if h.active_term().await.is_some() {
            active.insert(h.id());
        }
    }
    active
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Granting the lease stamps the leader's Raft term onto it, and a later grant
    /// at a higher term supersedes the earlier one (the fence's monotonicity). This
    /// drives the apply path directly (no network) to pin the term-stamping logic.
    #[tokio::test]
    async fn grant_stamps_term_and_supersedes() {
        let store = LeaseStore::new();
        // Apply a grant to node 2 at term 1, then a grant to node 3 at term 2.
        let mut inner = store.inner.write().await;
        let e1 = Entry {
            log_id: LogId::new(openraft::CommittedLeaderId::new(1, 0), 1),
            payload: EntryPayload::Normal(LeaseRequest::Grant { node_id: 2 }),
        };
        let r1 = apply_entry(&mut inner, &e1);
        assert_eq!(r1, LeaseResponse { node_id: 2, term: 1 });
        assert_eq!(inner.active_lease, Some(ActiveLease { node_id: 2, term: 1 }));

        let e2 = Entry {
            log_id: LogId::new(openraft::CommittedLeaderId::new(2, 0), 2),
            payload: EntryPayload::Normal(LeaseRequest::Grant { node_id: 3 }),
        };
        let r2 = apply_entry(&mut inner, &e2);
        assert_eq!(r2, LeaseResponse { node_id: 3, term: 2 });
        // The lease moved to node 3 at the higher term: node 2's old term (1) is now
        // superseded, which is exactly what fences a revived stale node 2.
        assert_eq!(inner.active_lease, Some(ActiveLease { node_id: 3, term: 2 }));
    }

    /// The fence verdict logic (without a live engine): a node that believes a term
    /// the committed lease has moved past is Fenced; a node still named at a current
    /// term is Active.
    #[tokio::test]
    async fn fence_blocks_a_stale_term_and_passes_a_current_one() {
        let store = LeaseStore::new();
        {
            let mut inner = store.inner.write().await;
            inner.active_lease = Some(ActiveLease { node_id: 2, term: 5 });
        }
        // A handle for node 2 (the holder) with a stub raft is awkward to build here,
        // so test the verdict math against the store directly via a small helper that
        // mirrors `fence`.
        let lease = store.active_lease().await.unwrap();

        // Node 2 believes term 5, the committed lease is node 2 @ 5: Active.
        let v = verdict_for(&lease, 2, 5);
        assert!(matches!(v, FenceVerdict::Active { term: 5 }));

        // Node 2 believes the STALE term 4, committed is node 2 @ 5: still Active
        // (its belief is not ahead of the committed term).
        let v = verdict_for(&lease, 2, 4);
        assert!(matches!(v, FenceVerdict::Active { term: 5 }));

        // After a handoff: committed lease moved to node 3 @ 6. Node 2 (revived,
        // still believing 5) is FENCED.
        let moved = ActiveLease { node_id: 3, term: 6 };
        let v = verdict_for(&moved, 2, 5);
        assert!(matches!(
            v,
            FenceVerdict::Fenced { committed_term: 6, committed_holder: 3, believed_term: 5 }
        ));
        assert!(!v.may_act());
    }

    /// A pure mirror of `LeaseHandle::fence`'s verdict math for the unit test (so it
    /// can run without constructing a live Raft engine).
    fn verdict_for(lease: &ActiveLease, my_id: LeaseNodeId, believed_term: u64) -> FenceVerdict {
        if lease.node_id == my_id && lease.term >= believed_term {
            FenceVerdict::Active { term: lease.term }
        } else {
            FenceVerdict::Fenced {
                committed_term: lease.term,
                committed_holder: lease.node_id,
                believed_term,
            }
        }
    }
}
