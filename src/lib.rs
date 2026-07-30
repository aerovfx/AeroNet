//! Core protocol primitives for AeroNet.
//!
//! Created by VietChung. See the repository's `AUTHORS.md` for author and
//! project links.

pub mod capability;
pub mod identity;
pub mod protocol;
pub mod storage;
pub mod transport;

pub use capability::{Capability, CapabilityAction};
pub use identity::{resolve_passphrase, AgentId, Identity};
pub use protocol::{AuthChallenge, AuthProof, Envelope, MessageKind, Payload, TaskContract};
pub use transport::NoiseSession;
