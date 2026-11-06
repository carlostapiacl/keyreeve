//! keyreeve rotates API keys on your own machine.
//!
//! A recipe describes how one provider creates, checks and revokes a key. The engine runs
//! those steps so that a failure or a crash at any point leaves working keys behind.

pub mod engine;
pub mod journal;
pub mod recipe;
pub mod secret;
pub mod simulate;
pub mod store;
pub mod transport;
