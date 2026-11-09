//! keyreeve rotates API keys on your own machine.
//!
//! A recipe describes how one provider creates, checks and revokes a key. The engine runs
//! those steps so that a failure or a crash at any point leaves working keys behind.

pub mod catalog;
pub mod engine;
pub mod history;
pub mod identify;
pub mod inventory;
pub mod journal;
pub mod keybook;
pub mod keys;
pub mod migrate;
pub mod places;
pub mod providers;
pub mod proxy;
pub mod recipe;
pub mod rotate;
pub mod schedule;
pub mod script;
pub mod secret;
pub mod sigv4;
pub mod simulate;
pub mod ssh;
pub mod store;
pub mod transport;
pub mod verify;
