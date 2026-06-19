//! In-process end-to-end pipeline tests for the Aegis platform.
//!
//! This crate has no library surface of its own. The real work lives in the
//! integration tests under `tests/`, which build a genuine [`aegis_core`] plugin
//! host, load the two central processors (`plugin-agent-detect` and
//! `plugin-scoring`) plus a capturing sink, and drive synthetic behavioral
//! telemetry through the **real** event bus to prove the
//! telemetry → detection → scoring → alert pipeline end-to-end.
