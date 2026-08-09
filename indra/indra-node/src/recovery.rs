//! Offline recovery of the highest provably-finalized chain prefix.
//!
//! Recovery never rewinds a live directory. It reads an archive block log,
//! requires each copied block's own QC, and writes a new node directory.

use std::path::{Path, PathBuf};

use indra_storage::{load_last_qc, BlockStore, PruneConfig};

use crate::{
    config::NodeConfig,
    error::{NodeError, NodeResult},
    sync::{verify_direct_provisional_qc, verify_provisional_certificate, verify_sync_candidate},
    NodeEngine,
};

/// Result of rebuilding one finalized prefix into a new directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRecoveryReport {
    /// Source directory inspected.
    pub source_dir: PathBuf,
    /// Newly-created destination directory.
    pub destination_dir: PathBuf,
    /// Highest block copied only after proof of its own finality.
    pub recovered_height: u64,
    /// First source height not copied because its own QC was unavailable.
    pub first_unfinalized_height: Option<u64>,
}

/// Rebuild the highest provably-finalized prefix into a new directory.
///
/// `destination_config.data_dir` must not exist or must be empty. The caller
/// must configure the independently trusted genesis used by the source chain.
pub fn recover_finalized_prefix(
    source_dir: &Path,
    destination_config: NodeConfig,
) -> NodeResult<SyncRecoveryReport> {
    let destination_dir = destination_config.data_dir.clone();
    if destination_dir.exists()
        && std::fs::read_dir(&destination_dir)
            .map_err(indra_storage::StorageError::from)?
            .next()
            .is_some()
    {
        return Err(NodeError::InvalidConfiguration {
            detail:
                "sync recovery destination must be new or empty; in-place recovery is forbidden"
                    .to_string(),
        });
    }
    std::fs::create_dir_all(&destination_dir).map_err(indra_storage::StorageError::from)?;

    let mut source = BlockStore::open(source_dir.join("blocks.log"), PruneConfig::archive())?;
    if source.lowest_height() > 0 {
        return Err(NodeError::InvalidConfiguration {
            detail: "offline recovery requires an archive block log containing genesis".to_string(),
        });
    }
    let source_next = source.next_height();
    let mut destination = NodeEngine::init(destination_config)?;
    let mut recovered_height = destination.height();
    let mut first_unfinalized_height = None;

    while recovered_height.saturating_add(2) < source_next {
        let height = recovered_height.saturating_add(1);
        let block = source.get(height)?;
        let carrier = source.get(height.saturating_add(1))?;
        let prepared = verify_sync_candidate(&block, &destination.state, 0)?;
        verify_provisional_certificate(&block, &carrier, &destination.state).map_err(|error| {
            NodeError::InvalidConfiguration {
                detail: format!(
                    "source chain is not recoverable at pair {height}/{}: {error:?}",
                    height.saturating_add(1)
                ),
            }
        })?;
        destination.commit_prepared_sync_block(&block, prepared)?;
        recovered_height = height;
    }

    if recovered_height.saturating_add(1) < source_next {
        let height = recovered_height.saturating_add(1);
        let block = source.get(height)?;
        let prepared = verify_sync_candidate(&block, &destination.state, 0)?;
        let terminal_qc = load_last_qc(&source_dir.join("state"))?;
        if terminal_qc.as_deref().is_some_and(|qc_bytes| {
            verify_direct_provisional_qc(&block, qc_bytes, &destination.state).is_ok()
        }) {
            destination.commit_prepared_sync_block(&block, prepared)?;
            recovered_height = height;
        } else {
            first_unfinalized_height = Some(height);
        }
    }

    Ok(SyncRecoveryReport {
        source_dir: source_dir.to_path_buf(),
        destination_dir,
        recovered_height,
        first_unfinalized_height,
    })
}
