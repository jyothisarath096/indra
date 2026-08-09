# Offline sync-branch recovery

The node never reorganizes a canonical finalized chain. This procedure exists
only for data directories created by versions that could commit a sync block
before seeing that block's own quorum certificate.

The node writes `sync_recovery_required.json` after expensive validation fails
at one height from three distinct authenticated validators. That diagnostic is
a stop-and-investigate signal; it is not proof by itself that local data is on
an unfinalized branch.

## Safe procedure

1. Stop the node. Do not delete, truncate, or modify its existing data directory.
2. Preserve a copy of the diagnostic and the original directory for review.
3. Obtain the network's independently trusted `genesis.toml`.
4. Choose a new, empty destination directory on the same secured machine.
5. Run:

   ```text
   indra-sync-recover <old-data-dir> <new-empty-data-dir> <trusted-genesis.toml>
   ```

6. Review the reported recovered height and any uncertified suffix. The tool
   copies only blocks whose own QC is verified either from the next block or
   from the persisted terminal QC.
7. Point a non-validator/observer process at the new directory first and let it
   synchronize normally. Compare its finalized height and tip with multiple
   independent validators.
8. Only after that review, stop the old process and start the validator using
   the new directory and its normal key configuration.

The tool refuses a non-empty destination and never rewinds the source in place.
It also refuses pruned source logs that do not contain genesis. These fail-closed
rules avoid trying to transactionally rewind block, epoch, snapshot, manifest,
and pending-pool state that older versions did not store as one rollback unit.
