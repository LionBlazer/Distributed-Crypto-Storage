# SQL capability guard coverage

Status: the [native refusal/raw-protocol gate](SQL-CAPABILITY-VALIDATION.md) passed
143 tests, two compile-fail doctests and two repository contract tests. One
retained SQL-success test was actually run and FAILED at the guard. The full SQL
suite is **not green**; none of the 61 old SQL-success scenarios is resolved by
the raw tests below.

The SQL facade previously accepted genuine arithmetic on an owner-selected set.
It lacked the peer FHE predicate/completeness and source-to-ciphertext formation
relations, and Jobs mutations lacked output-to-new-AEAD/index linkage. These
acceptance expectations are invalid under REQUIREMENTS 2 and 11–13.

The old SQL-success integration bodies currently remain UNCHANGED. Their
complete execution remains a blocking follow-up for the SQL goal. The admission
guard is a validated policy repair, not a passing full SQL implementation. These
cases must not be hidden behind `ignore`, a bypass flag, a renamed raw SQL executor, or a fabricated
proof. The exact original names below record the affected composition coverage.
Cancellation, parallel scheduling, sparse access, aggregate capacity and mutation
retry scenarios must be restored at the complete SQL boundary once its actual
proof relations exist. A refusal test does not replace those future assertions.

## Current owning replacements

- `proved_sql::sql_capabilities::every_unproved_sql_operation_rejects_without_rpc_publication_or_cached_answers`:
  actual OS peer, empty and nonempty provisioned source, SELECT/aggregate/UPDATE/
  INSERT, FALSE/TRUE, LIMIT 0, zero delta, offline peer, unchanged heads and no RPC.
- `proved_sql::sql_capabilities::whole_script_preflight_prevents_database_creation_and_all_earlier_statements`:
  real peer remains untouched when CREATE precedes an unsupported statement.
- `session::capability_tests::typed_select_capability_rejects_before_synchronization_or_source_io`:
  genuine imported encrypted catalog, typed projection, NULL/order/window syntax,
  no request and unchanged version.
- Private Session tests retain both old pending mutation records and refuse resume
  before synchronization/publication. The retained bytes are not advertised as a
  valid or recoverable SQL transition.
- Server tests use genuine checked arithmetic and valid owner signatures, then
  require Jobs mutation rejection during candidate validation and durable replay.
  Raw arithmetic proof forgery checks remain at `check_job`.

## Executed additive raw protocol coverage

All five tests below passed against genuine encrypted operations. The first two
launch actual OS processes; the other three exercise the production private RPC
scheduler over actual TLS servers. Existing integration bodies were preserved.

- `process_transport::raw_proof_failures::raw_prove_cancellation_interrupts_receipt_and_fresh_scope_verifies_the_next_proof`:
  actual Addition proofs before/after RequestSent and ReplyReceived interruption,
  independent fresh scopes, exact ciphertext custody and no publication.
- `process_transport::raw_proof_failures::raw_prove_explicit_holder_resubmission_uses_healthy_replica_and_all_corrupt_copies_fail`:
  Store/Copy, physical damage, explicit healthy-holder resubmission and all-lost
  refusal. This is not automatic Session failover.
- `query_rpc::raw_tests::interrupted_raw_reply_does_not_try_another_holder_and_fresh_scope_completes`:
  actual ByteSelect reply interruption, no alternative-holder RPC, then a genuine
  fresh proof and checked byte completion.
- `query_rpc::raw_tests::damaged_preferred_holder_falls_back_but_loss_of_both_cannot_reuse_a_checked_reply`:
  production Requests fallback, retained verified reply/cache, then both damaged
  holders reject in both the current and a fresh query scope.
- `query_rpc::raw_tests::required_raw_job_loss_returns_no_prefix_and_joins_the_successful_worker`:
  two predetermined raw jobs, one actual verified/completed proof, a required
  missing object, no successful prefix and joined admitted work.

These preserve specific cancellation, custody and required-job failure boundaries.
They do not restore SQL selection/completeness, typed windows/order/NULL behavior,
global aggregates, final freshness or atomic/exactly-once SQL mutation recovery.
Do not subtract five from the 61 retained SQL scenarios or label them passed.

## Preserved independent boundaries

The raw Core/compact-query BFV tests, `bfv-query-proof` genuine and hostile proofs,
`process_transport::separate_processes_execute_real_fhe_and_copy_ciphertext_without_owner_keys`,
`process_transport::real_disk_tampering_and_quota_failures_never_return_cached_owner_data`,
the exact-page and static-read tests,
`process_transport::padded_delta_rpc_requires_owner_and_recovers_exact_durable_ciphertext_after_lost_ack_and_restart`,
`support::compute_custody`, `support::ciphertext_preflight` and
`support::borrowed_custody` remain unchanged. They cover their arithmetic, custody,
authorization, quota and corruption contracts; they do not certify SQL selection.
Private typed-index parser/order tests and sql-plan grammar tests remain unchanged.
The old application-policy rejection, permissionless signature/state rejection,
TLS connection admission, listener shutdown, malformed import and locking-plan
refusal remain owning tests.

## Explicit inventory

Each affected name below depends on an SQL success that is now unavailable.
Its test body is retained pending an actual coverage-preserving port.
Tests identified as retained keep their independent provisioning, parser,
authorization or locking boundary. Raw arithmetic assertions are never converted
to unconditional acceptance/rejection stubs.

### apps/dcs-peer/tests/proved_sql.rs

- Affected SQL composition; unchanged test body, migration pending: `zero_delta_update_counts_matched_rows_after_real_proofs_without_publishing_new_images`.
- Affected SQL composition; unchanged test body, migration pending: `one_batch_fills_a254_row_shard_once_and_a255_row_shard_rejects_without_store`.
- Affected SQL composition; unchanged test body, migration pending: `a_cancelled_later_batch_proof_leaves_all_shards_unpublished_and_retry_is_one_commit`.
- Affected SQL composition; unchanged test body, migration pending: `immutable_mutation_profile_rejection_never_stores_or_creates_a_sticky_pending_batch`.
- Retained: `a_real_peer_rejects_initializing_an_old_application_policy_with_the_q2_aggregate_contract`.
- Affected SQL composition; unchanged test body, migration pending: `proved_select_insert_update_survive_a_process_loss_and_journal_restart`.
- Affected SQL composition; unchanged test body, migration pending: `later_shard_overflow_never_publishes_any_earlier_staged_update`.
- Affected SQL composition; unchanged test body, migration pending: `interrupted_confirmation_resumes_the_original_write_without_applying_it_twice`.
- Affected SQL composition; unchanged test body, migration pending: `real_peers_prove_count_sum_and_empty_sql_null_over_complete_shards`.
- Affected SQL composition; unchanged test body, migration pending: `q2_real_peers_aggregate_5119_and_5120_asymmetric_rows_with_partial_and_empty_bands`.
- Affected SQL composition; unchanged test body, migration pending: `aggregate_capacity_failure_on_one_shard_returns_no_prefix_and_publishes_nothing`.
- Affected SQL composition; unchanged test body, migration pending: `select_sends_proof_work_to_two_real_peers_before_reading_either_reply`.
- Affected SQL composition; unchanged test body, migration pending: `cancelling_both_select_workers_preserves_the_next_query`.
- Affected SQL composition; unchanged test body, migration pending: `update_proves_both_shards_concurrently_before_storing_any_new_copy`.
- Affected SQL composition; unchanged test body, migration pending: `concurrent_update_workers_queue_proofs_on_the_same_surviving_peer`.
- Affected SQL composition; unchanged test body, migration pending: `million_row_private_index_crosses_real_custody_frames_and_agreed_update_restore`.
- Affected SQL composition; unchanged test body, migration pending: `proved_update_keeps_frozen_delta_roles_on_quota_failure_and_preplans_full_for_new_replicas`.
- Affected SQL composition; unchanged test body, migration pending: `a_known_holder_endpoint_alias_is_rejected_before_proof_or_full_store`.
- Affected SQL composition; unchanged test body, migration pending: `million_matching_rows_with_explicit_limit_use_real_proofs_and_the_same_static_source_frames`.
- Affected SQL composition; unchanged test body, migration pending: `limited_shard_prefixes_merge_by_global_ordinal_with_uneven_matching_counts`.
- Affected SQL composition; unchanged test body, migration pending: `fixed_select_fetches_identical_static_images_for_projections_limits_absent_and_false_predicates`.
- Affected SQL composition; unchanged test body, migration pending: `interrupted_static_image_does_not_retry_an_uncancelled_replica_and_next_query_recovers`.
- Affected SQL composition; unchanged test body, migration pending: `cancellation_after_the_real_proof_reply_refuses_static_select_before_final_freshness_completion`.
- Affected SQL composition; unchanged test body, migration pending: `one_staged_nonce_survives_genuine_update_replication_copy_and_reopen`.

### apps/dcs-peer/tests/proved_faults.rs

- Affected SQL composition; unchanged test body, migration pending: `corrupted_physical_copy_falls_back_to_a_real_replica_but_losing_both_copies_never_uses_cached_rows`.
- Affected SQL composition; unchanged test body, migration pending: `limit_one_rejects_a_missing_later_shard_after_a_valid_first_shard_proof`.
- Affected SQL composition; unchanged test body, migration pending: `all_processes_offline_prevent_proved_reads_and_writes_after_a_successful_read`.
- Retained: `permissionless_identity_cannot_reconfigure_another_operator_or_publish_a_forged_state_with_valid_work`.

### crates/storage-client/tests/relational.rs

- Retained: `stalled_handshakes_cannot_exceed_connection_admission_or_poison_later_rpcs`.
- Retained: `locally_stopping_an_idle_listener_requires_no_further_client_connection`.
- Affected SQL composition; unchanged test body, migration pending: `cancelling_a_proved_read_interrupts_its_rpc_without_poisoning_the_next_query`.
- Affected SQL composition; unchanged test body, migration pending: `stopping_write_publication_retains_the_exact_mutation_for_single_application_recovery`.
- Affected SQL composition; unchanged test body, migration pending: `typed_tables_stream_more_than_128_rows_with_real_proofs_and_complete_private_indices`.
- Affected SQL composition; unchanged test body, migration pending: `proved_text_projection_preserves_spaces_and_uses_the_column_padding_rules`.
- Affected SQL composition; unchanged test body, migration pending: `proved_projection_uses_postgresql_null_order_before_applying_limit`.
- Affected SQL composition; unchanged test body, migration pending: `proved_row_windows_skip_after_ordering_and_extend_only_the_last_peer_group`.
- Affected SQL composition; unchanged test body, migration pending: `damaged_replicas_cannot_silently_omit_rows_or_return_an_unproved_empty_result`.
- Retained: `malformed_owner_tables_are_rejected_before_creating_keys_or_writing_peer_state`.
- Retained: `typed_catalog_lock_syntax_cannot_enter_ordinary_projection_or_network_synchronization`.

### apps/dcs-peer/tests/support/boolean_predicates.rs

- Affected SQL composition; unchanged test body, migration pending: `boolean_reads_null_aggregates_and_full_updates_complete_real_peer_proofs`.
- Affected SQL composition; unchanged test body, migration pending: `entire_union_hits_materialization_budget_before_any_proof_or_write`.
- Affected SQL composition; unchanged test body, migration pending: `noncontiguous_static_update_uses_one_delta_and_preserves_the_complete_encrypted_identity_tail`.
- Affected SQL composition; unchanged test body, migration pending: `historical_unverified_network_adapter_rejects_disjoint_sets_before_any_rpc`.

### apps/dcs-peer/tests/support/mutation_cancellation.rs

- Affected SQL composition; unchanged test body, migration pending: `an_interrupted_update_proof_never_uses_an_uncancelled_holder_or_publishes_a_mutation`.

### apps/dcs-peer/tests/support/received_version_import.rs

- Affected SQL composition; unchanged test body, migration pending: `final_full_version_import_rejects_a_corrupt_holder_and_accepts_the_exact_healthy_replica`.

### apps/dcs-peer/tests/support/select_pagination.rs

- Affected SQL composition; unchanged test body, migration pending: `interleaved_shards_apply_one_global_offset_after_complete_prefix_proofs`.
- Affected SQL composition; unchanged test body, migration pending: `all_null_empty_and_beyond_end_windows_still_use_every_actual_shard_proof`.
- Affected SQL composition; unchanged test body, migration pending: `cancellation_after_a_real_window_proof_refuses_completion_and_the_same_query_recovers`.

### apps/dcs-peer/tests/support/static_aggregate.rs

- Affected SQL composition; unchanged test body, migration pending: `sparse_and_empty_aggregates_share_the_row_select_static_frame_on_a_million_row_shard`.
- Affected SQL composition; unchanged test body, migration pending: `cancellation_after_a_real_aggregate_proof_refuses_final_completion_and_next_query_recovers`.
- Affected SQL composition; unchanged test body, migration pending: `interrupted_aggregate_image_never_uses_an_uncancelled_replica`.

### apps/dcs-peer/tests/support/static_update.rs

- Affected SQL composition; unchanged test body, migration pending: `million_row_update_reads_static_source_preserves_identity_tail_and_finishes_with_full_custody`.
- Affected SQL composition; unchanged test body, migration pending: `interrupted_static_update_source_does_not_try_an_uncancelled_holder_or_publish`.
- Affected SQL composition; unchanged test body, migration pending: `corrupt_identity_tail_after_delta_ack_keeps_exact_pending_and_retry_reuses_the_stored_object`.
- Affected SQL composition; unchanged test body, migration pending: `a_preplanned_new_replica_requires_full_source_and_shares_one_target_with_delta_holders`.
- Affected SQL composition; unchanged test body, migration pending: `overflow_on_one_static_shard_rejects_the_whole_proved_update_before_any_store`.

### apps/dcs-peer/tests/support/synchronization_cancellation.rs

- Affected SQL composition; unchanged test body, migration pending: `interrupted_journal_reply_stops_read_and_new_mutation_without_marking_a_holder_unavailable`.
- Affected SQL composition; unchanged test body, migration pending: `interrupted_pending_journal_reply_retains_the_stored_write_before_any_mining`.
- Affected SQL composition; unchanged test body, migration pending: `interrupted_full_version_reply_never_imports_from_an_uncancelled_replica_and_retry_reuses_the_write`.
- Affected SQL composition; unchanged test body, migration pending: `interrupted_mined_reply_never_tries_another_miner_and_retry_remines_only_the_retained_transition`.
- Affected SQL composition; unchanged test body, migration pending: `interrupted_second_publication_reply_retains_the_exact_block_even_after_a_prior_durable_ack`.

### apps/dcs-peer/tests/support/typed_sql.rs

- Affected SQL composition; unchanged test body, migration pending: `typed_300_row_select_accepts_complete_ordered_proved_bytes`.
- Affected SQL composition; unchanged test body, migration pending: `typed_postgresql_windows_prove_offset_empty_and_null_peer_groups_after_holder_loss`.
- Affected SQL composition; unchanged test body, migration pending: `typed_byte_workers_use_two_holders_and_preserve_cross_chunk_order`.
- Affected SQL composition; unchanged test body, migration pending: `stopped_typed_holder_is_attempted_once_per_query_and_survivor_proves_every_block`.
- Affected SQL composition; unchanged test body, migration pending: `cancelling_a_later_typed_block_joins_workers_and_never_falls_back_after_interrupted`.
- Affected SQL composition; unchanged test body, migration pending: `pg_case_distinct_catalog_names_use_real_proofs_and_bad_binding_sends_no_rpc`.

## Script and GUI expectations

Script syntax/token limits are tested directly without admitting SQL execution.
The former script-success assertions were replaced at their owning lexical/parser
boundary, not retained as executable SQL admission:

- `bootstrap_script_preserves_create_and_proved_select_as_distinct_operations`:
  whole-script refusal before CREATE.
- `comments_and_multi_row_insert_preserve_every_literal_and_source_statement` and
  `boolean_script_preserves_signed_bounds_null_semantics_and_compound_tokens`:
  lexical comment/compound-token checks and the unchanged sql-plan grammar suite.
- `pagination_preserves_nulls_and_window_order_and_rejects_a_later_duplicate_before_execution`
  and `aggregate_statements_are_planned_without_a_plaintext_fallback`:
  unchanged sql-plan tests; SQL acceptance explicitly refused.
- `inserted_row_budget_counts_all_batches_independently_of_statement_count` and
  `maximum_literal_batch_fits_the_statement_byte_limit_without_token_space_inflation`:
  direct bounded INSERT parser/literal checks, with script INSERT unavailable.
- `statement_budget_counts_source_statements_including_an_unterminated_last_one`:
  the same script limit using CREATE-only statements.
- `malformed_later_tuple_rejects_the_whole_script_before_creation`,
  `unsupported_later_statement_rejects_the_entire_plan_before_creation` and
  `script_limits_and_unsupported_comment_forms_reject_before_execution`:
  unsupported lexical/source forms plus whole-script refusal.
- `missing_table_and_duplicate_create_never_call_the_creator` and
  `failed_creation_keeps_the_workspace_empty_and_reports_the_actual_error`:
  duplicate CREATE preflight and CREATE-only actual creator failure.

CREATE-only provisioning and creator failure remain supported. A mixed script is
rejected as a whole before CREATE. The process GUI's old SQL-success/recovery
opt-in cases also remain unchanged pending a coverage-preserving port to
capability refusal, provisioning, import preservation and worker-result recovery. Their historical accepted SQL
results are no longer a present capability. UI presentation-only tests and the
historical local LabEngine tests are unchanged.

## Breaking durable-history behavior

The original Jobs application identifier, wire tags, signatures, disk namespace
and caps remain unchanged. Nevertheless, previously admitted Jobs INSERT/UPDATE
blocks now fail the shared verifier on import/reopen. There is no migration,
fallback, alternate owner-replacement application or receipt exemption. Empty
confirmations, initial encrypted provisioning, raw custody/Prove/Evaluate and the
separate Registry200 control verifier remain distinct. This is a deliberate
fail-closed compatibility break, not automatic recovery of old SQL mutations.

## Remaining coverage work

- Custody corruption, exact address/head binding, Copy and quota: keep the existing
  `process_transport` page/static-image/tampering tests and `compute_custody`.
  Additional former SQL fixture steps can use actual `RawBundle`, `Store`,
  `FetchVersion`, `Copy` and `StoreDelta`, without a Session SQL call.
- Lost acknowledgement and restart of ciphertext replacement: the existing
  `padded_delta_rpc_requires_owner_and_recovers_exact_durable_ciphertext_after_lost_ack_and_restart`
  remains the supported protocol assertion. It does not imply that a SQL mutation
  or pending SQL authorization can resume.
- Interrupted proof RPCs and concurrent heavy work: keep actual raw `Prove` and
  `RequestControl`/frame-observation tests plus the server's heavy-permit tests.
  Port an old cancellation gate only with a genuine raw request/verification and
  the same cancellation/next-request oracle; do not merely replace it by an error
  assertion at the SQL guard.
- Arithmetic overflow and old/new source authentication: the unchanged
  compact-query tests `multi_page_update_has_fresh_nonces_preserved_index_suffix_no_growth_and_global_overflow`,
  `either_changed_head_rejects_pending_results_and_public_evaluator_clones_share_keys`
  and `in_bounds_public_echo_after_genuine_addition_never_authorizes_any_write`
  retain their owner/arithmetic boundary. A global network SQL overflow/atomic
  publication assertion remains deferred until the full relation is available.
- Signature, work and stale/reorganized Journal behavior remain tested by the
  version-journal and distinct Registry200 admission suites. They cannot be
  advertised as distributed SQL finality or complete Source predicate proofs.
- Typed ordering, NULLs, padding and windows retain their relational-types/private
  index unit tests. Genuine peer FHE predicate/order/completeness proof composition
  is still missing, so the old accepted typed SELECT oracle cannot be ported by
  calling owner inspection and labelling it a query result.

The five additive ports above were executed; the additional possibilities in this
section remain future work. No old SQL-suite failure has been marked passed. The
supported protocol exercises and deferred SQL-only compositions stay separate.


## Automatic review constraints retained for integration

Three rejected actions were not applied:

1. Restoring the historical Database SQL API's old Evaluate-then-reject path was
   rejected as a possible fail-closed bypass. The stricter pre-I/O guard is kept.
2. Replacing the large proved_sql acceptance suite with a small refusal suite
   was rejected because it removed owning custody/cancellation/replication/
   freshness/fault coverage.
3. Repeating that consolidation after adding this explicit inventory was also
   rejected because an inventory alone does not port the actual supported
   protocol exercises.

No alternate tool, ignored-test change or SQL bypass was used. Production guards,
independent rejection tests and the five additive raw ports proceeded. The old
SQL suites were retained; their concrete remaining impact is recorded above.
Supported protocol coverage cannot resolve the absent SQL composition. SQL-only
success assertions remain unavailable rather than passed; the bounded native
results are linked at the start of this record.
