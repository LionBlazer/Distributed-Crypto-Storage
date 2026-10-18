//! PUBLIC NONSECRET integration fixture. Expected plaintext is a post-verification test oracle only.
use super::super::super::journal::{ProjectionHistory, projection_input};
use super::*;
use bfv_query_core::{Geometry, Owner};
use std::time::Instant;

pub(super) struct Fixture {
    pub(super) owner: Owner,
    pub(super) expected: Expected,
    pub(super) history: ProjectionHistory,
    pub(super) bundle: peer_runtime::RawBundle,
    pub(super) product: super::super::fixture::PublicProduct,
    pub(super) oracle: Vec<u64>,
}
impl Fixture {
    pub(super) fn new(limit: u8, other_limit: u8) -> Result<Self> {
        if !matches!(limit, 0 | 1) || !matches!(other_limit, 1 | 4) {
            return Err(Error::Binding);
        }
        let generation = Instant::now();
        let (history, encoded) = projection_input(limit, other_limit)?;
        let bundle = history.bundle()?;
        let (owner, setup) = Owner::generate(Geometry::Rows16)?;
        let product =
            super::super::fixture::produce_for_owner(&owner, &setup, encoded, generation)?;
        // Pin the actual complete public output claim; prepare re-verifies its
        // actual ten components rather than treating this value as proof authority.
        let verified = super::super::verify(
            &setup,
            &product.anchor,
            &product.expected,
            &product.encoding_frame,
            &product.prerequisites(),
            &product.evidence,
        )?;
        let statement = verified.statement().clone();
        let binding = Binding {
            request: product.expected.encoding.formation_source().request,
            query_id: [0x39; 16],
            target: bundle.target_version().map_err(|_| Error::Binding)?,
            setup_id: product.anchor.full_setup_id(),
            parameters: setup.update_parameters()?.to_bytes()?,
            freshness: history.policy(),
        };
        let expected = Expected::new(
            product.expected.clone(),
            statement,
            product.anchor.clone(),
            history.context().clone(),
            binding,
            &product.setup_bytes,
        )?;
        // Source PUBLIC fixture: sparse candidates [0,2,3]; held0, OFFSET-owned2,
        // returned3 has amount255. This vector NEVER prepares a peer request.
        let mut oracle = vec![0; 8192];
        if limit == 1 && other_limit == 1 {
            oracle[4096] = 255;
            oracle[512] = 1;
        }
        Ok(Self {
            owner,
            expected,
            history,
            bundle,
            product,
            oracle,
        })
    }
    #[cfg(test)]
    pub(super) fn prepare(&self) -> Result<Prepared> {
        prepare(
            &self.expected,
            self.history.journal(),
            &self.product.encoding_frame,
            &self.product.prerequisites(),
            &self.product.evidence,
        )
    }
}
pub(super) fn gate(executable: &std::path::Path) -> Result<()> {
    let total = Instant::now();
    let Fixture {
        owner,
        expected,
        history,
        bundle,
        product,
        oracle,
    } = Fixture::new(1, 1)?;
    let prepared = prepare(
        &expected,
        history.journal(),
        &product.encoding_frame,
        &product.prerequisites(),
        &product.evidence,
    )?;
    let input_bytes = serde_json::json!({"setup":product.setup_bytes.len(),
        "encoding":product.encoding_frame.len(),"key":product.key.len(),
        "bases":product.frames.each_ref().map(Vec::len),"formation":product.evidence.len()});
    drop(product); // No ten-proof cache, Backend, trace or private producer borrow crosses I/O.
    prepared.check_before_io(&expected, history.journal())?;
    let input_ms = total.elapsed().as_secs_f64() * 1000.0;
    let remote_start = Instant::now();
    let mut peer = crate::opening::peer_process::ProcessPeer::start(executable, &bundle)?;
    let peer_pid = peer.pid();
    let checked = prepared.run_remote(&expected, history.journal(), &peer.remote)?;
    let decoded = owner.decrypt_public_select_unverified_for_experiment(
        checked.request(),
        checked.encrypted_response(),
    )?;
    if decoded != oracle {
        return Err(Error::Binding);
    }
    let request_id = peer.last_request_id()?;
    let completion = peer.finish_on_eof()?;
    let identity = checked
        .identity()
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect::<String>();
    println!(
        "{}",
        serde_json::json!({
            "stage":"verified_registry200_peer_projection",
            "worker":"independent_dcs_peer_process","peer_pid":peer_pid,
            "owner_pid":std::process::id(),"peer_exit_code":completion.code,
            "peer_stdout":completion.stdout,"peer_stderr":completion.stderr,
            "rpc_request_id":request_id,"input_binding":identity,
            "elapsed_ms":total.elapsed().as_secs_f64()*1000.0,
            "input_generation_and_admission_ms":input_ms,
            "process_rpc_verification_decryption_and_eof_ms":remote_start.elapsed().as_secs_f64()*1000.0,
            "input_component_bytes":input_bytes,"encrypted_response_bytes":checked.encrypted_response().len(),
            "operation":format!("{:?}",checked.checked().operation()),
            "resolved_head":checked.resolved().block,"all8192_oracle_match":true,"eof_cleanup":true,
            "accepted_journal_history":true,"public_projection":true,"live_sql_grant":false,
            "agreed_finality":false,"writer_fence":false,"composed_128_claim":false
        })
    );
    Ok(())
}
