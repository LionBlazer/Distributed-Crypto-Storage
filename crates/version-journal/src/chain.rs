use std::collections::BTreeMap;

use num_bigint::BigUint;

use crate::{
    Body, Error, Genesis, HEADER_BYTES, Hash, Header, ProtocolProfile, Result, ShardState, Target,
    TransitionStatement, TransitionVerifier, hash, state_root,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadRef {
    pub genesis: Hash,
    pub database: [u8; 16],
    pub block: Hash,
    pub height: u64,
    pub state_root: Hash,
}

/// Policies refer to the currently validated, sufficiently buried branch.
/// LatestConfirmed means this synchronizer's branch, conditional on honest network
/// reachability. It cannot detect an eclipse or certify globally newest data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    Exact(HeadRef),
    AtLeast(HeadRef),
    LatestConfirmed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reorganization {
    pub common_ancestor: Hash,
    /// Old tip to fork point, excluding the common ancestor.
    pub detached: Vec<Hash>,
    /// Fork point to new tip, excluding the common ancestor.
    pub attached: Vec<Hash>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportOutcome {
    pub block: Hash,
    pub previous_tip: Hash,
    pub current_tip: Hash,
    pub reorganization: Option<Reorganization>,
}

#[derive(Clone)]
struct Node {
    header: Option<Header>,
    cumulative_work: BigUint,
    state: Option<Vec<ShardState>>,
    body: Option<Vec<u8>>,
    invalid: bool,
}

/// Owns a bounded fork graph. Reaching a resource cap rejects new data; it never
/// silently drops ancestry needed by read-after-write tokens. No peer identity
/// enters work validation or fork choice.
pub struct Journal {
    genesis: Genesis,
    id: Hash,
    nodes: BTreeMap<Hash, Node>,
    accounted_bytes: u64,
    header_tip: Hash,
    validated_tip: Hash,
}
impl Journal {
    pub fn new(genesis: Genesis) -> Result<Self> {
        genesis.validate()?;
        let id = genesis.id()?;
        let accounted_bytes =
            genesis.encode()?.len() as u64 + genesis.initial_shards.len() as u64 * 232 + 512;
        if accounted_bytes > genesis.profile.max_journal_bytes {
            return Err(Error::ResourceLimit);
        }
        let mut nodes = BTreeMap::new();
        nodes.insert(
            id,
            Node {
                header: None,
                cumulative_work: BigUint::from(0u8),
                state: Some(genesis.initial_shards.clone()),
                body: None,
                invalid: false,
            },
        );
        Ok(Self {
            genesis,
            id,
            nodes,
            accounted_bytes,
            header_tip: id,
            validated_tip: id,
        })
    }
    pub fn genesis(&self) -> &Genesis {
        &self.genesis
    }
    pub fn genesis_id(&self) -> Hash {
        self.id
    }
    pub fn profile(&self) -> &ProtocolProfile {
        &self.genesis.profile
    }
    pub fn header_count(&self) -> usize {
        self.nodes.len() - 1
    }
    /// Conservative payload/state/container accounting, not an OS RAM guarantee.
    pub fn accounted_bytes(&self) -> u64 {
        self.accounted_bytes
    }
    pub fn genesis_head(&self) -> HeadRef {
        self.head(self.id)
    }
    pub fn header(&self, id: Hash) -> Option<&Header> {
        self.nodes.get(&id)?.header.as_ref()
    }
    pub fn body(&self, id: Hash) -> Option<&[u8]> {
        self.nodes.get(&id)?.body.as_deref()
    }
    /// Topological order for bounded synchronization, including validated forks.
    /// References borrow the journal; proof bodies are not duplicated here.
    pub fn validated_blocks(&self) -> Vec<(&Header, &[u8])> {
        let mut blocks: Vec<_> = self
            .nodes
            .values()
            .filter(|n| !n.invalid && n.state.is_some())
            .filter_map(|n| Some((n.header.as_ref()?, n.body.as_deref()?)))
            .collect();
        blocks.sort_unstable_by(|(a, _), (b, _)| {
            a.height.cmp(&b.height).then_with(|| a.id().cmp(&b.id()))
        });
        blocks
    }
    /// Exact validated state for protocol processing. This does not assert
    /// confirmation or freshness; clients must first resolve their policy.
    pub fn validated_shards(&self, head: HeadRef) -> Result<&[ShardState]> {
        self.check_reference(head)?;
        self.nodes
            .get(&head.block)
            .and_then(|n| n.state.as_deref())
            .ok_or(Error::BodyUnavailable)
    }
    /// Observed strongest non-invalid header, even if its body is unavailable.
    /// This does not return an accepted database head.
    pub fn best_header(&self) -> Hash {
        self.best(false)
    }
    /// Validated does not mean confirmed. Use resolve for client acceptance.
    pub fn best_validated(&self) -> HeadRef {
        self.head(self.best(true))
    }
    pub fn cumulative_work(&self, id: Hash) -> Result<BigUint> {
        self.nodes
            .get(&id)
            .filter(|n| !n.invalid)
            .map(|n| n.cumulative_work.clone())
            .ok_or(Error::UnknownHead)
    }
    pub fn next_target(&self, parent: Hash) -> Result<Target> {
        let node = self.nodes.get(&parent).ok_or(Error::UnknownParent)?;
        if node.invalid {
            return Err(Error::InvalidAncestor);
        }
        let height = self
            .height(parent)
            .checked_add(1)
            .ok_or(Error::InvalidHeight)?;
        let interval = u64::from(self.profile().retarget_interval);
        if height == 1 {
            return Ok(self.profile().initial_target);
        }
        let old = node.header.as_ref().ok_or(Error::InvalidHeight)?.target;
        if (height - 1) % interval != 0 {
            return Ok(old);
        }
        let start = self.ancestor_at(parent, height - 1 - interval)?;
        // Saturating subtraction prevents malicious valid timestamps from creating
        // an unsigned underflow; the elapsed span is clamped by the pinned rule.
        let elapsed = self.timestamp(parent).saturating_sub(self.timestamp(start));
        let expected = self.profile().block_spacing_secs * interval;
        Ok(old.retarget(elapsed, expected, self.profile().pow_limit))
    }
    /// Constructs only a candidate. It neither validates proof nor publishes state.
    pub fn candidate(&self, parent: Hash, body: &Body, timestamp: u64) -> Result<Header> {
        let parent_node = self.nodes.get(&parent).ok_or(Error::UnknownParent)?;
        let previous = parent_node.state.as_ref().ok_or(Error::BodyUnavailable)?;
        if parent_node.invalid {
            return Err(Error::InvalidAncestor);
        }
        let wire = body.encode(self.profile())?;
        let next = self.apply_changes(parent, previous, body)?;
        Ok(Header {
            genesis: self.id,
            parent,
            height: self
                .height(parent)
                .checked_add(1)
                .ok_or(Error::InvalidHeight)?,
            timestamp,
            target: self.next_target(parent)?,
            body_hash: hash(&wire),
            state_root: state_root(&next),
            nonce: 0,
        })
    }
    /// Verifies a candidate's complete body before spending mining work. This
    /// neither mines nor publishes/accepts any database state.
    pub fn verify_candidate<V: TransitionVerifier + ?Sized>(
        &self,
        parent: Hash,
        body: &Body,
        verifier: &V,
    ) -> Result<Hash> {
        let header = self.candidate(parent, body, self.timestamp(parent))?;
        let wire = body.encode(self.profile())?;
        self.prepare_state(&header, &wire, verifier)?;
        Ok(header.state_root)
    }
    pub fn import_header(&mut self, header: Header, now: u64) -> Result<Hash> {
        let id = self.check_header(&header, now)?;
        if let Some(existing) = self.nodes.get(&id) {
            if existing.invalid {
                return Err(Error::InvalidAncestor);
            }
            return Ok(id);
        }
        self.check_capacity(HEADER_BYTES as u64 + 512, true)?;
        let parent = self.nodes.get(&header.parent).ok_or(Error::UnknownParent)?;
        let work = &parent.cumulative_work + header.target.work()?;
        self.nodes.insert(
            id,
            Node {
                header: Some(header),
                cumulative_work: work,
                state: None,
                body: None,
                invalid: false,
            },
        );
        self.accounted_bytes += HEADER_BYTES as u64 + 512;
        self.reconsider(id);
        Ok(id)
    }
    /// Verifies the exact bounded body against its header and parent state. The
    /// verifier is called before any mutation can become a validated head.
    pub fn import_body<V: TransitionVerifier + ?Sized>(
        &mut self,
        id: Hash,
        body_wire: &[u8],
        verifier: &V,
    ) -> Result<ImportOutcome> {
        let previous_tip = self.best(true);
        let node = self.nodes.get(&id).ok_or(Error::UnknownHead)?;
        if node.invalid {
            return Err(Error::InvalidAncestor);
        }
        if node.state.is_some() {
            if node.body.as_deref() != Some(body_wire) {
                return Err(Error::InvalidBody);
            }
            return Ok(self.outcome(id, previous_tip));
        }
        let header = node.header.as_ref().ok_or(Error::InvalidBody)?;
        // Uncommitted garbage supplied by a sender must not invalidate the
        // genuine header or its descendants. Only its hash-bound body can do so.
        if body_wire.len() > self.profile().max_body_bytes as usize {
            return Err(Error::ResourceLimit);
        }
        if hash(body_wire) != header.body_hash {
            return Err(Error::InvalidBody);
        }
        let result = self.prepare_state(header, body_wire, verifier);
        let state = match result {
            Ok(state) => state,
            Err(error) => {
                if !matches!(
                    error,
                    Error::BodyUnavailable | Error::ResourceLimit | Error::MissingComputationProof
                ) {
                    self.invalidate(id);
                }
                return Err(error);
            }
        };
        self.check_capacity(body_wire.len() as u64 + state.len() as u64 * 232, false)?;
        let node = self.nodes.get_mut(&id).ok_or(Error::UnknownHead)?;
        node.state = Some(state);
        node.body = Some(body_wire.to_vec());
        self.accounted_bytes +=
            body_wire.len() as u64 + node.state.as_ref().map_or(0, |s| s.len() as u64 * 232);
        self.reconsider(id);
        Ok(self.outcome(id, previous_tip))
    }
    /// All-or-nothing validated import. Invalid/unavailable bodies add no header.
    pub fn import_block<V: TransitionVerifier + ?Sized>(
        &mut self,
        header: Header,
        body_wire: &[u8],
        now: u64,
        verifier: &V,
    ) -> Result<ImportOutcome> {
        let prepared = self.prepare_block(header, body_wire, now, verifier)?;
        Ok(self.publish(prepared))
    }
    pub fn resolve(&self, policy: Freshness) -> Result<HeadRef> {
        let best = self.best(true);
        if self.best(false) != best {
            return Err(Error::BodyUnavailable);
        }
        let depth = u64::from(self.profile().confirmation_depth);
        let confirmed_height = self
            .height(best)
            .checked_sub(depth)
            .ok_or(Error::Unconfirmed)?;
        let confirmed = self.ancestor_at(best, confirmed_height)?;
        match policy {
            Freshness::LatestConfirmed => Ok(self.head(confirmed)),
            Freshness::Exact(requested) => {
                self.check_reference(requested)?;
                if !self.is_ancestor(requested.block, best) {
                    return Err(Error::Reorganized);
                }
                if requested.height > confirmed_height {
                    return Err(Error::Unconfirmed);
                }
                Ok(requested)
            }
            Freshness::AtLeast(minimum) => {
                self.check_reference(minimum)?;
                if !self.is_ancestor(minimum.block, best) {
                    return Err(Error::Reorganized);
                }
                if minimum.height > confirmed_height {
                    return Err(Error::Unconfirmed);
                }
                Ok(self.head(confirmed))
            }
        }
    }
    /// Rechecks the reference and requested policy each time, including after reorg.
    pub fn shards(&self, accepted: HeadRef, policy: Freshness) -> Result<&[ShardState]> {
        let required = self.resolve(policy)?;
        self.check_reference(accepted)?;
        if accepted != required {
            return Err(Error::StaleHead);
        }
        self.nodes
            .get(&accepted.block)
            .and_then(|n| n.state.as_deref())
            .ok_or(Error::BodyUnavailable)
    }
    pub fn is_ancestor(&self, ancestor: Hash, descendant: Hash) -> bool {
        if !self.nodes.contains_key(&ancestor) || !self.nodes.contains_key(&descendant) {
            return false;
        }
        let height = self.height(ancestor);
        self.ancestor_at(descendant, height)
            .is_ok_and(|id| id == ancestor)
    }

    pub(crate) fn prepare_block<V: TransitionVerifier + ?Sized>(
        &self,
        header: Header,
        body_wire: &[u8],
        now: u64,
        verifier: &V,
    ) -> Result<PreparedBlock> {
        let id = self.check_header(&header, now)?;
        if let Some(node) = self.nodes.get(&id) {
            if node.invalid {
                return Err(Error::InvalidAncestor);
            }
            if node.state.is_some() {
                if node.body.as_deref() != Some(body_wire) {
                    return Err(Error::InvalidBody);
                }
                return Ok(PreparedBlock {
                    id,
                    node: None,
                    bytes: 0,
                });
            }
        }
        let state = self.prepare_state(&header, body_wire, verifier)?;
        let header_bytes = if self.nodes.contains_key(&id) {
            0
        } else {
            HEADER_BYTES as u64 + 512
        };
        let bytes = header_bytes + body_wire.len() as u64 + state.len() as u64 * 232;
        self.check_capacity(bytes, header_bytes != 0)?;
        let parent = self.nodes.get(&header.parent).ok_or(Error::UnknownParent)?;
        let cumulative_work = &parent.cumulative_work + header.target.work()?;
        Ok(PreparedBlock {
            id,
            node: Some(Node {
                header: Some(header),
                cumulative_work,
                state: Some(state),
                body: Some(body_wire.to_vec()),
                invalid: false,
            }),
            bytes,
        })
    }
    pub(crate) fn publish(&mut self, prepared: PreparedBlock) -> ImportOutcome {
        let previous = self.best(true);
        if let Some(node) = prepared.node {
            self.nodes.insert(prepared.id, node);
            self.accounted_bytes += prepared.bytes;
            self.reconsider(prepared.id);
        }
        self.outcome(prepared.id, previous)
    }
    fn prepare_state<V: TransitionVerifier + ?Sized>(
        &self,
        header: &Header,
        wire: &[u8],
        verifier: &V,
    ) -> Result<Vec<ShardState>> {
        if wire.len() > self.profile().max_body_bytes as usize {
            return Err(Error::ResourceLimit);
        }
        if hash(wire) != header.body_hash {
            return Err(Error::InvalidBody);
        }
        let body = Body::decode(wire, self.profile())?;
        let parent = self.nodes.get(&header.parent).ok_or(Error::UnknownParent)?;
        if parent.invalid {
            return Err(Error::InvalidAncestor);
        }
        let previous = parent.state.as_ref().ok_or(Error::BodyUnavailable)?;
        let state = self.apply_changes(header.parent, previous, &body)?;
        let next_state_root = state_root(&state);
        if next_state_root != header.state_root {
            return Err(Error::InvalidTransition);
        }
        if let Body::Transition(transition) = &body {
            transition.check_authorization(&self.genesis.owner, self.id)?;
            verifier.verify(TransitionStatement {
                genesis: self.id,
                database: self.genesis.database,
                application_commitment: self.genesis.application_commitment,
                parent: self.head(header.parent),
                previous_shards: previous,
                next_shards: &state,
                request: &transition.request,
                updates: &transition.updates,
                proof: &transition.proof,
                next_state_root,
            })?;
        }
        Ok(state)
    }
    fn apply_changes(
        &self,
        parent: Hash,
        previous: &[ShardState],
        body: &Body,
    ) -> Result<Vec<ShardState>> {
        let mut state = previous.to_vec();
        if let Body::Transition(transition) = body {
            if transition.parent != parent {
                return Err(Error::InvalidTransition);
            }
            for update in &transition.updates {
                let index = state
                    .binary_search_by_key(&update.id, |s| s.id)
                    .map_err(|_| Error::InvalidTransition)?;
                if state[index].heads != update.old || update.old == update.new {
                    return Err(Error::InvalidTransition);
                }
                state[index].heads = update.new;
            }
        }
        Ok(state)
    }
    fn check_header(&self, header: &Header, now: u64) -> Result<Hash> {
        self.validate_mining_candidate(header, now)?;
        let id = header.id();
        if !header.target.permits(id) {
            return Err(Error::InvalidWork);
        }
        Ok(id)
    }
    /// Checks all header rules except completed proof of work. This is a mining
    /// admission check only; import always additionally verifies actual SHA256d.
    pub fn validate_mining_candidate(&self, header: &Header, now: u64) -> Result<()> {
        if header.genesis != self.id {
            return Err(Error::WrongDomain);
        }
        let parent = self.nodes.get(&header.parent).ok_or(Error::UnknownParent)?;
        if parent.invalid {
            return Err(Error::InvalidAncestor);
        }
        if header.height
            != self
                .height(header.parent)
                .checked_add(1)
                .ok_or(Error::InvalidHeight)?
        {
            return Err(Error::InvalidHeight);
        }
        if header.target != self.next_target(header.parent)? {
            return Err(Error::InvalidTarget);
        }
        if header.timestamp <= self.median_time(header.parent)
            || header.timestamp > now.saturating_add(self.profile().max_future_secs)
        {
            return Err(Error::InvalidTimestamp);
        }
        Ok(())
    }
    fn check_capacity(&self, bytes: u64, new_header: bool) -> Result<()> {
        if (new_header && self.nodes.len() > self.profile().max_headers as usize)
            || self
                .accounted_bytes
                .checked_add(bytes)
                .is_none_or(|b| b > self.profile().max_journal_bytes)
        {
            return Err(Error::ResourceLimit);
        }
        Ok(())
    }
    fn check_reference(&self, reference: HeadRef) -> Result<()> {
        if reference.genesis != self.id || reference.database != self.genesis.database {
            return Err(Error::WrongDomain);
        }
        let node = self.nodes.get(&reference.block).ok_or(Error::UnknownHead)?;
        if node.invalid {
            return Err(Error::InvalidAncestor);
        }
        if node.state.is_none() {
            return Err(Error::BodyUnavailable);
        }
        if self.head(reference.block) != reference {
            return Err(Error::InvalidTransition);
        }
        Ok(())
    }
    fn best(&self, require_state: bool) -> Hash {
        if require_state {
            self.validated_tip
        } else {
            self.header_tip
        }
    }
    fn reconsider(&mut self, candidate: Hash) {
        let node = self.nodes.get(&candidate).expect("inserted candidate");
        if node.invalid {
            return;
        }
        let stronger = |current: Hash| {
            let previous = self.nodes.get(&current).expect("existing tip");
            node.cumulative_work > previous.cumulative_work
                || (node.cumulative_work == previous.cumulative_work && candidate < current)
        };
        let header_better = stronger(self.header_tip);
        let state_better = node.state.is_some() && stronger(self.validated_tip);
        if header_better {
            self.header_tip = candidate;
        }
        if state_better {
            self.validated_tip = candidate;
        }
    }
    fn scan_best(&self, require_state: bool) -> Hash {
        self.nodes
            .iter()
            .filter(|(_, n)| !n.invalid && (!require_state || n.state.is_some()))
            .max_by(|(a_id, a), (b_id, b)| {
                a.cumulative_work
                    .cmp(&b.cumulative_work)
                    .then_with(|| b_id.cmp(a_id))
            })
            .map_or(self.id, |(id, _)| *id)
    }
    fn height(&self, id: Hash) -> u64 {
        self.nodes
            .get(&id)
            .and_then(|n| n.header.as_ref())
            .map_or(0, |h| h.height)
    }
    fn timestamp(&self, id: Hash) -> u64 {
        self.nodes
            .get(&id)
            .and_then(|n| n.header.as_ref())
            .map_or(self.genesis.timestamp, |h| h.timestamp)
    }
    fn head(&self, id: Hash) -> HeadRef {
        HeadRef {
            genesis: self.id,
            database: self.genesis.database,
            block: id,
            height: self.height(id),
            state_root: self
                .nodes
                .get(&id)
                .and_then(|n| n.header.as_ref())
                .map_or_else(
                    || state_root(&self.genesis.initial_shards),
                    |h| h.state_root,
                ),
        }
    }
    fn parent(&self, id: Hash) -> Option<Hash> {
        self.nodes.get(&id)?.header.as_ref().map(|h| h.parent)
    }
    fn ancestor_at(&self, mut id: Hash, height: u64) -> Result<Hash> {
        if !self.nodes.contains_key(&id) || self.height(id) < height {
            return Err(Error::UnknownHead);
        }
        while self.height(id) > height {
            id = self.parent(id).ok_or(Error::UnknownHead)?;
        }
        Ok(id)
    }
    fn median_time(&self, mut id: Hash) -> u64 {
        let mut times = Vec::with_capacity(11);
        loop {
            times.push(self.timestamp(id));
            if times.len() == 11 {
                break;
            }
            match self.parent(id) {
                Some(parent) => id = parent,
                None => break,
            }
        }
        times.sort_unstable();
        times[times.len() / 2]
    }
    fn invalidate(&mut self, id: Hash) {
        let descendants: Vec<_> = self
            .nodes
            .keys()
            .copied()
            .filter(|child| self.is_ancestor(id, *child))
            .collect();
        for descendant in descendants {
            if let Some(node) = self.nodes.get_mut(&descendant) {
                node.invalid = true;
            }
        }
        self.header_tip = self.scan_best(false);
        self.validated_tip = self.scan_best(true);
    }
    fn outcome(&self, id: Hash, previous_tip: Hash) -> ImportOutcome {
        let current_tip = self.best(true);
        let reorganization =
            if previous_tip != current_tip && !self.is_ancestor(previous_tip, current_tip) {
                Some(self.reorganization(previous_tip, current_tip))
            } else {
                None
            };
        ImportOutcome {
            block: id,
            previous_tip,
            current_tip,
            reorganization,
        }
    }
    fn reorganization(&self, mut old: Hash, mut new: Hash) -> Reorganization {
        let mut detached = Vec::new();
        let mut attached = Vec::new();
        while self.height(old) > self.height(new) {
            detached.push(old);
            old = self.parent(old).expect("known ancestry");
        }
        while self.height(new) > self.height(old) {
            attached.push(new);
            new = self.parent(new).expect("known ancestry");
        }
        while old != new {
            detached.push(old);
            attached.push(new);
            old = self.parent(old).expect("known ancestry");
            new = self.parent(new).expect("known ancestry");
        }
        attached.reverse();
        Reorganization {
            common_ancestor: old,
            detached,
            attached,
        }
    }
}

pub(crate) struct PreparedBlock {
    pub(crate) id: Hash,
    node: Option<Node>,
    bytes: u64,
}
