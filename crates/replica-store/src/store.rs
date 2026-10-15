use crate::*;
use compact_store::EncryptedSnapshot;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};

// Process-local opaque handle identity, not a network/cryptographic identifier.
// Checked allocation never reuses an identity, even after a store is dropped.
static NEXT_ORIGIN: AtomicU64 = AtomicU64::new(1);

fn allocate_origin() -> Result<u64> {
    let mut current = NEXT_ORIGIN.load(Ordering::Relaxed);
    loop {
        let next = current.checked_add(1).ok_or(Error::GenerationExhausted)?;
        match NEXT_ORIGIN.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => return Ok(current),
            Err(actual) => current = actual,
        }
    }
}

struct Peer {
    config: PeerConfig,
    available: bool,
    images: BTreeMap<ObjectId, Vec<u8>>,
    canonical_bytes: usize,
}
impl Peer {
    fn charged(&self) -> Result<usize> {
        self.images
            .len()
            .checked_mul(RECORD_METADATA_BYTES)
            .and_then(|n| n.checked_add(self.canonical_bytes))
            .ok_or(Error::ResourceLimit)
    }
}

/// Local, synchronous composition of ciphertext-only peer stores. No secret key,
/// plaintext or decrypt API is present. Not a network coordinator or durable store.
pub struct ReplicaStore {
    origin: u64,
    bounds: Bounds,
    peers: BTreeMap<PeerId, Peer>,
    objects: BTreeSet<ObjectId>,
    generation: u64,
}
impl ReplicaStore {
    pub fn new(bounds: Bounds) -> Result<Self> {
        if bounds.max_peers == 0
            || bounds.max_objects == 0
            || bounds.max_staged_bytes == 0
            || bounds.max_peers.checked_mul(bounds.max_objects).is_none()
            || bounds
                .max_objects
                .checked_mul(RECORD_METADATA_BYTES)
                .is_none()
            || bounds
                .images
                .max_image_bytes
                .checked_add(RECORD_METADATA_BYTES)
                .is_none()
            || bounds.images.max_image_bytes < compact_store::MANIFEST_BYTES
        {
            return Err(Error::InvalidBounds);
        }
        let origin = allocate_origin()?;
        Ok(Self {
            origin,
            bounds,
            peers: BTreeMap::new(),
            objects: BTreeSet::new(),
            generation: 0,
        })
    }
    fn next_generation(&self) -> Result<u64> {
        self.generation
            .checked_add(1)
            .ok_or(Error::GenerationExhausted)
    }
    pub fn register_peer(&mut self, config: PeerConfig) -> Result<()> {
        if self.peers.contains_key(&config.id) {
            return Err(Error::DuplicatePeer);
        }
        if self.peers.len() >= self.bounds.max_peers {
            return Err(Error::ResourceLimit);
        }
        let next = self.next_generation()?;
        self.peers.insert(
            config.id,
            Peer {
                config,
                available: true,
                images: BTreeMap::new(),
                canonical_bytes: 0,
            },
        );
        self.generation = next;
        Ok(())
    }
    /// Availability is an external observation. Marking even the last source offline
    /// is allowed and leaves its bytes charged; subsequent repair fails explicitly.
    pub fn set_available(&mut self, peer: PeerId, available: bool) -> Result<()> {
        let current = self.peers.get(&peer).ok_or(Error::UnknownPeer)?;
        if current.available == available {
            return Ok(());
        }
        let next = self.next_generation()?;
        self.peers
            .get_mut(&peer)
            .ok_or(Error::UnknownPeer)?
            .available = available;
        self.generation = next;
        Ok(())
    }
    pub fn set_quota(&mut self, peer: PeerId, quota_bytes: usize) -> Result<()> {
        let current = self.peers.get(&peer).ok_or(Error::UnknownPeer)?;
        if current.charged()? > quota_bytes {
            return Err(Error::Quota);
        }
        if current.config.quota_bytes == quota_bytes {
            return Ok(());
        }
        let next = self.next_generation()?;
        self.peers
            .get_mut(&peer)
            .ok_or(Error::UnknownPeer)?
            .config
            .quota_bytes = quota_bytes;
        self.generation = next;
        Ok(())
    }
    pub fn usage(&self, peer: PeerId) -> Result<PeerUsage> {
        let p = self.peers.get(&peer).ok_or(Error::UnknownPeer)?;
        Ok(PeerUsage {
            canonical_bytes: p.canonical_bytes,
            record_metadata_bytes: p.images.len() * RECORD_METADATA_BYTES,
            charged_bytes: p.charged()?,
            quota_bytes: p.config.quota_bytes,
            replicas: p.images.len(),
            available: p.available,
        })
    }
    /// Borrow the actual canonical ciphertext. Unavailable peers cannot serve it.
    pub fn ciphertext(&self, peer: PeerId, object: ObjectId) -> Result<&[u8]> {
        let p = self.peers.get(&peer).ok_or(Error::UnknownPeer)?;
        if !p.available {
            return Err(Error::Unavailable);
        }
        p.images
            .get(&object)
            .map(Vec::as_slice)
            .ok_or(Error::MissingReplica)
    }
    fn validate(&self, bytes: &[u8], expected: &Commitment) -> Result<()> {
        drop(EncryptedSnapshot::decode_for_head(
            bytes,
            expected,
            self.bounds.images,
        )?);
        Ok(())
    }
    /// Install an initial complete copy after current-head/full-root validation.
    /// Existing records cannot be overwritten by this entry point. Current-version
    /// replacement is performed only by repair with a surviving current source.
    pub fn seed(
        &mut self,
        peer: PeerId,
        object: ObjectId,
        expected: &Commitment,
        bytes: &[u8],
    ) -> Result<()> {
        let p = self.peers.get(&peer).ok_or(Error::UnknownPeer)?;
        if !p.available {
            return Err(Error::Unavailable);
        }
        if p.images.contains_key(&object) {
            return Err(Error::AlreadyPresent);
        }
        if !self.objects.contains(&object) && self.objects.len() >= self.bounds.max_objects {
            return Err(Error::ResourceLimit);
        }
        let charge = bytes
            .len()
            .checked_add(RECORD_METADATA_BYTES)
            .ok_or(Error::ResourceLimit)?;
        if p.charged()?
            .checked_add(charge)
            .is_none_or(|n| n > p.config.quota_bytes)
        {
            return Err(Error::Quota);
        }
        self.validate(bytes, expected)?;
        let next = self.next_generation()?;
        let bytes = bytes.to_vec();
        let p = self.peers.get_mut(&peer).ok_or(Error::UnknownPeer)?;
        p.canonical_bytes += bytes.len();
        p.images.insert(object, bytes);
        self.objects.insert(object);
        self.generation = next;
        Ok(())
    }
    fn normalize(&self, targets: &[ReplicaTarget]) -> Result<Vec<ReplicaTarget>> {
        if targets.len() > self.bounds.max_objects {
            return Err(Error::ResourceLimit);
        }
        let mut sorted = targets.to_vec();
        sorted.sort_by_key(|t| t.object);
        if sorted.windows(2).any(|v| v[0].object == v[1].object)
            || sorted
                .iter()
                .any(|t| t.copies == 0 || t.copies > self.bounds.max_peers)
        {
            return Err(Error::InvalidTargets);
        }
        let mut policies = BTreeMap::new();
        for t in &sorted {
            if let Some(bundle) = t.bundle
                && policies
                    .insert(bundle, t.copies)
                    .is_some_and(|copies| copies != t.copies)
            {
                return Err(Error::InvalidTargets);
            }
        }
        for t in &sorted {
            t.expected.layout().validate(self.bounds.images)?;
        }
        Ok(sorted)
    }
    /// Deterministic greedy placement: units by smallest ObjectId, members by
    /// ObjectId and destinations by PeerId. Only COMPLETE current bundle holders
    /// contribute failure domains; quota is reserved across each unit and batch.
    /// This is not a complete placement search or an optimal bin packer.
    pub fn plan_repair(&self, targets: &[ReplicaTarget]) -> Result<RepairPlan> {
        let targets = self.normalize(targets)?;
        let mut used = self
            .peers
            .iter()
            .map(|(id, p)| Ok((*id, p.charged()?)))
            .collect::<Result<BTreeMap<_, _>>>()?;
        let mut writes = Vec::new();
        let mut staged_bytes = 0usize;
        let mut units: Vec<Vec<&ReplicaTarget>> = Vec::new();
        let mut bundles = BTreeMap::new();
        for target in &targets {
            if let Some(bundle) = target.bundle {
                let index = *bundles.entry(bundle).or_insert_with(|| {
                    units.push(Vec::new());
                    units.len() - 1
                });
                units[index].push(target);
            } else {
                units.push(vec![target]);
            }
        }
        for members in units {
            // Objects may have complementary current sources: no complete source
            // bundle is required, but every member must have a valid current source.
            let mut source_sets = Vec::with_capacity(members.len());
            for target in &members {
                let sources = self
                    .peers
                    .iter()
                    .filter_map(|(id, p)| {
                        (p.available
                            && p.images
                                .get(&target.object)
                                .is_some_and(|b| self.validate(b, &target.expected).is_ok()))
                        .then_some(*id)
                    })
                    .collect::<Vec<_>>();
                if sources.is_empty() {
                    return Err(Error::NoAvailableSource(target.object));
                }
                source_sets.push(sources);
            }
            let mut domains = BTreeSet::new();
            for (id, p) in &self.peers {
                if p.available && source_sets.iter().all(|sources| sources.contains(id)) {
                    domains.insert(p.config.failure_domain);
                }
            }
            let required = members[0].copies; // Nonempty by construction; normalized policy.
            for (id, p) in &self.peers {
                if domains.len() >= required {
                    break;
                }
                if !p.available || domains.contains(&p.config.failure_domain) {
                    continue;
                }
                // Reserve the ENTIRE missing/replacement subset on one peer before
                // emitting any member copy or consuming batch staging capacity.
                let mut next = used[id];
                let mut additional = 0usize;
                let mut candidate = Vec::new();
                for (target, sources) in members.iter().zip(&source_sets) {
                    if sources.contains(id) {
                        continue;
                    } // Correct member already held.
                    let len = target.expected.layout().encoded_len()?;
                    let old_charge = p
                        .images
                        .get(&target.object)
                        .map(|b| {
                            b.len()
                                .checked_add(RECORD_METADATA_BYTES)
                                .ok_or(Error::ResourceLimit)
                        })
                        .transpose()?
                        .unwrap_or(0);
                    next = next
                        .checked_sub(old_charge)
                        .and_then(|n| n.checked_add(len))
                        .and_then(|n| n.checked_add(RECORD_METADATA_BYTES))
                        .ok_or(Error::ResourceLimit)?;
                    additional = additional.checked_add(len).ok_or(Error::ResourceLimit)?;
                    candidate.push(PlannedCopy {
                        object: target.object,
                        destination: *id,
                        canonical_bytes: len,
                        sources: sources.clone(),
                    });
                }
                if next > p.config.quota_bytes {
                    continue;
                }
                staged_bytes = staged_bytes
                    .checked_add(additional)
                    .ok_or(Error::ResourceLimit)?;
                if staged_bytes > self.bounds.max_staged_bytes {
                    return Err(Error::ResourceLimit);
                }
                used.insert(*id, next);
                domains.insert(p.config.failure_domain);
                writes.extend(candidate);
            }
            if domains.len() < required {
                return Err(Error::InsufficientDomainsOrCapacity);
            }
        }
        Ok(RepairPlan {
            origin: self.origin,
            generation: self.generation,
            targets,
            copies: writes,
        })
    }
    fn stage<F>(
        &self,
        plan: &RepairPlan,
        current: &[ReplicaTarget],
        fetch: &mut F,
    ) -> Result<(Vec<Vec<u8>>, RepairReport)>
    where
        F: FnMut(PeerId, ObjectId, &mut [u8]) -> Result<usize>,
    {
        if plan.origin != self.origin || plan.generation != self.generation {
            return Err(Error::StalePlan);
        }
        if self.normalize(current)? != plan.targets {
            return Err(Error::CurrentTargetsChanged);
        }
        let mut staged = Vec::with_capacity(plan.copies.len());
        let mut report = RepairReport::default();
        for copy in &plan.copies {
            let target = plan
                .targets
                .iter()
                .find(|t| t.object == copy.object)
                .ok_or(Error::InvalidTargets)?;
            let mut destination = vec![0u8; copy.canonical_bytes];
            let mut accepted = None;
            for source in &copy.sources {
                destination.fill(0);
                let failure = match fetch(*source, copy.object, &mut destination) {
                    Err(_) => Some(SourceFailure::Transport),
                    Ok(n) if n != destination.len() => Some(SourceFailure::WrongLength),
                    Ok(_) if self.validate(&destination, &target.expected).is_err() => {
                        Some(SourceFailure::InvalidImage)
                    }
                    Ok(_) => None,
                };
                if let Some(failure) = failure {
                    report.rejected_sources.push(RejectedSource {
                        object: copy.object,
                        peer: *source,
                        failure,
                    });
                } else {
                    accepted = Some(*source);
                    break;
                }
            }
            let source = accepted.ok_or(Error::NoAvailableSource(copy.object))?;
            report.copied.push(CompletedCopy {
                object: copy.object,
                source,
                destination: copy.destination,
                canonical_bytes: destination.len(),
            });
            staged.push(destination);
        }
        Ok((staged, report))
    }
    fn publish(
        &mut self,
        plan: RepairPlan,
        staged: Vec<Vec<u8>>,
        report: RepairReport,
    ) -> Result<RepairReport> {
        if plan.origin != self.origin || plan.generation != self.generation {
            return Err(Error::StalePlan);
        }
        if plan.copies.is_empty() {
            return Ok(report);
        }
        let next = self.next_generation()?;
        // All fallible validation/fetch/quota/generation operations precede publication.
        // Rust allocation aborts/panics and process crashes are not durable transactions.
        for (copy, bytes) in plan.copies.into_iter().zip(staged) {
            let p = self
                .peers
                .get_mut(&copy.destination)
                .expect("validated plan peer");
            if let Some(old) = p.images.insert(copy.object, bytes) {
                p.canonical_bytes -= old.len();
            }
            p.canonical_bytes += copy.canonical_bytes;
            self.objects.insert(copy.object);
        }
        self.generation = next;
        Ok(report)
    }
    /// Copy actual survivor ciphertext to bounded destination buffers, validate every
    /// full destination root, then publish ALL writes. Recoverable errors mutate none.
    pub fn repair_local(
        &mut self,
        plan: RepairPlan,
        current: &[ReplicaTarget],
    ) -> Result<RepairReport> {
        let (staged, report) = self.stage(&plan, current, &mut |peer, object, out| {
            let bytes = self.ciphertext(peer, object)?;
            if bytes.len() != out.len() {
                return Ok(bytes.len());
            }
            out.copy_from_slice(bytes);
            Ok(bytes.len())
        })?;
        self.publish(plan, staged, report)
    }
    /// Transport-independent receive boundary. The callback writes only into an
    /// exact-size bounded destination and reports its actual framed length. It owns
    /// transport authorization/timeouts/trailing-byte detection and any own memory.
    /// Corrupt, stale, short and transport-failed sources are skipped in stable order.
    pub fn repair_with<F>(
        &mut self,
        plan: RepairPlan,
        current: &[ReplicaTarget],
        mut fetch: F,
    ) -> Result<RepairReport>
    where
        F: FnMut(PeerId, ObjectId, &mut [u8]) -> Result<usize>,
    {
        let (staged, report) = self.stage(&plan, current, &mut fetch)?;
        self.publish(plan, staged, report)
    }
    /// Explicit deletion only when another AVAILABLE full copy matches the supplied
    /// current head. Historical/stale record cleanup is not implicit repair policy.
    pub fn remove_current(
        &mut self,
        peer: PeerId,
        object: ObjectId,
        expected: &Commitment,
    ) -> Result<()> {
        self.validate(self.ciphertext(peer, object)?, expected)?;
        let another = self.peers.iter().any(|(id, p)| {
            *id != peer
                && p.available
                && p.images
                    .get(&object)
                    .is_some_and(|b| self.validate(b, expected).is_ok())
        });
        if !another {
            return Err(Error::LastAvailableReplica);
        }
        let next = self.next_generation()?;
        let p = self.peers.get_mut(&peer).ok_or(Error::UnknownPeer)?;
        let bytes = p.images.remove(&object).ok_or(Error::MissingReplica)?;
        p.canonical_bytes -= bytes.len();
        self.generation = next;
        Ok(())
    }
}
