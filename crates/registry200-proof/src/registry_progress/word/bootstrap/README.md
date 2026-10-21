# Word EMPTY208 bootstrap

This fixed mathematical relation establishes the initial empty bank in the
original [Word](../README.md) registry domain. Its normal library entry points
`Expected::checked`, `PrivateInputs::checked`, `prove` and `verify` accept
caller-owned metadata/openings, never fixtures, alternate AIRs, verifier callbacks
or a producer-selected setup. Both proving and receiving require an actual
independently verified [SourceVersion](../../../source/version/README.md) proof.
The result authenticates mathematical consistency, not enrollment authority,
currentness, weighted finality, durable locks, BFV security or SQL admission.

The existing fixed EMPTY208 AIR and trace writer are shared privately with the
older progress bootstrap. The Word role has distinct DCSWEB01 framing/profile,
StateCertificate Source domain, original Word enrollment/registry headers and
265 constrained public values. The old Bootstrap803 protocol is unchanged and
cannot be reinterpreted as Word evidence. Direct dependencies are the private
`registry_progress::bootstrap_air` relation, sibling Word metadata/openings,
SourceVersion, existing hiding-FRI/P3 and SHA2. The proof crate imports no finality
or consumer layer.

The complete Source680 preimage binds all 587 u32 words and opening salt; the exact
TableId and all 32 row ID words feed Enrollment64 and Registry208. Both controllers
are bit constrained and nonzero. The enrollment commits both controllers in fixed
principal order. The registry commits that enrollment, original domain header,
TableId/row IDs and owner-selected salt; revision, allocator, both transaction
slots, held locks, progress presences/roots and padding are fixed zero. Exactly 119
Poseidon2 absorptions execute at H512, with resets at 0/85/93. The existing assessed
Goldilocks degree5 hiding-FRI suite and bounded canonical decoder remain in use.

`Expected` must be independently retained by the receiver: its Source contains
both full heads/packets and C_key/C_state, and its Word context binds the complete
Source scope, genesis and enrollment. The child frame binds the full expectation,
including C_state even when version_id is identical. Parent is canonical zero for
bootstrap only; this creates no transition, lease or current-head assertion.

`PrivateInputs` consumes a `SourceOpening`, two controller byte arrays and separate
enrollment/registry salt arrays. Every owner salt must be fresh and secret; public
unit fixture constants are not production randomness. Owned arrays use
`Zeroizing`; native field traces, copied values and SDK scratch are not claimed
erased. Early local root reconstruction produces no verification status. `prove`
returns explicitly unverified bytes. `verify` first checks the complete frame,
then independently verifies the Source prerequisite and actual child proof before
returning private move-only `VerifiedBootstrap`. Nothing serialized can mint it.

For use, retain an authorized Source/genesis/enrollment and independently agreed
expected empty root, prepare original openings, prove, then send the detached child
and Source certificate to an independent receiver. Higher layers must establish
the authority of those expectations and a fresh quorum before installing a bank.
No network SQL acceptance is enabled by this component.
