# Full product integration consumer

The parent input-formation test owns private Source/query witnesses and the actual
SDK FHE oracle. This module receives only public original setup/anchor, complete
Encoding statements, two original ciphertexts, proposed output and public frames
after the Owner, scope and private fixture have been dropped.

`verify` uses the Core [full graph](../../../../../../../crates/bfv-mul-relin-proof/README.md)
consumer; `verify_inputs` reloads the actual Key, two Source/encoding pairs, ten
Basis and two Formation frames and drops their buffers after genuine verification.
The other helpers test endpoint, session-budget and genuine foreign NTT rejection.
They use existing complete NTT circuits/proofs and fixed public BFV geometry.

All118 output records are written to the existing owned public temporary spool.
The complete prover, prepared key, graph, verifier and checked state are dropped;
a new setup/key/graph/verifier then actually verifies every input and output proof
from the public files. The original input16 test and its timing/spool accounting
remain separate from this optional output path. No SQL or fresh-head acceptance is
introduced. The [executed native validation](../../../../../../bfv-mul-relin-proof/VALIDATION.md)
records the complete proof, source/receipt identities, timings, public stream
sizes, process observations and remaining protocol limitations.
The [Core extraction validation](../../../../../../bfv-mul-relin-proof/CORE-EXTRACTION-VALIDATION.md)
reruns this genuine complete integration with shared Core claims/routing and
public key preparation, preserving the original proof profiles and caps.
