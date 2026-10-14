# BFV security input specification

This isolated research script maps the published fhe0.1.1 N16384 BFV profile to
exact lattice-estimator inputs. It has no project-module dependency and does not
change the storage/query backend, security parameters or build. Its default mode
uses Python's standard library to print the exact modulus/distribution manifest.

Run from the repository root:

~~~sh
python3 experiments/bfv-security/estimate_bfv.py
~~~

Explicit --estimate additionally requires Sage and a clean official estimator
checkout pinned to53da5982597709ba0fdf94ea37a84d822310fd84. It installs nothing.
Obtain the research CPU lease before running attacks. The prepared path evaluates
full classical MATZOV/ADPS16 cost sweeps and records their conditional generic-LWE
results. It is not a BFV code audit, ring/KDM proof, noise bound or query proof.

See the [input gate and reproducible invocation](../../docs/experiment-bfv-security.md)
for CBD20/variance10 conversion, sample-count assumptions, evaluation-key exposure,
performed lightweight checks and the currently missing Sage runtime. No numerical
security estimate has run in this stage.
