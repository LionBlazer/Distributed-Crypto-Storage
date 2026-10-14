# BFV security input specification

This isolated script maps two published fhe0.1.1 BFV profiles to exact
lattice-estimator inputs. It has no project-module dependency and changes no
storage/query backend or build. The unchanged default is n16384-plain25;
N8192 byte-limb inputs require an explicit selector.

| Profile | N | Plaintext t | Q bits | Maximum plaintext component |
| --- | ---: | ---: | ---: | ---: |
| n16384-plain25, default | 16384 | 33292289 | 438 | Full SUM16776960 |
| n8192-byte17 | 8192 | 114689 | 218 | Each byte-limb SUM65280 |

Both use exact ND.CenteredBinomial(20) for secret/error, variance10, and the same
explicit independent-LWE sample/ring/KDM caveats. Default mode uses only stdlib
and prints a profile-labeled manifest; it performs no security estimate.

Run from the repository root:

~~~sh
python3 experiments/bfv-security/estimate_bfv.py
python3 experiments/bfv-security/estimate_bfv.py --profile n8192-byte17
python3 experiments/bfv-security/test_manifest.py
~~~

Explicit --estimate additionally requires Sage and a clean official estimator
checkout pinned to53da5982597709ba0fdf94ea37a84d822310fd84. It installs nothing.
Obtain the research CPU lease before running attacks. The prepared path evaluates
full classical MATZOV/ADPS16 cost sweeps and labels their conditional generic-LWE
results with the selected profile. It is not a BFV code audit, ring/KDM proof,
noise bound or query proof. No numerical estimate has run in this stage.

See the [input gate and reproducible invocation](../../docs/experiment-bfv-security.md)
for exact primes, CBD/Gaussian conventions, sample counts, evaluation-key exposure
and concrete missing-Sage runtime evidence.
