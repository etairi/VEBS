# Foundations of Verifiably Encrypted (Blind) Signatures

Implementation for the primitives VEBS of the paper *Foundations of Verifiably Encrypted (Blind) Signatures*.
The implementation is for the structure-preserving signature constructions proven secure in the paper, and require no NIZK for verifiability.

The main script produces a CSV file with the running times of encryption, verification and resolve algorithms of VEBS.

## How to run

```
cargo run --release
```

The command above runs 100 execution for each primitive and produces a CSV file with the computation time and the communication complexity.