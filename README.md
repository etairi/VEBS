# Foundations of Verifiably Encrypted (Blind) Signatures

Implementation for the primitives VEBS of the paper *Foundations of Verifiably Encrypted (Blind) Signatures*.
The implementations are for the BLS and SPS constructions proven secure in the paper, and require no NIZK for verifiability.

The main script produces a CSV file with the running times of encryption, verification and decryption of VEBS.
The results can be compared with the phases Setup, Buy and Get for protocol Execute of [SWEEP-UC](https://eprint.iacr.org/2022/1605.pdf)

Note that we have also implemented an Schnorr-based adaptor signature, reproducing the one in [Generalized Channels from Limited Blockchain
Scripts and Adaptor Signatures](https://eprint.iacr.org/2020/476.pdf) and that our Setup, Buy and Get also compute the same Schnorr adaptor signature algorithms as in SWEEP-UC.

## How to run

```
cargo run --release
```

The command above runs 100 execution for each primitive and produces a CSV file with the computation time and the communication complexity.