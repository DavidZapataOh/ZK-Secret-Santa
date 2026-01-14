# ZK Secret Santa 🎅🤫

**A decentralized, verifiable, and privacy-preserving Secret Santa protocol powered by Zero-Knowledge Proofs.**

> This project implements the protocol described in the paper [arXiv:2501.06515](https://arxiv.org/abs/2501.06515).

## 📖 Overview

Traditional Secret Santa games rely on a trusted third party (or a centralized server) to perform the shuffle and assign gift recipients. This introduces a single point of failure and potential privacy leaks—the organizer knows everything!

**ZK Secret Santa** solves this by using **Zero-Knowledge Proofs (ZKP)** and **Smart Contracts** to ensure:
1.  **Privacy**: No participant (and no observer) knows who is sending a gift to whom, except for the sender and eventually the receiver.
2.  **Verifiability**: The shuffle is mathematically proven to be a valid permutation of the participants, ensuring no one is left out or assigned to themselves.
3.  **Fairness**: The protocol is executed on-chain and verified by ZK circuits, removing the need for trust.

## ✨ Features

- **Verifiable Shuffle**: Uses ZK circuits to prove that the assignment of secret santas is a valid internal permutation without revealing the mapping.
- **Decentralized Registration**: Participants register on-chain within a specified time window.
- **Commitment Scheme**: Users commit to their participation using standard crypto-primitives before the shuffle.
- **Privacy-Preserving**: Sender identities are hidden using nullifiers and ZK proofs.
- **On-Chain Logic**: The core coordination happens on an EVM-compatible blockchain.

## 🛠 Technology Stack

This project leverages the latest in ZK and EVM tooling:

- **[Noir](https://noir-lang.org/)**: The ZK domain-specific language used for writing the circuits (`circuits/`).
- **[Solidity](https://soliditylang.org/)**: Smart contracts for state management and verification (`src/`).
- **[Foundry](https://book.getfoundry.sh/)**: A blazing fast, portable, and modular toolkit for Ethereum application development (testing, deployment, scripting).
- **[Poseidon2](https://github.com/privacy-scaling-explorations/poseidon)**: Efficient ZK-friendly hashing.

## 📂 Project Structure

- `src/`: Solidity smart contracts.
  - `SecretSanta.sol`: The main entry point managing the event lifecycle.
  - `Register.sol`: Handles participant registration.
- `circuits/`: Noir circuits for generating proofs.
  - `sender/`: Circuit to prove sender validity and authorization.
  - `receiver/`: Circuit to verify receiver disclosure.
- `test/`: Foundry tests.
- `script/`: Deployment and interaction scripts.

## 🚀 Getting Started

### Prerequisites

- **[Foundry](https://getfoundry.sh/)**: Ensure you have `forge`, `cast`, and `anvil` installed.
- **[Nargo](https://noir-lang.org/docs/getting_started/installation/)**: The build tool and package manager for Noir.

### Installation

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/your-username/zk-secret-santa.git
    cd zk-secret-santa
    ```

2.  **Install dependencies**:
    ```bash
    forge install
    ```

3.  **Compile contracts**:
    ```bash
    forge build
    ```

4.  **Compile circuits** (if modifying Noir code):
    Navigate to the circuits directory and run:
    ```bash
    cd circuits/sender
    nargo check
    ```

## 🧪 Testing

Run the full suite of Solidity tests:

```bash
forge test
```

For circuit tests (if applicable):

```bash
cd circuits/sender
nargo test
```

## 🤝 Contributing

Contributions are welcome! If you find a bug or want to improve the circuits/contracts, please open an issue or submit a pull request.

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

## 📜 License

Distributed under the MIT License. See `src/SecretSanta.sol` for identifiers or `LICENSE` file for more information.

---

*Built with ❤️ and ZK Magic.*
