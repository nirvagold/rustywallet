# rustywallet-coinjoin

CoinJoin and PayJoin (BIP78) utilities for rustywallet.

## Features

- **PayJoin (BIP78)**: Sender and receiver PayJoin protocol
- **CoinJoin Building**: Create CoinJoin transactions with equal outputs
- **Output Mixing**: Shuffle and equalize outputs for privacy
- **Coordinator-less**: P2P CoinJoin without central coordinator
- **PSBT Workflow**: Build CoinJoin transactions as PSBTs for hardware wallet compatibility
- **PSBT PayJoin**: BIP78 PayJoin with PSBT support

## Installation

```toml
[dependencies]
rustywallet-coinjoin = "0.2"
```

## Quick Start

### PSBT-based CoinJoin (Recommended)

```rust
use rustywallet_coinjoin::prelude::*;

// Create PSBT CoinJoin builder
let mut builder = PsbtCoinJoinBuilder::new();

// Add participants
builder.add_participant(Participant::new(
    "alice",
    vec![InputRef::from_outpoint([1u8; 32], 0, 100_000)],
    output_script_alice,
));
builder.add_participant(Participant::new(
    "bob",
    vec![InputRef::from_outpoint([2u8; 32], 0, 100_000)],
    output_script_bob,
));

builder.set_output_amount(50_000);

// Build PSBT
let psbt = builder.build_psbt()?;

// Each participant signs their inputs
let alice_signed = sign_psbt(&psbt, alice_key)?;
let bob_signed = sign_psbt(&psbt, bob_key)?;

// Combine signed PSBTs
let combined = combine_participant_psbts(&[alice_signed, bob_signed])?;

// Finalize and extract transaction
let tx = finalize_coinjoin_psbt(&mut combined)?;
```

### PSBT PayJoin (BIP78)

```rust
use rustywallet_coinjoin::prelude::*;

// Receiver creates PayJoin from sender's PSBT
let mut payjoin = PsbtPayJoin::from_original_psbt(sender_psbt_base64)?;

// Receiver adds their input
payjoin.add_receiver_input(InputRef::from_outpoint([1u8; 32], 0, 50_000));
payjoin.set_receiver_output_script(receiver_script);

// Create proposal PSBT
let proposal = payjoin.create_proposal()?;

// Both parties sign
// ...

// Finalize
let tx = PsbtPayJoin::finalize(&mut signed_psbt)?;
```

### Legacy CoinJoin Transaction

```rust
use rustywallet_coinjoin::prelude::*;

// Create CoinJoin with equal outputs
let mut builder = CoinJoinBuilder::new();
builder.add_participant_simple("alice", inputs1, output_script1);
builder.add_participant_simple("bob", inputs2, output_script2);

builder.set_output_amount(50_000);
let coinjoin_tx = builder.build()?;
```

### Coordinator-less Session

```rust
use rustywallet_coinjoin::prelude::*;

// Create session
let mut session = CoinJoinSession::new(50_000);

// Participants join
session.join(Participant::new("alice", inputs1, output1))?;
session.join(Participant::new("bob", inputs2, output2))?;

// Build transaction
let tx = session.build_transaction()?;

// Collect signatures
session.submit_signature("alice", alice_sig)?;
session.submit_signature("bob", bob_sig)?;
```

## PSBT Workflow Benefits

The PSBT-based workflow provides several advantages:

1. **Hardware Wallet Support**: PSBTs can be signed by hardware wallets
2. **Multi-Party Signing**: Each participant signs independently
3. **Signature Aggregation**: Combine signatures from multiple PSBTs
4. **Validation**: Verify all inputs are signed before finalization
5. **Interoperability**: Standard PSBT format works with other wallets

## BIP78 PayJoin

PayJoin improves privacy by having the receiver contribute inputs:

1. Sender creates original PSBT
2. Receiver adds their inputs and adjusts outputs
3. Both parties sign
4. Transaction looks like regular payment

## CoinJoin

CoinJoin combines multiple users' transactions:

- Equal output amounts break amount correlation
- Multiple inputs from different users
- Shuffled outputs hide ownership

## Security

- Verify all inputs before signing
- Use equal output amounts
- Randomize output order
- Validate fee calculations
- Use PSBT workflow for hardware wallet security

## License

MIT
