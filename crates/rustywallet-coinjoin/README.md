# rustywallet-coinjoin

CoinJoin and PayJoin (BIP78) utilities for rustywallet.

## Features

- **PayJoin (BIP78)**: Sender and receiver PayJoin protocol
- **CoinJoin Building**: Create CoinJoin transactions with equal outputs
- **Output Mixing**: Shuffle and equalize outputs for privacy
- **Coordinator-less**: P2P CoinJoin without central coordinator

## Installation

```toml
[dependencies]
rustywallet-coinjoin = "0.1"
```

## Quick Start

### PayJoin (BIP78)

```rust
use rustywallet_coinjoin::prelude::*;

// Receiver creates PayJoin request
let receiver = PayJoinReceiver::new(receiver_address, amount);
let request = receiver.create_request(&original_psbt)?;

// Sender processes PayJoin
let sender = PayJoinSender::new();
let payjoin_psbt = sender.process_request(&request, &sender_utxos)?;
```

### CoinJoin Transaction

```rust
use rustywallet_coinjoin::prelude::*;

// Create CoinJoin with equal outputs
let mut builder = CoinJoinBuilder::new();
builder.add_participant(inputs1, output_address1);
builder.add_participant(inputs2, output_address2);

let coinjoin_tx = builder.build(output_amount)?;
```

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

## License

MIT
