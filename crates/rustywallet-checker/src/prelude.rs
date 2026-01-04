//! Prelude module for convenient imports

pub use crate::bitcoin::{check_btc_balance, BitcoinBalance};
pub use crate::electrum::{
    check_btc_balance_electrum, check_btc_balances_batch, ElectrumChecker, ElectrumConfig,
};
pub use crate::error::CheckerError;
pub use crate::ethereum::{check_eth_balance, EthereumBalance};
