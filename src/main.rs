use ckb_sdk::{
    traits::{
        DefaultCellCollector, DefaultCellDepResolver, DefaultHeaderDepResolver,
        DefaultTransactionDependencyProvider, SecpCkbRawKeySigner,
    },
    tx_builder::{
        balance_tx_capacity, fill_placeholder_witnesses, transfer::CapacityTransferBuilder,
        unlock_tx, CapacityBalancer, TxBuilder,
    },
    unlock::{ScriptUnlocker, SecpSighashUnlocker},
    CkbRpcClient, ScriptId, constants::ONE_CKB,
};
use ckb_types::{
    bytes::Bytes,
    core::{BlockView, ScriptHashType, TransactionView},
    h256,
    packed::{Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
    prelude::*,
    H256,
};
use lazy_static::lazy_static;
use rsa::{PublicKeyParts, RsaPrivateKey, RsaPublicKey};

use ckb_hash::{blake2b_256, new_blake2b};

use clap::{Args, Parser, Subcommand};
use serde_derive::{Deserialize, Serialize};
use std::{collections::HashMap, fs};

use ckb_jsonrpc_types as json_types;

pub const SIGHASH_TYPE_HASH: H256 =
    h256!("0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8");

lazy_static! {
    /// The reference to lazily-initialized static secp256k1 engine, used to execute all signature operations
    pub static ref SECP256K1: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Create(create_args) => {
            let room_cfg: RoomCfg =
                serde_json::from_slice(&fs::read(&create_args.cfg_file).unwrap()).unwrap();
            let room_info = RoomInfo {
                current_count: create_args.current_count,
                message_price: create_args.message_price,
                timelock: create_args.timelock,
                host_pubkey: room_cfg.host_pubkey.clone(),
                host_lock_hash: room_cfg.host_lock_hash(),
                owner_pubkey: room_cfg.owner_pubkey.clone(),
                members_pubkey_hash: room_cfg.members_pubkey_hash.clone(),
            };
            create(&room_cfg, &room_info, &create_args);
            // println!("> room_cfg: {}", serde_json::to_string_pretty(&room_cfg).unwrap());
        }
        Commands::Charge(_room_args) => {
            println!("charge");
        }
        Commands::ExtendTimeLock(_room_args) => println!("extend timelock"),
        Commands::GenKeyPair(gen_key_pair_args) => {
            let key_pair = gen_keypair(gen_key_pair_args.bit_size);
            if let Some(output_path) = gen_key_pair_args.output_path {
                fs::write(
                    &output_path,
                    serde_json::to_string_pretty(&key_pair).unwrap(),
                )
                .unwrap();
            } else {
                let res = serde_json::to_string_pretty(&key_pair).unwrap();
                println!("generate result:{}", res);
            }
        }
    }
}

fn skip_0x<'a>(s: &'a str) -> &'a str {
    if s.len() < 2 {
        return s;
    }
    if s.starts_with("0x") || s.starts_with("0X") {
        return &s[2..];
    } else {
        return s;
    }
}
#[derive(Subcommand)]
enum Commands {
    /// build omni lock address
    Create(CreateArgs),
    /// Generate the transaction
    Charge(RoomArgs),
    /// Sign the transaction
    ExtendTimeLock(RoomArgs),
    GenKeyPair(GenKeyPairArgs),
}
#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Hash, Eq, PartialEq, Debug, Serialize, Deserialize)]
struct RoomCfg {
    host_pubkey: RsaPublicKey,
    owner_pubkey: RsaPublicKey,
    members_pubkey_hash: Vec<RsaPublicKey>,
    operator_script_tx_hash: H256,
    operator_script_tx_index: usize,
    host_lock_tx_hash: H256,
    host_lock_tx_index: usize,
    host_lock_args: String,

    rsa_dep_tx_hash: H256,
    rsa_dep_tx_index: usize,
    /// CKB rpc url, default_value = "http://127.0.0.1:8114")
    ckb_rpc: String,
    /// CKB indexer rpc url, default_value = "http://127.0.0.1:8116")
    ckb_indexer: String,
}
impl RoomCfg {
    fn host_lock_hash(&self) -> [u8; 32] {
        let script = self.build_lock_script(
            &self.host_lock_tx_hash,
            self.host_lock_tx_index,
            &self.host_lock_args,
        );

        let host_lock_hash = blake2b_256(script.as_slice());
        host_lock_hash
    }

    pub fn build_lock_script(
        &self,
        lock_tx_hash: &H256,
        lock_idx: usize,
        lock_args: &str,
    ) -> Script {
        let mut ckb_client = CkbRpcClient::new(self.ckb_rpc.as_str());
        let out_point_json = json_types::OutPoint {
            tx_hash: lock_tx_hash.clone(),
            index: ckb_jsonrpc_types::Uint32::from(lock_idx as u32),
        };
        let cell_status = ckb_client.get_live_cell(out_point_json, true).unwrap();
        let code_hash = cell_status
            .cell
            .expect("get the cell")
            .data
            .expect("get data")
            .hash;
        let args = hex::decode(skip_0x(lock_args)).expect("decode host lock args");
        Script::new_builder()
            .code_hash(Byte32::from_slice(code_hash.as_bytes()).unwrap())
            .hash_type(ScriptHashType::Data1.into())
            .args(args.pack())
            .build()
    }
}

#[derive(Args)]
struct RoomArgs {
    #[clap(long, value_name = "current_count")]
    current_count: u64,
    #[clap(long, value_name = "message_price")]
    message_price: u64,
    #[clap(long, value_name = "timelock")]
    timelock: u64,
    #[clap(long, value_name = "cfg_file")]
    cfg_file: String,
}
#[derive(Args)]
struct CreateArgs {
    #[clap(long, value_name = "output_lock_hash")]
    output_lock_tx_hash: H256,
    #[clap(long, value_name = "output_lock_index")]
    output_lock_index: usize,
    #[clap(long, value_name = "output_lock_args")]
    output_lock_args: String,
    #[clap(long, value_name = "current_count")]
    current_count: u64,
    #[clap(long, value_name = "message_price")]
    message_price: u64,
    #[clap(long, value_name = "timelock")]
    timelock: u64,
    #[clap(long, value_name = "cfg_file")]
    cfg_file: String,
    /// The sender private key (hex string)
    #[clap(long, value_name = "KEY")]
    sender_key: H256,
}

#[derive(Args)]
struct GenKeyPairArgs {
    #[clap(long, value_name = "bit_size")]
    bit_size: usize,
    #[clap(long, value_name = "output_path")]
    output_path: Option<String>,
}

fn create(room_cfg: &RoomCfg, room_info: &RoomInfo, create_args: &CreateArgs) {
    let cell_data = room_info.to_cell_data();
    let output_lock_script = room_cfg.build_lock_script(
        &create_args.output_lock_tx_hash,
        create_args.output_lock_index,
        &create_args.output_lock_args,
    );

    let sender_key = secp256k1::SecretKey::from_slice(create_args.sender_key.as_bytes())
        .map_err(|err| format!("invalid sender secret key: {}", err))
        .unwrap();
    let sender = {
        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &sender_key);
        let hash160 = blake2b_256(&pubkey.serialize()[..])[0..20].to_vec();
        Script::new_builder()
            .code_hash(SIGHASH_TYPE_HASH.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(Bytes::from(hash160).pack())
            .build()
    };

    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(Bytes::from(vec![0u8; 65])).pack())
        .build();
    let balancer = CapacityBalancer::new_simple(sender, placeholder_witness, 1000);

    // Build:
    //   * CellDepResolver
    //   * HeaderDepResolver
    //   * CellCollector
    //   * TransactionDependencyProvider
    let mut ckb_client = CkbRpcClient::new(room_cfg.ckb_rpc.as_str());
    let mut cell_dep_resolver = {
        let genesis_block = ckb_client.get_block_by_number(0.into()).unwrap().unwrap();
        DefaultCellDepResolver::from_genesis(&BlockView::from(genesis_block)).unwrap()
    };
    let header_dep_resolver = DefaultHeaderDepResolver::new(room_cfg.ckb_rpc.as_str());
    let mut cell_collector =
        DefaultCellCollector::new(room_cfg.ckb_indexer.as_str(), room_cfg.ckb_rpc.as_str());
    let tx_dep_provider = DefaultTransactionDependencyProvider::new(room_cfg.ckb_rpc.as_str(), 10);

    let type_script_placeholder = placeholder_type_(&room_cfg);
    {
        let outpoint = OutPoint::new(
            Byte32::from_slice(room_cfg.operator_script_tx_hash.as_bytes()).unwrap(),
            (room_cfg.operator_script_tx_index as u32).into(),
        );
        let cell_dep = CellDep::new_builder().out_point(outpoint).build();
        cell_dep_resolver.insert(
            ScriptId::from(&type_script_placeholder),
            cell_dep,
            "operator-script".to_string(),
        );
    }
    // Build the transaction
    let output = CellOutput::new_builder()
        .lock(output_lock_script)
        .capacity((500u64 * ONE_CKB).pack())
        .type_(Some(placeholder_type_(&room_cfg)).pack())
        .build();

    let unlockers = {
        let signer = SecpCkbRawKeySigner::new_with_secret_keys(vec![sender_key]);
        let sighash_unlocker = SecpSighashUnlocker::from(Box::new(signer) as Box<_>);
        let sighash_script_id = ScriptId::new_type(SIGHASH_TYPE_HASH.clone());
        let mut unlockers = HashMap::default();
        unlockers.insert(
            sighash_script_id,
            Box::new(sighash_unlocker) as Box<dyn ScriptUnlocker>,
        );
        unlockers
    };

    let builder = CapacityTransferBuilder::new(vec![(output, Bytes::copy_from_slice(&cell_data))]);
    let base_tx = builder
        .build_base(
            &mut cell_collector,
            &cell_dep_resolver,
            &header_dep_resolver,
            &tx_dep_provider,
        )
        .expect("build base");

    let base_tx = add_cell_dep(
        base_tx,
        &[
            (
                &create_args.output_lock_tx_hash,
                create_args.output_lock_index,
            ),
            (&room_cfg.rsa_dep_tx_hash, room_cfg.rsa_dep_tx_index),
        ],
    );

    let (tx_filled_witnesses, _) =
        fill_placeholder_witnesses(base_tx, &tx_dep_provider, &unlockers)
            .expect("fill_placeholder_witnesses");

    let tx = balance_tx_capacity(
        &tx_filled_witnesses,
        &balancer,
        &mut cell_collector,
        &tx_dep_provider,
        &cell_dep_resolver,
        &header_dep_resolver,
    )
    .expect("balance_tx_capacity");

    let tx = replace_type_script(tx, room_cfg);
    let (new_tx, _new_still_locked_groups) =
        unlock_tx(tx, &tx_dep_provider, &unlockers).expect("unlock transaction");
    assert!(_new_still_locked_groups.is_empty(), "not all unlocked");
    let json_tx = json_types::TransactionView::from(new_tx.clone());
    println!(
        "new_tx: {}",
        serde_json::to_string_pretty(&json_tx).unwrap()
    );

    let outputs_validator = Some(json_types::OutputsValidator::Passthrough);
    let tx_hash = ckb_client
        .send_transaction(json_tx.inner, outputs_validator)
        .expect("send transaction");
    println!(">>> tx {:#x} sent! <<<", tx_hash);
}

fn add_cell_dep(base_tx: TransactionView, outs: &[(&H256, usize)]) -> TransactionView {
    let mut builder = base_tx.as_advanced_builder();
    for (hash, index) in outs {
        let cell_dep = {
            let tx_hash = Byte32::from_slice(hash.as_bytes()).expect("transform tx hash");
            let out_point = OutPoint::new(tx_hash, *index as u32);
            CellDep::new_builder().out_point(out_point).build()
        };
        builder = builder.cell_dep(cell_dep);
    }
    builder.build()
}

fn replace_type_script(tx: TransactionView, room_cfg: &RoomCfg) -> TransactionView {
    let input = tx.inputs().get(0).expect("get input 0");
    let type_script = build_type_script(input, room_cfg);
    let outputs: Vec<_> = tx
        .outputs().into_iter().enumerate().map(|(idx, output)| {
            if 0 == idx {
                output.as_builder().type_(Some(type_script.clone()).pack()).build()
            } else {
                output
            }
        }).collect();

    tx.as_advanced_builder().set_outputs(outputs).build()
}

fn placeholder_type_(room_cfg: &RoomCfg) -> Script {
    let type_id = vec![0u8; 32];
    let type_id = Bytes::from(type_id);
    build_type_script_with_args(type_id, room_cfg)
}

fn build_type_script(input: CellInput, room_cfg: &RoomCfg) -> Script {
    let mut blake2b = new_blake2b();
    blake2b.update(input.as_slice());
    blake2b.update(&0u64.to_le_bytes()); // output index
    let mut ret = vec![0u8; 32];
    blake2b.finalize(&mut ret);
    let type_id = Bytes::from(ret);
    build_type_script_with_args(type_id, room_cfg)
}

fn build_type_script_with_args(type_id: Bytes, room_cfg: &RoomCfg) -> Script {
    let mut ckb_client = CkbRpcClient::new(room_cfg.ckb_rpc.as_str());
    let out_point_json = json_types::OutPoint {
        tx_hash: room_cfg.operator_script_tx_hash.clone(),
        index: ckb_jsonrpc_types::Uint32::from(room_cfg.operator_script_tx_index as u32),
    };
    let cell_status = ckb_client.get_live_cell(out_point_json, true).unwrap();
    let cell = cell_status.cell.expect("get the operator cell");

    let code_hash = cell.data.expect("get operator data").hash;

    Script::new_builder()
        .code_hash(Byte32::from_slice(code_hash.as_bytes()).expect("convert code hash to Byte32"))
        .hash_type(ScriptHashType::Data1.into())
        .args(type_id.pack())
        .build()
}

fn rsa_pubkey_data(pubkey: &RsaPublicKey) -> Vec<u8> {
    let mut e = pubkey.e().to_bytes_le();
    let mut n = pubkey.n().to_bytes_le();
    while e.len() < 4 {
        e.push(0);
    }
    while n.len() < pubkey.size() {
        n.push(0)
    }
    e.extend(n);
    e
}
#[derive(Serialize, Deserialize)]
struct KeyPair {
    priv_key: RsaPrivateKey,
    pub_key: RsaPublicKey,
}
fn gen_keypair(bit_size: usize) -> KeyPair {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, bit_size).expect("generate a key");
    let pub_key = priv_key.to_public_key();
    KeyPair { priv_key, pub_key }
}

struct RoomInfo {
    current_count: u64,
    message_price: u64,
    timelock: u64,
    // Host's RSA public key blake160 hash
    host_pubkey: RsaPublicKey,
    // Host's lock script hash, for receiving the charge capacity
    host_lock_hash: [u8; 32],
    // Owner's RSA public key blake160 hash
    owner_pubkey: RsaPublicKey,
    members_pubkey_hash: Vec<RsaPublicKey>,
}

fn rsa_pubkey_blake160(pubkey: &RsaPublicKey) -> [u8; 20] {
    let hash = blake2b_256(&rsa_pubkey_data(pubkey));
    let mut blake160 = [0u8; 20];
    blake160.copy_from_slice(&hash[0..20]);
    blake160
}

impl RoomInfo {
    fn to_cell_data(&self) -> Vec<u8> {
        let data_len = 8 + 8 + 8 + 20 + 32 + 20 + 2 + 20 * self.members_pubkey_hash.len();
        let mut data = vec![0u8; data_len];
        data[0..8].copy_from_slice(&self.current_count.to_le_bytes()[..]);
        data[8..16].copy_from_slice(&self.message_price.to_le_bytes()[..]);
        data[16..24].copy_from_slice(&self.timelock.to_le_bytes()[..]);
        data[24..44].copy_from_slice(&rsa_pubkey_blake160(&self.host_pubkey)[..]);
        data[44..76].copy_from_slice(&self.host_lock_hash[..]);
        data[76..96].copy_from_slice(&rsa_pubkey_blake160(&self.owner_pubkey)[..]);
        data[96..98].copy_from_slice(&(self.members_pubkey_hash.len() as u16).to_le_bytes()[..]);
        let mut offset = 98;
        for pubkey in &self.members_pubkey_hash {
            data[offset..offset + 20].copy_from_slice(&rsa_pubkey_blake160(pubkey)[..]);
            offset += 20;
        }
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_skip_0x() {
        assert_eq!("deadbeef", skip_0x("0xdeadbeef"));
        assert_eq!("deadbeef", skip_0x("0Xdeadbeef"));
        assert_eq!("deadbeef", skip_0x("deadbeef"));
        assert_eq!("deadbeef", skip_0x("deadbeef"));
        assert_eq!("de", skip_0x("de"));
        assert_eq!("de", skip_0x("de"));
        assert_eq!("", skip_0x("0X"));
        assert_eq!("", skip_0x("0x"));
    }
}
