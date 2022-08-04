use ckb_sdk::CkbRpcClient;
use ckb_types::{
    core::ScriptHashType,
    packed::{Byte32, Script},
    prelude::*, H256,
};
use rsa::{
    PublicKeyParts,
    RsaPrivateKey,
    RsaPublicKey,
};

use ckb_hash::blake2b_256;

use clap::{Args, Parser, Subcommand};
use serde_derive::{Deserialize, Serialize};
use std::fs;

use ckb_jsonrpc_types as json_types;
fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Create(create_args) => {
            println!("create");
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
    host_lock_tx_indx: usize,
    host_lock_args: String,
    /// CKB rpc url, default_value = "http://127.0.0.1:8114")
    ckb_rpc: String,
    /// CKB indexer rpc url, default_value = "http://127.0.0.1:8116")
    ckb_indexer: String,
}
impl RoomCfg {
    fn host_lock_hash(&self) -> [u8; 32] {
        let script = self.build_lock_script(
            &self.host_lock_tx_hash,
            self.host_lock_tx_indx,
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
        let cell_status = ckb_client.get_live_cell(out_point_json, false).unwrap();
        let code_hash = cell_status.cell.unwrap().data.unwrap().hash;
        let args = hex::decode(lock_args).expect("decode host lock args");
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
    output_lock_hash: H256,
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
    let out_lock_script = room_cfg.build_lock_script(
        &create_args.output_lock_hash,
        create_args.output_lock_index,
        &create_args.output_lock_args,
    );
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
