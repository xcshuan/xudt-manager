use ckb_hash::{blake2b_256, new_blake2b};
use ckb_sdk::{
    constants::SIGHASH_TYPE_HASH,
    traits::{CellCollector, CellQueryOptions, DefaultCellCollector, ValueRangeOption},
    transaction::{
        builder::CkbTransactionBuilder,
        input::TransactionInput,
        signer::{SignContexts, TransactionSigner},
        TransactionBuilderConfiguration,
    },
    {Address, AddressPayload, CkbRpcClient, NetworkInfo, SECP256K1},
};
use ckb_types::{
    bytes::Bytes,
    core::{DepType, ScriptHashType},
    h256,
    packed::{Bytes as PackBytes, CellDep, CellInput, CellOutput, OutPoint, Script},
    prelude::{Builder, Entity, Pack},
    H256,
};
use std::env;
use std::error::Error as StdErr;
use std::str::FromStr;
use xudt_manager::{handler::XudtHandler, XudtTransactionBuilder};

const UNIQUE_ARGS_SIZE: usize = 20;
const ISSUE_DECIMAL: u8 = 8;
const ISSUE_NAME: &'static str = "XUDT Test Token";
const ISSUE_SYMBOL: &'static str = "XTT";
const ISSUE_AMOUNT: u128 = 2100_000;
const NANOS_PER_SEC: u64 = 1_000_000_000;

fn main() -> Result<(), Box<dyn StdErr>> {
    let network_info = NetworkInfo::testnet();
    let mut configuration =
        TransactionBuilderConfiguration::new_with_network(network_info.clone())?;
    configuration
        .register_script_handler(Box::new(XudtHandler::new_with_network(&network_info)?) as Box<_>);

    let issue_private_key_words = env::var("ISSUE_PRIVATE_KEY")?;
    let issue_private_key = H256::from_str(issue_private_key_words.as_ref())?;

    let (issue_lock_script, issue_addr) = {
        let secret_key = secp256k1::SecretKey::from_slice(issue_private_key.as_bytes())
            .map_err(|err| format!("invalid sender secret key: {}", err))?;

        let pubkey = secp256k1::PublicKey::from_secret_key(&SECP256K1, &secret_key);
        let hash160 = blake2b_256(&pubkey.serialize()[..])[0..20].to_vec();
        let payload = AddressPayload::from_pubkey(&pubkey);
        (
            Script::new_builder()
                .code_hash(SIGHASH_TYPE_HASH.pack())
                .hash_type(ScriptHashType::Type.into())
                .args(Bytes::from(hash160).pack())
                .build(),
            Address::new(network_info.network_type, payload, true),
        )
    };

    println!("sender_addr: {}", issue_addr);

    let mut cell_collector = DefaultCellCollector::new(&network_info.url);

    let ckb_query = {
        let mut query = CellQueryOptions::new_lock(issue_lock_script.clone());
        query.secondary_script_len_range = Some(ValueRangeOption::new_exact(0));
        query.data_len_range = Some(ValueRangeOption::new_exact(0));
        query
    };

    let mut ckb_cells = cell_collector.collect_live_cells(&ckb_query, true)?.0;
    ckb_cells.retain(|cell| cell.output.type_().is_none());
    assert!(!ckb_cells.is_empty());

    let unique_type_script = Script::new_builder()
        .code_hash(
            h256!("0x8e341bcfec6393dcd41e635733ff2dca00a6af546949f70c57a706c0f344df8b").pack(),
        )
        .hash_type(ScriptHashType::Type.into())
        .args(generate_unique_type_args(
            CellInput::new_builder()
                .previous_output(ckb_cells[0].clone().out_point)
                .build(),
            1,
        ))
        .build();

    let mut builder = XudtTransactionBuilder::new(
        issue_lock_script.clone(),
        issue_lock_script.clone(),
        configuration,
        vec![],
    );

    builder.add_input(
        TransactionInput {
            live_cell: ckb_cells[0].clone(),
            since: 0,
        },
        0,
    );

    let xudt_type = Script::new_builder()
        .code_hash(
            h256!("0x25c29dc317811a6f6f3985a7a9ebc4838bd388d19d0feeecf0bcd60f6c0975bb").pack(),
        )
        .hash_type(ScriptHashType::Type.into())
        .args(Bytes::from(issue_lock_script.calc_script_hash().as_bytes()).pack())
        .build();

    let issue_amount = ISSUE_AMOUNT * (10u128.pow(ISSUE_DECIMAL as u32));
    builder.add_output_and_data(
        CellOutput::new_builder()
            .lock(issue_lock_script.clone())
            .type_(Some(xudt_type).pack())
            .capacity(
                (calculate_udt_cell_capacity(issue_lock_script.clone()) as u64 * NANOS_PER_SEC)
                    .pack(),
            )
            .build(),
        issue_amount.to_le_bytes().pack(),
    );

    builder.add_output_and_data(
        CellOutput::new_builder()
            .lock(issue_lock_script.clone())
            .type_(Some(unique_type_script).pack())
            .capacity(
                (calculate_xudt_token_info_cell_capacity(issue_lock_script.clone()) as u64
                    * NANOS_PER_SEC)
                    .pack(),
            )
            .build(),
        encode_token_info().pack(),
    );

    builder.add_output_and_data(
        CellOutput::new_builder()
            .lock(issue_lock_script.clone())
            .build(),
        PackBytes::default(),
    );

    builder.add_cell_deps(vec![
        CellDep::new_builder()
            .out_point(
                OutPoint::new_builder()
                    .tx_hash(
                        h256!("0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37")
                            .pack(),
                    )
                    .index(0u32.pack())
                    .build(),
            )
            .dep_type(DepType::DepGroup.into())
            .build(),
        CellDep::new_builder()
            .out_point(
                OutPoint::new_builder()
                    .tx_hash(
                        h256!("0xff91b063c78ed06f10a1ed436122bd7d671f9a72ef5f5fa28d05252c17cf4cef")
                            .pack(),
                    )
                    .index(0u32.pack())
                    .build(),
            )
            .build(),
        CellDep::new_builder()
            .out_point(
                OutPoint::new_builder()
                    .tx_hash(
                        h256!("0xbf6fb538763efec2a70a6a3dcb7242787087e1030c4e7d86585bc63a9d337f5f")
                            .pack(),
                    )
                    .index(0u32.pack())
                    .build(),
            )
            .build(),
    ]);

    let mut tx_with_groups = builder.build(&Default::default())?;
    let private_keys = vec![issue_private_key];
    TransactionSigner::new(&network_info)
        .sign_transaction(
            &mut tx_with_groups,
            &SignContexts::new_sighash_h256(private_keys).unwrap(),
        )
        .unwrap();

    let json_tx = ckb_jsonrpc_types::TransactionView::from(tx_with_groups.get_tx_view().clone());
    println!("tx: {}", serde_json::to_string_pretty(&json_tx).unwrap());

    let tx_hash = CkbRpcClient::new(network_info.url.as_str())
        .send_transaction(json_tx.inner, None)
        .expect("send transaction");

    println!(">>> tx {} sent! <<<", tx_hash);

    Ok(())
}

fn generate_unique_type_args(first_input: CellInput, first_output_index: u64) -> PackBytes {
    let input = first_input.as_bytes();
    let mut hasher = new_blake2b();
    hasher.update(input.as_ref());
    hasher.update(first_output_index.to_le_bytes().as_ref());
    let mut args = [0u8; 40];
    hasher.finalize(&mut args);
    args[0..UNIQUE_ARGS_SIZE].pack()
}

fn calculate_xudt_token_info_cell_capacity(lock: Script) -> usize {
    let lock_size = lock.args().len() + 33;
    let cell_data_size = encode_token_info().len() / 2;
    let unique_type_size = 32 + 1 + UNIQUE_ARGS_SIZE;
    lock_size + unique_type_size + 8 + cell_data_size
}

fn encode_token_info() -> Vec<u8> {
    let decimal = hex::encode(&vec![ISSUE_DECIMAL]);
    let name = hex::encode(ISSUE_NAME);
    let name_size = hex::encode(&vec![(name.len() / 2) as u8]);
    let symbol = hex::encode(ISSUE_SYMBOL);
    let symbol_size = hex::encode(&vec![(symbol.len() / 2) as u8]);

    [
        decimal.as_bytes(),
        name_size.as_bytes(),
        name.as_bytes(),
        symbol_size.as_bytes(),
        symbol.as_bytes(),
    ]
    .concat()
}

fn calculate_udt_cell_capacity(lock: Script) -> usize {
    let args_size = lock.args().len();
    let type_args = 32;
    let cell_size = 33 + args_size + 33 + type_args + 8 + 16;
    cell_size + 1
}
