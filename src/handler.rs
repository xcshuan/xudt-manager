use ckb_sdk::{
    core::TransactionBuilder,
    transaction::handler::{HandlerContext, ScriptHandler},
    tx_builder::TxBuilderError,
    NetworkInfo, NetworkType, ScriptGroup, ScriptId,
};
use ckb_types::{
    core::DepType,
    h256,
    packed::{CellDep, OutPoint},
    prelude::*,
};

/// xUDT script handler, it will setup the [Simple UDT](https://github.com/XuJiandong/rfcs/blob/xudt/rfcs/0052-extensible-udt/0052-extensible-udt.md) related data automatically.
pub struct XudtHandler {
    cell_deps: Vec<CellDep>,
    xudt_script_id: ScriptId,
}

pub struct XudtContext;

impl HandlerContext for XudtContext {}

impl XudtHandler {
    pub fn new_with_network(network: &NetworkInfo) -> Result<Self, TxBuilderError> {
        let (out_point, xudt_script_id) = if network.network_type == NetworkType::Mainnet {
            (
                OutPoint::new_builder()
                    .tx_hash(
                        h256!("0xc07844ce21b38e4b071dd0e1ee3b0e27afd8d7532491327f39b786343f558ab7")
                            .pack(),
                    )
                    .index(0u32.pack())
                    .build(),
                ScriptId::new_data1(h256!(
                    "0x50bd8d6680b8b9cf98b73f3c08faf8b2a21914311954118ad6609be6e78a1b95"
                )),
            )
        } else if network.network_type == NetworkType::Testnet {
            (
                OutPoint::new_builder()
                    .tx_hash(
                        h256!("0xbf6fb538763efec2a70a6a3dcb7242787087e1030c4e7d86585bc63a9d337f5f")
                            .pack(),
                    )
                    .index(0u32.pack())
                    .build(),
                ScriptId::new_type(h256!(
                    "0x25c29dc317811a6f6f3985a7a9ebc4838bd388d19d0feeecf0bcd60f6c0975bb"
                )),
            )
        } else {
            return Err(TxBuilderError::UnsupportedNetworkType(network.network_type));
        };

        let cell_dep = CellDep::new_builder()
            .out_point(out_point)
            .dep_type(DepType::Code.into())
            .build();

        Ok(Self {
            cell_deps: vec![cell_dep],
            xudt_script_id,
        })
    }
}

impl ScriptHandler for XudtHandler {
    fn build_transaction(
        &self,
        tx_builder: &mut TransactionBuilder,
        script_group: &mut ScriptGroup,
        context: &dyn HandlerContext,
    ) -> Result<bool, TxBuilderError> {
        if context.as_any().is::<XudtContext>()
            && ScriptId::from(&script_group.script) == self.xudt_script_id
        {
            tx_builder.dedup_cell_deps(self.cell_deps.clone());
            if script_group.input_indices.is_empty() {
                // issue xudt, do nothing
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn init(&mut self, _network: &NetworkInfo) -> Result<(), TxBuilderError> {
        Ok(())
    }
}
