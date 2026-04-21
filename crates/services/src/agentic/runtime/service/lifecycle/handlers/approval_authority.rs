use crate::agentic::runtime::keys::get_approval_authority_key;
use crate::agentic::runtime::types::{
    RegisterApprovalAuthorityParams, RevokeApprovalAuthorityParams,
};
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_types::codec;
use ioi_types::error::TransactionError;

pub async fn handle_register_approval_authority(
    state: &mut dyn StateAccess,
    params: RegisterApprovalAuthorityParams,
    ctx: &TxContext<'_>,
) -> Result<(), TransactionError> {
    params
        .authority
        .verify()
        .map_err(|e| TransactionError::Invalid(format!("Invalid approval authority: {}", e)))?;
    if ctx.signer_account_id.0 != params.authority.authority_id {
        return Err(TransactionError::Invalid(
            "approval authority signer does not match authority_id".to_string(),
        ));
    }
    let key = get_approval_authority_key(&params.authority.authority_id);
    state.insert(&key, &codec::to_bytes_canonical(&params.authority)?)?;
    Ok(())
}

pub async fn handle_revoke_approval_authority(
    state: &mut dyn StateAccess,
    params: RevokeApprovalAuthorityParams,
    ctx: &TxContext<'_>,
) -> Result<(), TransactionError> {
    if ctx.signer_account_id.0 != params.authority_id {
        return Err(TransactionError::Invalid(
            "approval authority signer does not match authority_id".to_string(),
        ));
    }
    let key = get_approval_authority_key(&params.authority_id);
    let bytes = state.get(&key)?.ok_or_else(|| {
        TransactionError::Invalid("approval authority is not registered".to_string())
    })?;
    let mut authority: ioi_types::app::ApprovalAuthority = codec::from_bytes_canonical(&bytes)?;
    authority.revoked = true;
    state.insert(&key, &codec::to_bytes_canonical(&authority)?)?;
    Ok(())
}
