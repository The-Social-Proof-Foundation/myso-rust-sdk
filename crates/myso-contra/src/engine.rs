// Copyright (c) The Social Proof Foundation, LLC.
// SPDX-License-Identifier: Apache-2.0

//! Builds a programmable-transaction plan the phone executes and signs.
//! The account key is an argument and is not stored.

use std::str::FromStr;

use myso_contra_crypto::amount::{
    EncryptedAmount, WellFormedLimb, collapse_blindings, encrypt_amount,
};
use myso_contra_crypto::elgamal::Ciphertext;
use myso_contra_crypto::group::{self, g, mul};
use myso_contra_crypto::group::{RistrettoPoint, Scalar};
use myso_contra_crypto::proofs::{
    DdhProof, ElGamalProof, KeyConsistencyProof, MultiRecipient, prove_is_zero, scalar_to_u32_limbs,
};
use myso_contra_crypto::types::{PROTOCOL_DDH, PROTOCOL_ELGAMAL, PROTOCOL_KEY_CONSISTENCY, dst};
use myso_contra_crypto::well_formed::contra_range_proofs;
use myso_sdk_types::{Address, Identifier, StructTag, TypeTag};
use serde_json::{Value, json};

use crate::error::ContraError;

const DENY_LIST: &str = "0x403";

pub fn token_account_object_id(
    package_id: &str,
    account_registry_id: &str,
    owner: &str,
    token_type: &str,
) -> Result<String, ContraError> {
    let package = address(package_id)?;
    let registry = address(account_registry_id)?;
    let owner = address(owner)?;
    let token = StructTag::from_str(token_type)
        .map_err(|error| ContraError::InvalidArgument(error.to_string()))?;
    let account_key = TypeTag::from_str(&format!("{}::contra::AccountKey", package))
        .map_err(|error| ContraError::InvalidArgument(error.to_string()))?;
    let account = registry.derive_object_id(&account_key, &bcs::to_bytes(&owner).expect("address"));
    let field_key = TypeTag::Struct(Box::new(struct_tag(
        &package,
        "TokenAccountKey",
        Some(&token),
    )));
    // Same name bytes as web `bcs.byteVector().serialize([])` → `[0]`, not a raw empty slice.
    Ok(account
        .derive_dynamic_child_id(&field_key, &empty_vec_name())
        .to_string())
}

pub fn account_public_key_hex(token_account_json: &str) -> Result<String, ContraError> {
    let value: Value = serde_json::from_str(token_account_json)
        .map_err(|error| ContraError::Failed(error.to_string()))?;
    let account =
        find_account(&value).ok_or_else(|| ContraError::Failed("missing public key".into()))?;
    let body =
        field(account, "pk").ok_or_else(|| ContraError::Failed("missing public key".into()))?;
    let bytes = byte_field(body)?;
    if bytes.len() != 32 {
        return Err(ContraError::Failed("public key is not 32 bytes".into()));
    }
    Ok(hex::encode(bytes))
}

pub fn decrypt_balance(
    account_key: &[u8],
    token_account_json: &str,
) -> Result<(u64, u64, u64), ContraError> {
    let secret = account_scalar(account_key)?;
    let snapshot = parse_snapshot(
        &serde_json::from_str(token_account_json)
            .map_err(|e| ContraError::Failed(e.to_string()))?,
    )?;
    let inverse = secret.invert();
    Ok((
        snapshot
            .active
            .decrypt(&inverse)
            .map_err(ContraError::Failed)?,
        snapshot
            .pending
            .decrypt(&inverse)
            .map_err(ContraError::Failed)?,
        snapshot.pending_public,
    ))
}

pub fn plan_transaction(request_json: &str) -> Result<String, ContraError> {
    let request: Value =
        serde_json::from_str(request_json).map_err(|e| ContraError::Failed(e.to_string()))?;
    let action = required_str(&request, "action")?;
    let plan = match action {
        "create" => plan_create(&request)?,
        "wrap" => plan_wrap(&request)?,
        "updateBalance" => plan_update(&request)?,
        "transfer" => plan_transfer(&request)?,
        "unwrap" => plan_unwrap(&request)?,
        other => {
            return Err(ContraError::InvalidArgument(format!(
                "unknown action {other}"
            )));
        }
    };
    serde_json::to_string(&plan).map_err(|e| ContraError::Failed(e.to_string()))
}

struct Ids {
    package: String,
    account: String,
    token: String,
    pool: String,
    token_type: String,
    session: [u8; 21],
}

fn ids(request: &Value) -> Result<Ids, ContraError> {
    let package = address(required_str(request, "packageId")?)?;
    let registry = address(required_str(request, "accountRegistryId")?)?;
    let token_registry = address(required_str(request, "tokenRegistryId")?)?;
    let owner = address(required_str(request, "owner")?)?;
    let token_type = StructTag::from_str(required_str(request, "tokenType")?)
        .map_err(|e| ContraError::InvalidArgument(e.to_string()))?;
    let package_text = package.to_string();
    let account_key = TypeTag::from_str(&format!("{package_text}::contra::AccountKey"))
        .map_err(|e| ContraError::InvalidArgument(e.to_string()))?;
    let account = registry.derive_object_id(&account_key, &bcs::to_bytes(&owner).expect("address"));
    let token_key = TypeTag::Struct(Box::new(struct_tag(
        &package,
        "TokenKey",
        Some(&token_type),
    )));
    let name = empty_vec_name();
    let token = token_registry.derive_object_id(&token_key, &name);
    let pool_key = TypeTag::from_str(&format!("{package_text}::contra::PoolKey"))
        .map_err(|e| ContraError::InvalidArgument(e.to_string()))?;
    let pool = token.derive_object_id(&pool_key, &name);
    let token_account_key = TypeTag::Struct(Box::new(struct_tag(
        &package,
        "TokenAccountKey",
        Some(&token_type),
    )));
    let unique = account.derive_object_id(&token_account_key, &name);
    let mut session_id = [0u8; 20];
    session_id.copy_from_slice(&unique.as_bytes()[..20]);
    Ok(Ids {
        package: package_text,
        account: account.to_string(),
        token: token.to_string(),
        pool: pool.to_string(),
        token_type: token_type.to_string(),
        session: dst(&session_id, PROTOCOL_ELGAMAL),
    })
}

fn struct_tag(package: &Address, name: &str, arg: Option<&StructTag>) -> StructTag {
    StructTag::new(
        *package,
        Identifier::from_static("contra"),
        Identifier::new(name).expect("identifier"),
        arg.cloned()
            .map(|tag| TypeTag::Struct(Box::new(tag)))
            .into_iter()
            .collect(),
    )
}

struct Planner {
    steps: Vec<Value>,
}

impl Planner {
    fn new() -> Self {
        Self { steps: Vec::new() }
    }

    fn call(
        &mut self,
        target: &str,
        type_arguments: Vec<String>,
        arguments: Vec<Value>,
        returns: u8,
    ) -> usize {
        let index = self.steps.len();
        self.steps.push(json!({
            "op": "moveCall",
            "target": target,
            "typeArguments": type_arguments,
            "arguments": arguments,
            "returns": returns,
        }));
        index
    }

    fn vector(&mut self, type_tag: &str, elements: Vec<Value>) -> usize {
        let index = self.steps.len();
        self.steps.push(json!({
            "op": "makeMoveVec",
            "type": type_tag,
            "elements": elements,
        }));
        index
    }

    fn split(&mut self, coin: Value, amount: u64) -> usize {
        let index = self.steps.len();
        self.steps.push(json!({
            "op": "splitCoins",
            "coin": coin,
            "amount": amount,
        }));
        index
    }

    fn merge(&mut self, destination: Value, sources: Vec<Value>) {
        self.steps.push(json!({
            "op": "mergeCoins",
            "destination": destination,
            "sources": sources,
        }));
    }

    fn transfer(&mut self, objects: Vec<Value>, address: &str) {
        self.steps.push(json!({
            "op": "transferObjects",
            "objects": objects,
            "address": address,
        }));
    }

    fn finish(self) -> Value {
        json!({ "steps": self.steps })
    }
}

fn result(index: usize) -> Value {
    json!({ "result": index })
}
fn object(id: &str) -> Value {
    json!({ "object": id })
}
fn pure_u64(value: u64) -> Value {
    json!({ "u64": value })
}
fn pure_address(value: &str) -> Value {
    json!({ "address": value })
}
fn pure_bytes(bytes: &[u8]) -> Value {
    json!({ "bytes": hex::encode(bytes) })
}
fn pure_matrix(rows: &[Vec<u8>]) -> Value {
    json!({ "byteMatrix": rows.iter().map(hex::encode).collect::<Vec<_>>() })
}

fn plan_create(request: &Value) -> Result<Value, ContraError> {
    let ids = ids(request)?;
    let secret = account_scalar(&hex_key(request)?)?;
    let public = mul(&g(), &secret);
    let auditors = point_list(request.get("auditorKeys").unwrap_or(&Value::Null))?;
    let mut plan = Planner::new();
    let account = if request.get("hasAccount").and_then(Value::as_bool) == Some(false) {
        plan.call(
            &format!("{}::contra::new_account", ids.package),
            vec![],
            vec![
                object(required_str(request, "accountRegistryId")?),
                pure_address(required_str(request, "owner")?),
            ],
            1,
        )
    } else {
        usize::MAX
    };
    let auth = authorize(&mut plan, &ids);
    let pk = plan.call(
        "0x2::ristretto255::g_from_bytes",
        vec![],
        vec![pure_bytes(&group::point_bytes(&public))],
        1,
    );
    let key_encryption = key_encryption_option(&mut plan, &ids, &secret, &public, &auditors)?;
    let account_arg = if account == usize::MAX {
        object(&ids.account)
    } else {
        result(account)
    };
    plan.call(
        &format!("{}::contra::register", ids.package),
        vec![ids.token_type.clone()],
        vec![
            account_arg,
            result(auth),
            object(&ids.token),
            result(pk),
            result(key_encryption),
        ],
        0,
    );
    if account != usize::MAX {
        plan.call(
            &format!("{}::contra::share_account", ids.package),
            vec![],
            vec![result(account)],
            0,
        );
    }
    Ok(plan.finish())
}

fn plan_wrap(request: &Value) -> Result<Value, ContraError> {
    let ids = ids(request)?;
    let amount = required_u64(request, "amount")?;
    let primary = required_str(request, "coinObjectId")?;
    let merges = string_list(request.get("mergeCoinObjectIds").unwrap_or(&Value::Null));
    let mut plan = Planner::new();
    if !merges.is_empty() {
        plan.merge(
            object(primary),
            merges.iter().map(|id| object(id)).collect(),
        );
    }
    let coin = plan.split(object(primary), amount);
    let auth = authorize(&mut plan, &ids);
    plan.call(
        &format!("{}::contra::wrap", ids.package),
        vec![ids.token_type],
        vec![
            object(&ids.account),
            result(auth),
            object(&ids.token),
            object(DENY_LIST),
            object(&ids.pool),
            result(coin),
            pure_bytes(&[]),
        ],
        0,
    );
    Ok(plan.finish())
}

fn plan_update(request: &Value) -> Result<Value, ContraError> {
    let ids = ids(request)?;
    let secret = account_scalar(&hex_key(request)?)?;
    let snapshot = snapshot_from_request(request)?;
    let mut plan = Planner::new();
    let auth = authorize(&mut plan, &ids);
    let (should_merge, new_balance, balance_proof) =
        balance_update(&ids, &secret, &snapshot, 0, Ciphertext::trivial(0))?;
    if should_merge {
        plan.call(
            &format!("{}::contra::merge", ids.package),
            vec![ids.token_type.clone()],
            vec![object(&ids.account), result(auth)],
            0,
        );
    }
    let (amount, proof) = encrypted_amount_and_proof(&mut plan, &ids, &new_balance)?;
    let ddh = ddh_call(&mut plan, &ids, &balance_proof);
    plan.call(
        &format!("{}::contra::update_active_balance", ids.package),
        vec![ids.token_type],
        vec![
            object(&ids.account),
            result(auth),
            result(amount),
            result(proof),
            result(ddh),
        ],
        0,
    );
    Ok(plan.finish())
}

fn plan_transfer(request: &Value) -> Result<Value, ContraError> {
    let ids = ids(request)?;
    let secret = account_scalar(&hex_key(request)?)?;
    let sender_pk = mul(&g(), &secret);
    let receiver_pk = point_from_hex(required_str(request, "receiverPublicKey")?)?;
    let amount = required_u64(request, "amount")?;
    let receiver = required_str(request, "receiver")?;
    let snapshot = snapshot_from_request(request)?;
    let elgamal = ids.session;
    let receiver_limbs = encrypt_amount(&elgamal, &receiver_pk, amount);
    let sender_limbs: Vec<Ciphertext> = receiver_limbs
        .iter()
        .map(|limb| Ciphertext::encrypt(&sender_pk, limb.value, &limb.blinding))
        .collect();
    let total_blinding = collapse_blindings(
        &receiver_limbs
            .iter()
            .map(|limb| limb.blinding)
            .collect::<Vec<_>>(),
    );
    let total = Ciphertext::encrypt(&sender_pk, amount, &total_blinding);
    let consistency = ElGamalProof::prove(&elgamal, &total_blinding, amount, &total, &sender_pk);
    let (should_merge, new_balance, balance_proof) =
        balance_update(&ids, &secret, &snapshot, amount, total)?;
    let mut plan = Planner::new();
    let auth = authorize(&mut plan, &ids);
    if should_merge {
        plan.call(
            &format!("{}::contra::merge", ids.package),
            vec![ids.token_type.clone()],
            vec![object(&ids.account), result(auth)],
            0,
        );
    }
    let receiver_amount = encrypted_amount_call(
        &mut plan,
        &ids,
        &receiver_limbs
            .iter()
            .map(|limb| limb.ciphertext)
            .collect::<Vec<_>>(),
    );
    let sender_amount = encrypted_amount_call(&mut plan, &ids, &sender_limbs);
    let amounts_type = format!("{}::encrypted_amount::EncryptedAmount", ids.package);
    let receiver_amounts = plan.vector(&amounts_type, vec![result(receiver_amount)]);
    let sender_amounts = plan.vector(&amounts_type, vec![result(sender_amount)]);
    let proof = well_formed_call(
        &mut plan,
        &ids,
        &[receiver_limbs.to_vec(), new_balance.to_vec()],
    )?;
    let pks = plan.call(
        &format!("{}::decode::g_vector", ids.package),
        vec![],
        vec![pure_matrix(&[group::point_bytes(&receiver_pk).to_vec()])],
        1,
    );
    let consistency_arg = elgamal_call(&mut plan, &ids, &consistency);
    let new_amount = encrypted_amount_call(
        &mut plan,
        &ids,
        &new_balance
            .iter()
            .map(|limb| limb.ciphertext)
            .collect::<Vec<_>>(),
    );
    let ddh = ddh_call(&mut plan, &ids, &balance_proof);
    let batch = plan.call(
        &format!("{}::contra::batched_transfer", ids.package),
        vec![ids.token_type.clone()],
        vec![
            object(&ids.account),
            result(auth),
            object(&ids.token),
            object(DENY_LIST),
            result(pks),
            result(receiver_amounts),
            result(proof),
            result(sender_amounts),
            result(consistency_arg),
            result(new_amount),
            result(ddh),
        ],
        1,
    );
    let receiver_account = receiver_account_id(request, receiver)?;
    let added = plan.call(
        &format!("{}::contra::add_to_batch", ids.package),
        vec![ids.token_type.clone()],
        vec![
            result(batch),
            object(&receiver_account),
            pure_bytes(&[]),
            object(DENY_LIST),
        ],
        1,
    );
    plan.call(
        &format!("{}::contra::try_finalize", ids.package),
        vec![ids.token_type],
        vec![result(added)],
        0,
    );
    Ok(plan.finish())
}

fn plan_unwrap(request: &Value) -> Result<Value, ContraError> {
    let ids = ids(request)?;
    let secret = account_scalar(&hex_key(request)?)?;
    let amount = required_u64(request, "amount")?;
    let snapshot = snapshot_from_request(request)?;
    let (should_merge, new_balance, balance_proof) = balance_update(
        &ids,
        &secret,
        &snapshot,
        amount,
        Ciphertext::trivial(amount),
    )?;
    let mut plan = Planner::new();
    let auth = authorize(&mut plan, &ids);
    if should_merge {
        plan.call(
            &format!("{}::contra::merge", ids.package),
            vec![ids.token_type.clone()],
            vec![object(&ids.account), result(auth)],
            0,
        );
    }
    let (amount_arg, proof) = encrypted_amount_and_proof(&mut plan, &ids, &new_balance)?;
    let ddh = ddh_call(&mut plan, &ids, &balance_proof);
    let coin = plan.call(
        &format!("{}::contra::try_unwrap", ids.package),
        vec![ids.token_type],
        vec![
            object(&ids.account),
            result(auth),
            object(&ids.token),
            object(DENY_LIST),
            object(&ids.pool),
            result(amount_arg),
            result(proof),
            pure_u64(amount),
            result(ddh),
        ],
        1,
    );
    plan.transfer(vec![result(coin)], required_str(request, "owner")?);
    Ok(plan.finish())
}

fn authorize(plan: &mut Planner, ids: &Ids) -> usize {
    plan.call(
        &format!("{}::contra::authorize_as_sender", ids.package),
        vec![ids.token_type.clone()],
        vec![object(&ids.token)],
        1,
    )
}

fn balance_update(
    ids: &Ids,
    secret: &Scalar,
    snapshot: &Snapshot,
    amount: u64,
    diff: Ciphertext,
) -> Result<(bool, Vec<WellFormedLimb>, DdhProof), ContraError> {
    let inverse = secret.invert();
    let active = snapshot
        .active
        .decrypt(&inverse)
        .map_err(ContraError::Failed)?;
    let pending = snapshot
        .pending
        .decrypt(&inverse)
        .map_err(ContraError::Failed)?;
    let should_merge = pending > 0 || snapshot.pending_public > 0;
    let spendable = if should_merge {
        active + pending + snapshot.pending_public
    } else {
        active
    };
    if amount > spendable {
        return Err(ContraError::Failed(
            "Not enough private balance.".to_owned(),
        ));
    }
    let old = if should_merge {
        snapshot
            .active
            .collapse()
            .add(snapshot.pending.collapse())
            .add(Ciphertext::trivial(snapshot.pending_public))
    } else {
        snapshot.active.collapse()
    };
    let public = mul(&g(), secret);
    let elgamal = ids.session;
    let mut ddh_dst = ids.session;
    ddh_dst[20] = PROTOCOL_DDH;
    let new_balance = encrypt_amount(&elgamal, &public, spendable - amount).to_vec();
    let collapsed = EncryptedAmount {
        limbs: [
            new_balance[0].ciphertext,
            new_balance[1].ciphertext,
            new_balance[2].ciphertext,
            new_balance[3].ciphertext,
        ],
    }
    .collapse();
    let proof = prove_is_zero(
        &ddh_dst,
        secret,
        &public,
        &collapsed.subtract(old).add(diff),
    );
    Ok((should_merge, new_balance, proof))
}

fn encrypted_amount_and_proof(
    plan: &mut Planner,
    ids: &Ids,
    limbs: &[WellFormedLimb],
) -> Result<(usize, usize), ContraError> {
    let amount = encrypted_amount_call(
        plan,
        ids,
        &limbs.iter().map(|limb| limb.ciphertext).collect::<Vec<_>>(),
    );
    let proof = well_formed_call(plan, ids, &[limbs.to_vec()])?;
    Ok((amount, proof))
}

fn encrypted_amount_call(plan: &mut Planner, ids: &Ids, limbs: &[Ciphertext]) -> usize {
    let mut rows = Vec::new();
    for limb in limbs {
        rows.push(group::point_bytes(&limb.ciphertext).to_vec());
        rows.push(group::point_bytes(&limb.decryption_handle).to_vec());
    }
    plan.call(
        &format!("{}::decode::encrypted_amount", ids.package),
        vec![],
        vec![pure_matrix(&rows)],
        1,
    )
}

fn well_formed_call(
    plan: &mut Planner,
    ids: &Ids,
    batch: &[Vec<WellFormedLimb>],
) -> Result<usize, ContraError> {
    let flat: Vec<(u64, Scalar)> = batch
        .iter()
        .flat_map(|amount| amount.iter().map(|limb| (limb.value, limb.blinding)))
        .collect();
    let range_proofs = contra_range_proofs(&flat, 16, &ids.session);
    let mut consistency = Vec::new();
    for amount in batch {
        consistency.push(result(consistency_call(plan, ids, amount)));
    }
    let consistency_vec = plan.vector(
        &format!("{}::encrypted_amount::ConsistencyProof", ids.package),
        consistency,
    );
    Ok(plan.call(
        &format!("{}::encrypted_amount::new_well_formed_proof", ids.package),
        vec![],
        vec![pure_matrix(&range_proofs), result(consistency_vec)],
        1,
    ))
}

fn consistency_call(plan: &mut Planner, ids: &Ids, limbs: &[WellFormedLimb]) -> usize {
    let mut rows = Vec::new();
    for limb in limbs {
        rows.push(group::point_bytes(&limb.proof.a).to_vec());
        rows.push(group::point_bytes(&limb.proof.b).to_vec());
        rows.push(group::scalar_bytes(&limb.proof.z1).to_vec());
        rows.push(group::scalar_bytes(&limb.proof.z2).to_vec());
    }
    plan.call(
        &format!("{}::decode::consistency_proof", ids.package),
        vec![],
        vec![pure_matrix(&rows)],
        1,
    )
}

fn ddh_call(plan: &mut Planner, ids: &Ids, proof: &DdhProof) -> usize {
    plan.call(
        &format!("{}::decode::ddh_proof", ids.package),
        vec![],
        vec![pure_matrix(&[
            group::point_bytes(&proof.a).to_vec(),
            group::point_bytes(&proof.b).to_vec(),
            group::scalar_bytes(&proof.z).to_vec(),
        ])],
        1,
    )
}

fn elgamal_call(plan: &mut Planner, ids: &Ids, proof: &ElGamalProof) -> usize {
    plan.call(
        &format!("{}::decode::elgamal_proof", ids.package),
        vec![],
        vec![pure_matrix(&[
            group::point_bytes(&proof.a).to_vec(),
            group::point_bytes(&proof.b).to_vec(),
            group::scalar_bytes(&proof.z1).to_vec(),
            group::scalar_bytes(&proof.z2).to_vec(),
        ])],
        1,
    )
}

fn key_encryption_option(
    plan: &mut Planner,
    ids: &Ids,
    secret: &Scalar,
    public: &RistrettoPoint,
    auditors: &[RistrettoPoint],
) -> Result<usize, ContraError> {
    let option_type = format!("{}::auditors::KeyEncryption", ids.package);
    if auditors.is_empty() {
        return Ok(plan.call("0x1::option::none", vec![option_type], vec![], 1));
    }
    let limbs = scalar_to_u32_limbs(secret);
    let mut blindings = [Scalar::ZERO; 8];
    let mut ciphertexts = Vec::new();
    for (index, limb) in limbs.iter().enumerate() {
        blindings[index] = group::random_scalar();
        ciphertexts.push(MultiRecipient::encrypt(auditors, *limb, &blindings[index]));
    }
    let mut key_dst = ids.session;
    key_dst[20] = PROTOCOL_KEY_CONSISTENCY;
    let proof =
        KeyConsistencyProof::prove(&key_dst, &limbs, public, auditors, &ciphertexts, &blindings);
    let mut encoded = Vec::new();
    for ciphertext in &ciphertexts {
        let mut rows = vec![group::point_bytes(&ciphertext.commitment).to_vec()];
        rows.extend(
            ciphertext
                .handles
                .iter()
                .map(|handle| group::point_bytes(handle).to_vec()),
        );
        encoded.push(result(plan.call(
            &format!("{}::decode::multi_recipient_encryption", ids.package),
            vec![],
            vec![pure_matrix(&rows), pure_u64(auditors.len() as u64)],
            1,
        )));
    }
    let vector = plan.vector(
        &format!("{}::twisted_elgamal::MultiRecipientEncryption", ids.package),
        encoded,
    );
    let mut parts = Vec::new();
    for point in proof.a1.iter().chain(proof.a2.iter()) {
        parts.push(group::point_bytes(point).to_vec());
    }
    parts.push(group::point_bytes(&proof.a3).to_vec());
    for scalar in proof.z1.iter().chain(proof.z2.iter()) {
        parts.push(group::scalar_bytes(scalar).to_vec());
    }
    let proof_arg = plan.call(
        &format!("{}::decode::key_consistency_proof", ids.package),
        vec![],
        vec![pure_matrix(&parts), pure_u64(auditors.len() as u64)],
        1,
    );
    let pairs: Vec<(u64, Scalar)> = limbs.iter().copied().zip(blindings).collect();
    let range = contra_range_proofs(&pairs, 32, &key_dst);
    let built = plan.call(
        &format!("{}::auditors::new_key_encryption", ids.package),
        vec![],
        vec![
            result(vector),
            result(proof_arg),
            pure_bytes(range.first().map(Vec::as_slice).unwrap_or(&[])),
        ],
        1,
    );
    Ok(plan.call(
        "0x1::option::some",
        vec![option_type],
        vec![result(built)],
        1,
    ))
}

struct Snapshot {
    active: EncryptedAmount,
    pending: EncryptedAmount,
    pending_public: u64,
}

fn snapshot_from_request(request: &Value) -> Result<Snapshot, ContraError> {
    let raw = request
        .get("tokenAccountJson")
        .and_then(Value::as_str)
        .unwrap_or("{}");
    parse_snapshot(&serde_json::from_str(raw).map_err(|e| ContraError::Failed(e.to_string()))?)
}

fn parse_snapshot(value: &Value) -> Result<Snapshot, ContraError> {
    let body = find_account(value)
        .ok_or_else(|| ContraError::Failed("token account balance was not in the object".into()))?;
    Ok(Snapshot {
        active: parse_amount(
            field(body, "active")
                .ok_or_else(|| ContraError::Failed("missing active balance".into()))?,
        )?,
        pending: parse_amount(
            field(body, "pending")
                .ok_or_else(|| ContraError::Failed("missing pending balance".into()))?,
        )?,
        pending_public: json_u64(
            field(body, "public_balance")
                .and_then(|v| field(v, "value"))
                .unwrap_or(&Value::Null),
        ),
    })
}

fn parse_amount(value: &Value) -> Result<EncryptedAmount, ContraError> {
    let amount = field(value, "amount").unwrap_or(value);
    let mut limbs = [Ciphertext::trivial(0); 4];
    for (index, name) in ["l0", "l1", "l2", "l3"].iter().enumerate() {
        let limb =
            field(amount, name).ok_or_else(|| ContraError::Failed(format!("missing {name}")))?;
        limbs[index] = Ciphertext {
            ciphertext: point_field(limb, "ciphertext")?,
            decryption_handle: point_field(limb, "decryption_handle")?,
        };
    }
    Ok(EncryptedAmount { limbs })
}

fn point_field(value: &Value, name: &str) -> Result<RistrettoPoint, ContraError> {
    let bytes = byte_field(field(value, name).unwrap_or(&Value::Null))?;
    group::point_from_bytes(&bytes).ok_or_else(|| ContraError::Failed(format!("bad point {name}")))
}

fn byte_field(value: &Value) -> Result<Vec<u8>, ContraError> {
    let bytes = field(value, "bytes").unwrap_or(value);
    match bytes {
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_u64().map(|n| n as u8))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| ContraError::Failed("bad point bytes".into())),
        Value::String(text) => hex::decode(text.trim_start_matches("0x"))
            .map_err(|e| ContraError::Failed(e.to_string())),
        _ => Err(ContraError::Failed("missing point bytes".into())),
    }
}

fn find_account(value: &Value) -> Option<&Value> {
    if field(value, "active").is_some() && field(value, "pending").is_some() {
        return Some(value);
    }
    match value {
        Value::Object(map) => map.values().find_map(find_account),
        Value::Array(items) => items.iter().find_map(find_account),
        _ => None,
    }
}

fn field<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    value
        .get("fields")
        .and_then(|fields| fields.get(name))
        .or(value.get(name))
}

fn json_u64(value: &Value) -> u64 {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        .unwrap_or(0)
}

fn account_scalar(bytes: &[u8]) -> Result<Scalar, ContraError> {
    group::scalar_from_canonical(bytes)
        .ok_or_else(|| ContraError::InvalidArgument("account key is not a canonical scalar".into()))
}

fn hex_key(request: &Value) -> Result<Vec<u8>, ContraError> {
    let text = required_str(request, "accountKey")?;
    hex::decode(text.trim_start_matches("0x"))
        .map_err(|e| ContraError::InvalidArgument(e.to_string()))
}

fn point_from_hex(text: &str) -> Result<RistrettoPoint, ContraError> {
    let bytes = hex::decode(text.trim_start_matches("0x"))
        .map_err(|e| ContraError::InvalidArgument(e.to_string()))?;
    group::point_from_bytes(&bytes)
        .ok_or_else(|| ContraError::InvalidArgument("bad receiver public key".into()))
}

fn point_list(value: &Value) -> Result<Vec<RistrettoPoint>, ContraError> {
    let Value::Array(items) = value else {
        return Ok(Vec::new());
    };
    items
        .iter()
        .filter_map(Value::as_str)
        .map(point_from_hex)
        .collect()
}

fn string_list(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str, ContraError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| ContraError::InvalidArgument(format!("missing {key}")))
}

fn required_u64(value: &Value, key: &str) -> Result<u64, ContraError> {
    let raw = value
        .get(key)
        .ok_or_else(|| ContraError::InvalidArgument(format!("missing {key}")))?;
    json_u64(raw)
        .checked_sub(0)
        .filter(|_| raw.is_string() || raw.is_number())
        .ok_or_else(|| ContraError::InvalidArgument(format!("bad {key}")))
        .and_then(|_| {
            if raw.as_str() == Some("0") || raw.as_u64() == Some(0) {
                Err(ContraError::InvalidArgument(format!("bad {key}")))
            } else if json_u64(raw) == 0 {
                Err(ContraError::InvalidArgument(format!("bad {key}")))
            } else {
                Ok(json_u64(raw))
            }
        })
}

fn address(text: &str) -> Result<Address, ContraError> {
    Address::from_str(text).map_err(|e| ContraError::InvalidArgument(e.to_string()))
}

/// BCS `vector<u8>` with length 0 → `[0]`. Matches TS `bcs.byteVector().serialize([])`.
fn empty_vec_name() -> Vec<u8> {
    bcs::to_bytes(&Vec::<u8>::new()).expect("empty vec BCS")
}

fn receiver_account_id(request: &Value, receiver: &str) -> Result<String, ContraError> {
    let package = address(required_str(request, "packageId")?)?;
    let registry = address(required_str(request, "accountRegistryId")?)?;
    let owner = address(receiver)?;
    let package_text = package.to_string();
    let account_key = TypeTag::from_str(&format!("{package_text}::contra::AccountKey"))
        .map_err(|e| ContraError::InvalidArgument(e.to_string()))?;
    Ok(registry
        .derive_object_id(&account_key, &bcs::to_bytes(&owner).expect("address"))
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_plan_does_not_include_the_account_key() {
        let request = r#"{
            "action":"wrap",
            "packageId":"0xc1fe",
            "accountRegistryId":"0x10",
            "tokenRegistryId":"0x11",
            "owner":"0x22",
            "tokenType":"0x2::myso::MYSO",
            "amount":"5",
            "coinObjectId":"0x33"
        }"#;
        let plan = plan_transaction(request).unwrap();
        assert!(plan.contains("contra::wrap"));
        assert!(!plan.contains("accountKey"));
    }

    #[test]
    fn empty_vec_name_is_bcs_zero_length() {
        assert_eq!(empty_vec_name(), vec![0u8]);
    }

    /// Live testnet MYUSD ConfidentialToken — must match web `getConfidentialTokenId`.
    #[test]
    fn confidential_token_id_matches_web_myusd() {
        let package = address("0xc1fe").unwrap();
        let token_registry =
            address("0xf99d63752b6144d0a786fc7d4894b751bdefac90d61417175d0f27bc35669b0d").unwrap();
        let token_type = StructTag::from_str(
            "0xf862bc40fe05aa0b6779ff7894f0c46a6bed19d179f68116119b9d222a32fb19::myusd::MYUSD",
        )
        .unwrap();
        let token_key = TypeTag::Struct(Box::new(struct_tag(
            &package,
            "TokenKey",
            Some(&token_type),
        )));
        let token = token_registry.derive_object_id(&token_key, &empty_vec_name());
        assert_eq!(
            token.to_string(),
            "0x3fdc6625e234d16a8eb285946ca335220034e0fcdb408929aa4f9e42729a778f"
        );
    }

    #[test]
    fn create_plan_references_live_myusd_confidential_token() {
        let request = r#"{
            "action":"create",
            "packageId":"0xc1fe",
            "accountRegistryId":"0xbb7ee5a9204a880c4b5e938dbbb188acc14d405a99e1aa663b03c34414901d40",
            "tokenRegistryId":"0xf99d63752b6144d0a786fc7d4894b751bdefac90d61417175d0f27bc35669b0d",
            "owner":"0x6b27c51107b378c9a1c6f1b471e43407d3027e8485464b0f7e9be8d196cbd8e0",
            "tokenType":"0xf862bc40fe05aa0b6779ff7894f0c46a6bed19d179f68116119b9d222a32fb19::myusd::MYUSD",
            "accountKey":"a97a3850c6ebc903140b0658922fc72de2e314bd7acd402ce46fa9bcf3d8bd00",
            "hasAccount":false,
            "auditorKeys":[]
        }"#;
        let plan = plan_transaction(request).unwrap();
        assert!(
            plan.contains("0x3fdc6625e234d16a8eb285946ca335220034e0fcdb408929aa4f9e42729a778f"),
            "plan should reference live ConfidentialToken, got: {plan}"
        );
        assert!(
            !plan.contains("0x68a361d25c27f3899dcd8eba2a5288c991c5434120606792563e7b609173a20a"),
            "plan must not use the old empty-slice derived id"
        );
    }
}

#[cfg(test)]
mod decrypt_json_tests {
    use super::*;
    use myso_contra_crypto::group::{identity, point_bytes};

    #[test]
    fn decrypts_trivial_zero_from_number_array_json() {
        let id = point_bytes(&identity());
        let bytes_json = format!(
            "[{}]",
            id.iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        let limb = format!(
            r#"{{"ciphertext":{{"bytes":{bytes_json}}},"decryption_handle":{{"bytes":{bytes_json}}}}}"#
        );
        let amount = format!(r#"{{"l0":{limb},"l1":{limb},"l2":{limb},"l3":{limb}}}"#);
        let account = format!(
            r#"{{"pk":{{"bytes":{bytes_json}}},"active":{{"amount":{amount},"upper_bound":1}},"pending":{{"amount":{amount},"upper_bound":1}},"public_balance":{{"value":"0"}}}}"#
        );
        let mut key = [1u8; 32];
        key[31] = 0;
        let (a, p, pp) = decrypt_balance(&key, &account).unwrap();
        assert_eq!((a, p, pp), (0, 0, 0));
    }
}
