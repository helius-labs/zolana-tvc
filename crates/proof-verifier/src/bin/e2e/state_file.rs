use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use borsh::BorshDeserialize as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zolana_tvc_protocol::digest::{state_digest, wallet_id_hash};
use zolana_tvc_protocol::encoding::{
    decimal_u64, hex_bytes, hex32, is_rfc8785, jcs_serialize, parse_strict_json,
};
use zolana_tvc_protocol::types::SealedWalletStateV1;

pub const STATE_FILE_TYPE: &str = "ZOLANA_TVC_E2E_STATE_V1";
const MAX_STATE_FILE_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingTransferV1 {
    #[serde(with = "hex32")]
    pub request_id: [u8; 32],
    #[serde(with = "hex32")]
    pub request_digest: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub signed_transaction: Vec<u8>,
    pub transaction_signature: String,
    pub turnkey_activity_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedTransferV1 {
    #[serde(with = "hex32")]
    pub request_id: [u8; 32],
    #[serde(with = "hex32")]
    pub request_digest: [u8; 32],
    pub transaction_signature: String,
    pub turnkey_activity_id: String,
    #[serde(with = "decimal_u64")]
    pub slot: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct E2eStateFileV1 {
    pub r#type: String,
    pub version: u8,
    pub endpoint: String,
    pub release_id: String,
    #[serde(with = "hex32")]
    pub security_domain_id: [u8; 32],
    #[serde(with = "hex32")]
    pub manifest_digest: [u8; 32],
    #[serde(with = "hex32")]
    pub executable_digest: [u8; 32],
    pub quorum_key_id: String,
    #[serde(with = "decimal_u64")]
    pub quorum_key_epoch: u64,
    #[serde(with = "hex_bytes")]
    pub quorum_public_key: Vec<u8>,
    pub wallet_id: String,
    pub turnkey_wallet_id: String,
    pub turnkey_wallet_account_id: String,
    pub solana_address: String,
    #[serde(with = "hex32")]
    pub expected_ed25519_public_key: [u8; 32],
    #[serde(with = "hex32")]
    pub descriptor_digest: [u8; 32],
    #[serde(with = "decimal_u64")]
    pub state_version: u64,
    #[serde(with = "hex32")]
    pub state_digest: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub sealed_wallet_state: Vec<u8>,
    #[serde(with = "decimal_u64")]
    pub local_generation: u64,
    pub pending_transfer: Option<PendingTransferV1>,
    pub last_finalized_transfer: Option<FinalizedTransferV1>,
}

impl E2eStateFileV1 {
    pub fn validate_sealed_state(&self) -> Result<()> {
        ensure!(self.r#type == STATE_FILE_TYPE, "wrong state-file type");
        ensure!(self.version == 1, "unsupported state-file version");
        let sealed = SealedWalletStateV1::try_from_slice(&self.sealed_wallet_state)
            .context("invalid sealed wallet state")?;
        ensure!(
            sealed.version == self.version,
            "sealed-state version mismatch"
        );
        ensure!(
            sealed.quorum_key_id == self.quorum_key_id,
            "sealed-state Quorum key ID mismatch"
        );
        ensure!(
            sealed.quorum_key_epoch == self.quorum_key_epoch,
            "sealed-state Quorum epoch mismatch"
        );
        ensure!(
            sealed.state_version == self.state_version,
            "sealed-state version checkpoint mismatch"
        );
        ensure!(
            sealed.wallet_id_hash == wallet_id_hash(&self.wallet_id),
            "sealed-state wallet ID mismatch"
        );
        ensure!(
            state_digest(&sealed)? == self.state_digest,
            "sealed-state digest checkpoint mismatch"
        );
        if let Some(pending) = &self.pending_transfer {
            ensure!(
                pending.signed_transaction.len() <= 1_232,
                "pending transaction exceeds Solana packet size"
            );
            ensure!(
                !pending.transaction_signature.is_empty()
                    && !pending.turnkey_activity_id.is_empty(),
                "pending transaction metadata is incomplete"
            );
        }
        Ok(())
    }
}

pub struct LockedStateFile {
    path: PathBuf,
    _lock: File,
}

impl LockedStateFile {
    pub fn acquire(path: &Path) -> Result<Self> {
        let parent = normalized_parent(path)?;
        ensure!(parent.is_dir(), "state-file parent is not a directory");
        reject_symlink(path)?;

        let lock_path = sibling_path(path, ".lock")?;
        reject_symlink(&lock_path)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&lock_path)
            .with_context(|| format!("failed to open state lock {}", lock_path.display()))?;
        lock.set_permissions(fs::Permissions::from_mode(0o600))?;
        lock.lock()
            .with_context(|| format!("failed to lock {}", lock_path.display()))?;
        Ok(Self {
            path: path.to_owned(),
            _lock: lock,
        })
    }

    pub fn ensure_absent(&self) -> Result<()> {
        ensure!(
            !self.path.try_exists()?,
            "state file already exists; refusing to overwrite its checkpoint"
        );
        Ok(())
    }

    pub fn create(&self, state: &E2eStateFileV1) -> Result<[u8; 32]> {
        self.ensure_absent()?;
        state.validate_sealed_state()?;
        let bytes = encode_state(state)?;
        atomic_replace(&self.path, &bytes)?;
        Ok(file_digest(&bytes))
    }

    pub fn load(&self) -> Result<(E2eStateFileV1, [u8; 32])> {
        reject_symlink(&self.path)?;
        let metadata = fs::metadata(&self.path)
            .with_context(|| format!("failed to inspect {}", self.path.display()))?;
        ensure!(metadata.is_file(), "state path is not a regular file");
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "state file must not be accessible by group or other users"
        );
        ensure!(
            metadata.len() <= MAX_STATE_FILE_BYTES,
            "state file is unexpectedly large"
        );
        let bytes = fs::read(&self.path)
            .with_context(|| format!("failed to read {}", self.path.display()))?;
        let text = std::str::from_utf8(&bytes).context("state file is not UTF-8")?;
        ensure!(is_rfc8785(text), "state file is not canonical JCS");
        let state: E2eStateFileV1 =
            parse_strict_json(text).map_err(|error| anyhow::anyhow!("state decode: {error}"))?;
        state.validate_sealed_state()?;
        Ok((state, file_digest(&bytes)))
    }

    pub fn replace(
        &self,
        expected_file_digest: [u8; 32],
        state: &E2eStateFileV1,
    ) -> Result<[u8; 32]> {
        let (_, current_digest) = self.load()?;
        ensure!(
            current_digest == expected_file_digest,
            "state-file CAS failed: checkpoint changed"
        );
        state.validate_sealed_state()?;
        let bytes = encode_state(state)?;
        atomic_replace(&self.path, &bytes)?;
        Ok(file_digest(&bytes))
    }
}

fn encode_state(state: &E2eStateFileV1) -> Result<Vec<u8>> {
    Ok(jcs_serialize(state)?.into_bytes())
}

fn file_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = normalized_parent(path)?;
    let temporary_path = sibling_path(path, &format!(".tmp-{}", hex::encode(random16())))?;
    let result = (|| -> Result<()> {
        let mut temporary = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary_path)
            .with_context(|| {
                format!(
                    "failed to create temporary state {}",
                    temporary_path.display()
                )
            })?;
        temporary.write_all(bytes)?;
        temporary.sync_all()?;
        fs::rename(&temporary_path, path)
            .with_context(|| format!("failed to replace {}", path.display()))?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn normalized_parent(path: &Path) -> Result<&Path> {
    let parent = path.parent().context("state file has no parent")?;
    if parent.as_os_str().is_empty() {
        Ok(Path::new("."))
    } else {
        Ok(parent)
    }
}

fn sibling_path(path: &Path, suffix: &str) -> Result<PathBuf> {
    let mut name = OsString::from(path.file_name().context("state file has no file name")?);
    name.push(suffix);
    Ok(normalized_parent(path)?.join(name))
}

fn reject_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("refusing symlink state path {}", path.display())
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn random16() -> [u8; 16] {
    use p256::elliptic_curve::rand_core::{OsRng, RngCore as _};

    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_file_refuses_overwrite_and_detects_cas_change() {
        let directory =
            std::env::temp_dir().join(format!("zolana-tvc-state-file-{}", hex::encode(random16())));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("wallet.json");
        let guard = LockedStateFile::acquire(&path).unwrap();
        let state = test_state();
        let digest = guard.create(&state).unwrap();
        assert!(guard.create(&state).is_err());

        let mut changed = state.clone();
        changed.local_generation = 1;
        let next_digest = guard.replace(digest, &changed).unwrap();
        assert_ne!(digest, next_digest);
        assert!(guard.replace(digest, &state).is_err());
        assert_eq!(guard.load().unwrap().0.local_generation, 1);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        drop(guard);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn state_file_rejects_permissive_mode_and_unknown_fields() {
        let directory =
            std::env::temp_dir().join(format!("zolana-tvc-state-file-{}", hex::encode(random16())));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("wallet.json");
        let guard = LockedStateFile::acquire(&path).unwrap();
        let state = test_state();
        guard.create(&state).unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(guard.load().is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let mut value = serde_json::to_value(&state).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_owned(), serde_json::Value::Bool(true));
        atomic_replace(&path, jcs_serialize(&value).unwrap().as_bytes()).unwrap();
        assert!(guard.load().is_err());

        drop(guard);
        fs::remove_dir_all(directory).unwrap();
    }

    fn test_state() -> E2eStateFileV1 {
        let sealed = SealedWalletStateV1 {
            version: 1,
            quorum_key_id: "quorum".to_owned(),
            quorum_key_epoch: 1,
            wallet_id_hash: wallet_id_hash("wallet"),
            state_version: 1,
            previous_state_digest: None,
            ciphertext: vec![4; 64],
        };
        E2eStateFileV1 {
            r#type: STATE_FILE_TYPE.to_owned(),
            version: 1,
            endpoint: "https://example.invalid".to_owned(),
            release_id: "release".to_owned(),
            security_domain_id: [5; 32],
            manifest_digest: [6; 32],
            executable_digest: [7; 32],
            quorum_key_id: sealed.quorum_key_id.clone(),
            quorum_key_epoch: sealed.quorum_key_epoch,
            quorum_public_key: vec![8; 130],
            wallet_id: "wallet".to_owned(),
            turnkey_wallet_id: "turnkey-wallet".to_owned(),
            turnkey_wallet_account_id: "account".to_owned(),
            solana_address: "address".to_owned(),
            expected_ed25519_public_key: [9; 32],
            descriptor_digest: [10; 32],
            state_version: sealed.state_version,
            state_digest: state_digest(&sealed).unwrap(),
            sealed_wallet_state: borsh::to_vec(&sealed).unwrap(),
            local_generation: 0,
            pending_transfer: None,
            last_finalized_transfer: None,
        }
    }
}
