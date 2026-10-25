use zeroize::{ ZeroizeOnDrop, Zeroizing };
use p256::ecdsa::SigningKey;
use subtle::ConstantTimeEq;
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac::<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC can take key of any size");
    for p in parts {
        mac.update(p);
    }

    mac.finalize().into_bytes().into()
}

#[derive(ZeroizeOnDrop)]
pub struct MasterSecrets {
    derive: [u8; 32],
    mac: [u8; 32],
}

impl MasterSecrets {
    pub fn new(derive: [u8; 32], mac: [u8; 32]) -> Self {
        MasterSecrets { derive, mac }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyHandle(pub [u8; 64]);

impl KeyHandle {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

#[derive(Debug)]
pub enum WrapError {
    InvalidScalar,
}

pub fn wrap_key(
    secrets: &MasterSecrets,
    application: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<(KeyHandle, SigningKey), WrapError> {
    let private = Zeroizing::new(hmac(&secrets.derive, &[application, nonce]));
    let signing_key = SigningKey::from_slice(private.as_slice())
        .map_err(|_| WrapError::InvalidScalar)?;

    let mac = hmac(&secrets.mac, &[application, private.as_slice()]);
    let mut key_handle = [0u8; 64];
    key_handle[0..32].copy_from_slice(nonce);
    key_handle[32..64].copy_from_slice(&mac);

    Ok((KeyHandle(key_handle), signing_key))
}

pub fn unwrap_key(secrets: &MasterSecrets, application: &[u8; 32], key_handle: &[u8]) -> Option<SigningKey> {
    if key_handle.len() != 64 {
        return None;
    }

    let nonce = &key_handle[0..32];
    let handle_mac = &key_handle[32..64];

    let private = Zeroizing::new(hmac(&secrets.derive, &[application, nonce]));
    let expected_mac = hmac(&secrets.mac, &[application, private.as_slice()]);
    if handle_mac.ct_eq(&expected_mac).unwrap_u8() == 0 {
        return None;
    }

    // Valid MAC!
    SigningKey::from_slice(private.as_slice()).ok()
}
