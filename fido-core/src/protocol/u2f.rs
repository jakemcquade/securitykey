use heapless::Vec;
use p256::ecdsa::VerifyingKey;

use crate::constants::MAX_MESSAGE_LEN;
use crate::crypto::key_wrap::KeyHandle;
use crate::protocol::apdu::{Apdu, StatusWord};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthControl {
    CheckOnly,
    EnforceUserPresenceAndSign,
    DontEnforceUserPresenceAndSign,
}

#[derive(Debug, PartialEq)]
pub enum U2fRequest<'a> {
    Register {
        challenge: [u8; 32],
        application: [u8; 32],
    },
    Authenticate {
        control: AuthControl,
        challenge: [u8; 32],
        application: [u8; 32],
        key_handle: &'a [u8],
    },
    Version,
}

impl<'a> U2fRequest<'a> {
    pub fn parse(apdu: &Apdu<'a>) -> Result<U2fRequest<'a>, StatusWord> {
        // CLA must be 0x00 or it's unsupported.
        if apdu.cla != 0x00 {
            return Err(StatusWord::ClaNotSupported);
        }

        match apdu.ins {
            0x01 => {
                // Register
                if apdu.data.len() != 64 {
                    return Err(StatusWord::WrongLength);
                }

                let mut challenge = [0u8; 32];
                challenge.copy_from_slice(&apdu.data[0..32]);

                let mut application = [0u8; 32];
                application.copy_from_slice(&apdu.data[32..64]);
                Ok(U2fRequest::Register {
                    challenge,
                    application,
                })
            }
            0x02 => {
                // Authenticate
                if apdu.data.len() < 65 {
                    return Err(StatusWord::WrongLength);
                }

                let kh_len = apdu.data[64] as usize;
                if apdu.data.len() != 65 + kh_len {
                    return Err(StatusWord::WrongLength);
                }

                let control = match apdu.p1 {
                    0x07 => AuthControl::CheckOnly,
                    0x03 => AuthControl::EnforceUserPresenceAndSign,
                    0x08 => AuthControl::DontEnforceUserPresenceAndSign,
                    _ => return Err(StatusWord::WrongData),
                };

                let mut challenge = [0u8; 32];
                challenge.copy_from_slice(&apdu.data[0..32]);

                let mut application = [0u8; 32];
                application.copy_from_slice(&apdu.data[32..64]);

                let key_handle = &apdu.data[65..];
                Ok(U2fRequest::Authenticate {
                    control,
                    challenge,
                    application,
                    key_handle,
                })
            }
            0x03 => Ok(U2fRequest::Version),
            _ => Err(StatusWord::InsNotSupported),
        }
    }
}

pub type SignatureBytes = Vec<u8, 72>;

#[derive(Debug, PartialEq)]
pub enum U2fResponse<'a> {
    Version,
    Registration {
        public_key: [u8; 65],
        key_handle: KeyHandle,
        attestation_cert: &'a [u8],
        signature: SignatureBytes,
    },
    Authentication {
        user_presence: u8,
        counter: u32,
        signature: SignatureBytes,
    },
    Status(StatusWord),
}

impl U2fResponse<'_> {
    pub fn encode(&self) -> Vec<u8, MAX_MESSAGE_LEN> {
        let mut out = Vec::new();
        match self {
            U2fResponse::Version => {
                let _ = out.extend_from_slice(b"U2F_V2");
                let _ = out.extend_from_slice(&StatusWord::NoError.to_bytes());
            }
            U2fResponse::Status(sw) => {
                let _ = out.extend_from_slice(&sw.to_bytes());
            }
            U2fResponse::Authentication {
                user_presence,
                counter,
                signature,
            } => {
                let _ = out.push(*user_presence);
                let _ = out.extend_from_slice(&counter.to_be_bytes());
                let _ = out.extend_from_slice(signature);
                let _ = out.extend_from_slice(&StatusWord::NoError.to_bytes());
            }
            U2fResponse::Registration {
                public_key,
                key_handle,
                attestation_cert,
                signature,
            } => {
                let _ = out.push(0x05);
                let _ = out.extend_from_slice(public_key);
                let kh_bytes = key_handle.as_bytes();
                let _ = out.push(kh_bytes.len() as u8);
                let _ = out.extend_from_slice(kh_bytes);
                let _ = out.extend_from_slice(attestation_cert);
                let _ = out.extend_from_slice(signature);
                let _ = out.extend_from_slice(&StatusWord::NoError.to_bytes());
            }
        }

        out
    }
}

pub fn registration_signed_data(
    application: &[u8; 32],
    challenge: &[u8; 32],
    key_handle: &[u8],
    public_key: &[u8; 65],
) -> Vec<u8, 385> {
    let mut data = Vec::new();
    let _ = data.push(0x00);
    let _ = data.extend_from_slice(application);
    let _ = data.extend_from_slice(challenge);
    let _ = data.extend_from_slice(key_handle);
    let _ = data.extend_from_slice(public_key);
    data
}

pub fn authentication_signed_data(
    application: &[u8; 32],
    user_presence: u8,
    counter: u32,
    challenge: &[u8; 32],
) -> [u8; 69] {
    let mut data = [0u8; 69];
    data[0..32].copy_from_slice(application);
    data[32] = user_presence;
    data[33..37].copy_from_slice(&counter.to_be_bytes());
    data[37..69].copy_from_slice(challenge);
    data
}

pub fn encode_public_key(key: &VerifyingKey) -> [u8; 65] {
    let encoded = key.to_sec1_point(false);
    let mut out = [0u8; 65];
    out.copy_from_slice(encoded.as_bytes());
    out
}
