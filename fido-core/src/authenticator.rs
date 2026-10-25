use p256::ecdsa::{ Signature, signature::Signer, SigningKey};
use rand_core::CryptoRngCore;

use crate::apdu::StatusWord;
use crate::keys::{MasterSecrets, unwrap_key, wrap_key};
use crate::platform::{CounterStore, Millis, UserPresence};
use crate::u2f::{AuthControl, SignatureBytes, U2fRequest, U2fResponse, authentication_signed_data, encode_public_key, registration_signed_data};

pub struct Attestation<'a> {
    pub key: SigningKey,
    pub certificate: &'a [u8],
}

pub struct U2fAuthenticator<'a, P: UserPresence, C: CounterStore, R: CryptoRngCore> {
    secrets: MasterSecrets,
    attestation: Attestation<'a>,
    presence: P,
    counter: C,
    rng: R,
}

impl<'a, P: UserPresence, C: CounterStore, R: CryptoRngCore> U2fAuthenticator<'a, P, C, R> {
    pub fn new(secrets: MasterSecrets, attestation: Attestation<'a>, presence: P, counter: C, rng: R) -> Self {
        U2fAuthenticator {
            secrets,
            attestation,
            presence,
            counter,
            rng,
        }
    }

    pub fn process(&mut self, request: &U2fRequest<'_>, now: Millis) -> U2fResponse<'a> {
        match request {
            U2fRequest::Version => U2fResponse::Version,
            U2fRequest::Register { application, challenge } => {
                // Require button press for registration
                if !self.presence.consume_presence(now) {
                    return U2fResponse::Status(StatusWord::ConditionsNotSatisfied);
                }

                // Create a credential key pair and key handle for the application
                let (key_handle, signing_key) = {
                    let mut ampt = 0;
                    loop {
                        let mut nonce = [0u8; 32];
                        self.rng.fill_bytes(&mut nonce);

                        match wrap_key(&self.secrets, application, &nonce) {
                            Ok(pair) => break pair,
                            Err(_) => {
                                ampt += 1;
                                if ampt >= 4 {
                                    return U2fResponse::Status(StatusWord::NoPreciseDiagnosis);
                                }
                            }
                        }
                    }
                };

                // Create public key from the signing key
                let public_key = encode_public_key(signing_key.verifying_key());

                // Sign the registration data with the attestation key
                let signed = registration_signed_data(application, challenge, key_handle.as_bytes(), &public_key);
                let sig: Signature = self.attestation.key.sign(&signed);
                let signature = match SignatureBytes::from_slice(sig.to_der().as_bytes()) {
                    Ok(s) => s,
                    Err(_) => return U2fResponse::Status(StatusWord::NoPreciseDiagnosis),
                };

                U2fResponse::Registration {
                    public_key, key_handle,
                    attestation_cert: self.attestation.certificate,
                    signature
                }
            }

            U2fRequest::Authenticate { control, challenge, application, key_handle } => {
                // Verify handle
                let signing_key = match unwrap_key(&self.secrets, application, key_handle) {
                    Some(k) => k,
                    None => return U2fResponse::Status(StatusWord::WrongData),
                };

                // Match control byte
                match control {
                    // "Is this yours?" yes (6985) / Don't Enforce: Key requires touch
                    AuthControl::CheckOnly | AuthControl::DontEnforceUserPresenceAndSign => {
                        return U2fResponse::Status(StatusWord::ConditionsNotSatisfied);
                    }
                    AuthControl::EnforceUserPresenceAndSign => {}
                }

                // Require button press for authentication
                if !self.presence.consume_presence(now) {
                    return U2fResponse::Status(StatusWord::ConditionsNotSatisfied);
                }

                // Increment counter
                let counter = match self.counter.increment() {
                    Ok(c) => c,
                    Err(_) => return U2fResponse::Status(StatusWord::NoPreciseDiagnosis),
                };

                // Sign the authentication data with the credential key
                let user_presence = 0x01;
                let signed = authentication_signed_data(application, user_presence, counter, challenge);
                let sig: Signature = signing_key.sign(&signed);
                let signature = match SignatureBytes::from_slice(sig.to_der().as_bytes()) {
                    Ok(s) => s,
                    Err(_) => return U2fResponse::Status(StatusWord::NoPreciseDiagnosis),
                };

                U2fResponse::Authentication { user_presence, counter, signature }
            }
        }
    }
}
