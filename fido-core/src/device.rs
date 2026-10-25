use heapless::Vec;
use rand_core::CryptoRngCore;

use crate::apdu::Apdu;
use crate::authenticator::U2fAuthenticator;
use crate::consts::{MAX_MESSAGE_LEN, REPORT_LEN, VERSION_BUILD, VERSION_MAJOR, VERSION_MINOR};
use crate::ctaphid::{Assembler, AssemblerOutput, Capabilities, ChannelAllocator, ChannelId, Command, HidError, InitResponse, Message, Packet};
use crate::platform::{CounterStore, Millis, UserPresence};
use crate::u2f::{U2fRequest, U2fResponse};

fn error_response(cid: ChannelId, error: HidError) -> HidResponse {
    let mut payload = Vec::new();
    let _ = payload.push(error as u8);
    HidResponse { cid, cmd: Command::Error as u8, payload }
}

#[derive(Debug)]
pub struct HidResponse {
    pub cid: ChannelId,
    pub cmd: u8,
    pub payload: Vec<u8, MAX_MESSAGE_LEN>,
}

pub struct Device<'a, P: UserPresence, C: CounterStore, R: CryptoRngCore> {
    assembler: Assembler,
    channels: ChannelAllocator,
    authenticator: U2fAuthenticator<'a, P, C, R>,
}

impl<'a, P: UserPresence, C: CounterStore, R: CryptoRngCore> Device<'a, P, C, R> {
    pub fn new(authenticator: U2fAuthenticator<'a, P, C, R>) -> Self {
        Device {
            assembler: Assembler::new(),
            channels: ChannelAllocator::new(),
            authenticator,
        }
    }

    pub fn handle_report(&mut self, report: &[u8; REPORT_LEN], now: Millis) -> Option<HidResponse> {
        let packet = Packet::parse(report);
        match self.assembler.push(&packet, now) {
            AssemblerOutput::Pending => None,
            AssemblerOutput::Ignored => None,
            AssemblerOutput::Error { cid, error } => Some(error_response(cid, error)),
            AssemblerOutput::Complete(msg) => Some(self.dispatch(msg, now)),
        }
    }

    pub fn poll(&mut self, now: Millis) -> Option<HidResponse> {
        let (cid, error) = self.assembler.check_timeout(now)?;
        Some(error_response(cid, error))
    }

    pub fn dispatch(&mut self, msg: Message, now: Millis) -> HidResponse {
        if msg.cid == ChannelId(0) {
            return error_response(msg.cid, HidError::InvalidChannel);
        }

        let command = match Command::try_from(msg.cmd) {
            Ok(c) => c,
            Err(_) => return error_response(msg.cid, HidError::InvalidCmd)
        };

        // Broadcast channel only supports INIT command
        if msg.cid == ChannelId::BROADCAST && command != Command::Init {
            return error_response(msg.cid, HidError::InvalidChannel);
        }

        // Other channels must be allocated before use
        if command != Command::Init && msg.cid != ChannelId::BROADCAST && !self.channels.is_allocated(msg.cid) {
            return error_response(msg.cid, HidError::InvalidChannel);
        }

        // Route commands
        match command {
            Command::Init => self.handle_init(msg),
            Command::Ping => HidResponse { cid: msg.cid, cmd: msg.cmd, payload: msg.payload },
            Command::Wink => HidResponse { cid: msg.cid, cmd: msg.cmd, payload: Vec::new() },
            Command::Msg => self.handle_msg(msg, now),
            Command::Error => error_response(msg.cid, HidError::InvalidCmd)
        }
    }

    fn handle_init(&mut self, msg: Message) -> HidResponse {
        if msg.payload.len() != 8 {
            return error_response(msg.cid, HidError::InvalidLen);
        }

        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&msg.payload);

        // On broadcast channel, allocate a new channel ID or keep existing
        let new_cid = if msg.cid == ChannelId::BROADCAST {
            match self.channels.allocate() {
                Some(c) => c,
                None => return error_response(msg.cid, HidError::Other)
            }
        } else {
            msg.cid
        };

        let reply = InitResponse {
            nonce,
            cid: new_cid,
            protocol_version: 2,
            major: VERSION_MAJOR,
            minor: VERSION_MINOR,
            build: VERSION_BUILD,
            capabilities: Capabilities::WINK,
        };

        let mut payload = Vec::new();
        let _ = payload.extend_from_slice(&reply.to_bytes());
        HidResponse { cid: msg.cid, cmd: Command::Init as u8, payload }
    }

    fn handle_msg(&mut self, msg: Message, now: Millis) -> HidResponse {
        let response = match Apdu::parse(&msg.payload) {
            Err(sw) => U2fResponse::Status(sw),
            Ok(apdu) => match U2fRequest::parse(&apdu) {
                Err(sw) => U2fResponse::Status(sw),
                Ok(request) => self.authenticator.process(&request, now),
            }
        };

        let payload = response.encode();
        HidResponse { cid: msg.cid, cmd: Command::Msg as u8, payload }
    }
}
