use heapless::Vec;

use crate::consts::{CONT_DATA_LEN, INIT_DATA_LEN, MAX_MESSAGE_LEN, REPORT_LEN, TRANSACTION_TIMEOUT_MS};
use crate::platform::Millis;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelId(pub u32);

impl ChannelId {
    pub const BROADCAST: ChannelId = ChannelId(0xFFFF_FFFF);
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Ping = 0x81,
    Msg = 0x83,
    Init = 0x86,
    Wink = 0x88,
    Error = 0xBF,
}

impl TryFrom<u8> for Command {
    type Error = u8;

    fn try_from(b: u8) -> Result<Self, u8> {
        match b {
            0x81 => Ok(Command::Ping),
            0x83 => Ok(Command::Msg),
            0x86 => Ok(Command::Init),
            0x88 => Ok(Command::Wink),
            0xBF => Ok(Command::Error),
            other => Err(other)
        }
    }
}

#[derive(Debug)]
pub enum Packet<'a> {
    Init { cid: ChannelId, cmd: u8, bcnt: u16, data: &'a [u8] }, // 57 bytes
    Cont { cid: ChannelId, seq: u8, data: &'a [u8] },            // 59 bytes
}

impl<'a> Packet<'a> {
    pub fn parse(report: &'a [u8; REPORT_LEN]) -> Packet<'a> {
        let cid = ChannelId(u32::from_be_bytes([report[0], report[1], report[2], report[3]]));
        if report[4] & 0x80 != 0 {
            let cmd: u8 = report[4];
            let bcnt = u16::from_be_bytes([report[5], report[6]]);
            let data = &report[7..];
            Packet::Init { cid, cmd, bcnt, data }
        } else {
            let seq = report[4];
            let data = &report[5..];
            Packet::Cont { cid, seq, data }
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HidError {
    InvalidCmd = 0x01,
    InvalidPar = 0x02,
    InvalidLen = 0x03,
    InvalidSeq = 0x04,
    MsgTimeout = 0x05,
    ChannelBusy = 0x06,
    InvalidChannel = 0x0B,
    Other = 0x7F,
}

#[derive(Debug)]
pub struct Message {
    pub cid: ChannelId,
    pub cmd: u8,
    pub payload: Vec<u8, MAX_MESSAGE_LEN>,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum AssemblerOutput {
    Pending,
    Complete(Message),
    Error { cid: ChannelId, error: HidError },
    Ignored,
}

#[allow(clippy::large_enum_variant)]
enum AssemblerState {
    Idle,
    Receiving {
        cid: ChannelId,
        cmd: u8,
        expected_len: usize,
        buffer: Vec<u8, MAX_MESSAGE_LEN>,
        next_seq: u8,
        last_packet_at: Millis,
    },
}

pub struct Assembler {
    state: AssemblerState,
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Assembler {
    pub fn new() -> Self {
        Assembler { state: AssemblerState::Idle }
    }

    pub fn push(&mut self, packet: &Packet<'_>, now: Millis) -> AssemblerOutput {
        let state = core::mem::replace(&mut self.state, AssemblerState::Idle);
        match state {
            AssemblerState::Idle => {
                match packet {
                    Packet::Init { cid, cmd, bcnt, data } => {
                        let bcnt = *bcnt as usize;

                        // Invalid length check
                        if bcnt > MAX_MESSAGE_LEN {
                            return AssemblerOutput::Error { cid: *cid, error: HidError::InvalidLen };
                        }

                        let mut buffer = Vec::new();
                        if bcnt <= INIT_DATA_LEN {
                            // Complete message in init packet
                            if buffer.extend_from_slice(&data[..bcnt]).is_err() {
                                return AssemblerOutput::Error { cid: *cid, error: HidError::Other };
                            }

                            AssemblerOutput::Complete(Message { cid: *cid, cmd: *cmd, payload: buffer })
                        } else {
                            // Start receiving continuation packets
                            if buffer.extend_from_slice(data).is_err() {
                                return AssemblerOutput::Error { cid: *cid, error: HidError::Other };
                            }

                            self.state = AssemblerState::Receiving {
                                cid: *cid,
                                cmd: *cmd,
                                expected_len: bcnt,
                                buffer,
                                next_seq: 0,
                                last_packet_at: now,
                            };

                            AssemblerOutput::Pending
                        }
                    }
                    Packet::Cont { .. } => AssemblerOutput::Ignored
                }
            },
            AssemblerState::Receiving { cid, cmd, expected_len, mut buffer, next_seq, last_packet_at } => {
                match packet {
                    Packet::Cont { cid: pcid, seq, data } => {
                        // Not our channel
                        if *pcid != cid {
                            self.state = AssemblerState::Receiving { cid, cmd, expected_len, buffer, next_seq, last_packet_at };
                            return AssemblerOutput::Ignored;
                        }

                        // Wrong sequence
                        if *seq != next_seq {
                            return AssemblerOutput::Error { cid, error: HidError::InvalidSeq }
                        }

                        // Correct continuation packet
                        let remaining = expected_len - buffer.len();
                        let take = remaining.min(CONT_DATA_LEN);
                        if buffer.extend_from_slice(&data[..take]).is_err() {
                            return AssemblerOutput::Error { cid, error: HidError::Other };
                        }

                        if buffer.len() >= expected_len {
                            // Complete message
                            AssemblerOutput::Complete(Message { cid, cmd, payload: buffer })
                        } else {
                            // Still receiving
                            self.state = AssemblerState::Receiving {
                                cid, cmd, expected_len, buffer,
                                next_seq: next_seq + 1,
                                last_packet_at: now,
                            };

                            AssemblerOutput::Pending
                        }
                    }
                    Packet::Init { cid: pcid, cmd: pcmd, bcnt: _, data: _ } => {
                        // Init packet while receiving a message
                        if *pcid != cid {
                            self.state = AssemblerState::Receiving {
                                cid, cmd, expected_len, buffer, next_seq, last_packet_at
                            };
                        
                            return AssemblerOutput::Error { cid: *pcid, error: HidError::ChannelBusy };
                        }

                        // Same channel. Check if init command.
                        if *pcmd == Command::Init as u8 {
                            return self.push(packet, now);
                        }

                        AssemblerOutput::Error { cid, error: HidError::InvalidSeq }
                    }
                }
            },
        }
    }

    pub fn check_timeout(&mut self, now: Millis) -> Option<(ChannelId, HidError)> {
        if let AssemblerState::Receiving { cid, last_packet_at, .. } = self.state
            && now.0.saturating_sub(last_packet_at.0) >= TRANSACTION_TIMEOUT_MS {
                self.state = AssemblerState::Idle;
                return Some((cid, HidError::MsgTimeout));
            }
        None
    }

    pub fn is_busy(&self) -> bool {
        matches!(self.state, AssemblerState::Receiving { .. })
    }
}

pub struct Fragments<'a> {
    cid: ChannelId,
    cmd: u8,
    payload: &'a [u8],
    offset: usize,
    next_seq: u8,
    done: bool,
}

impl Iterator for Fragments<'_> {
    type Item = [u8; REPORT_LEN];

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let is_init: bool = self.next_seq == 0 && self.offset == 0;
        let mut report = [0u8; REPORT_LEN];
        let cid = self.cid.0.to_be_bytes();
        report[0..4].copy_from_slice(&cid);

        let chunk_len;
        if is_init {
            // Init packet
            report[4] = self.cmd;

            let bcnt = (self.payload.len() as u16).to_be_bytes();
            report[5..7].copy_from_slice(&bcnt);

            let n = self.payload.len().min(INIT_DATA_LEN);
            report[7..7 + n].copy_from_slice(&self.payload[..n]);
            chunk_len = n;
        } else {
            // Continuation packet
            report[4] = self.next_seq;

            let remaining = self.payload.len() - self.offset;
            let n = remaining.min(CONT_DATA_LEN);
            report[5..5 + n].copy_from_slice(&self.payload[self.offset..self.offset + n]);
            self.next_seq += 1;
            chunk_len = n;
        }

        self.offset += chunk_len;
        if self.offset >= self.payload.len() {
            self.done = true;
        }

        Some(report)
    }
}

pub fn fragment(cid: ChannelId, cmd: u8, payload: &[u8]) -> Option<Fragments<'_>> {
    if payload.len() > MAX_MESSAGE_LEN {
        return None;
    }

    Some(Fragments {
        cid,
        cmd,
        payload,
        offset: 0,
        next_seq: 0,
        done: false,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities(u8);

impl Capabilities {
    pub const WINK: Capabilities = Capabilities(0x01);
    pub const CBOR: Capabilities = Capabilities(0x04);
    pub const NMSG: Capabilities = Capabilities(0x08);

    pub fn bits(self) -> u8 { self.0 }
}

pub struct InitResponse {
    pub nonce: [u8; 8],
    pub cid: ChannelId,
    pub protocol_version: u8,
    pub major: u8,
    pub minor: u8,
    pub build: u8,
    pub capabilities: Capabilities,
}

impl InitResponse {
    pub fn to_bytes(&self) -> [u8; 17] {
        let mut bytes = [0u8; 17];
        bytes[0..8].copy_from_slice(&self.nonce);
        bytes[8..12].copy_from_slice(&self.cid.0.to_be_bytes());
        bytes[12] = self.protocol_version;
        bytes[13] = self.major;
        bytes[14] = self.minor;
        bytes[15] = self.build;
        bytes[16] = self.capabilities.bits();
        bytes
    }
}

pub struct ChannelAllocator {
    next: u32,
}

impl Default for ChannelAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelAllocator {
    pub fn new() -> Self {
        ChannelAllocator { next: 1 }
    }

    pub fn with_next(next: u32) -> Self {
        ChannelAllocator { next }
    }

    pub fn allocate(&mut self) -> Option<ChannelId> {
        if self.next == ChannelId::BROADCAST.0 {
            return None;
        }

        let id = self.next;
        self.next += 1;
        Some(ChannelId(id))
    }

    pub fn is_allocated(&self, cid: ChannelId) -> bool {
        cid.0 >= 1 && cid.0 < self.next
    }
}
