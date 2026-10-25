#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusWord {
    NoError = 0x9000,
    ConditionsNotSatisfied = 0x6985,
    WrongData = 0x6A80,
    WrongLength = 0x6700,
    ClaNotSupported = 0x6E00,
    InsNotSupported = 0x6D00,
    NoPreciseDiagnosis = 0x6F00,
}

impl StatusWord {
    pub fn to_bytes(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }
}

#[derive(Debug)]
pub struct Apdu<'a> {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: &'a [u8],
    pub le: Option<usize>,
}

impl<'a> Apdu<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Apdu<'a>, StatusWord> {
        if bytes.len() < 4 {
            return Err(StatusWord::WrongLength);
        }

        let cla = bytes[0];
        let ins = bytes[1];
        let p1 = bytes[2];
        let p2 = bytes[3];
        let body = &bytes[4..];
        if body.is_empty() {
            return Ok(Apdu {
                cla,
                ins,
                p1,
                p2,
                data: &[],
                le: None,
            });
        }

        // Body must start with 0x00 marker.
        if body[0] != 0x00 {
            return Err(StatusWord::WrongLength);
        }

        // After the marker, at least 2 bytes for length
        if body.len() < 3 {
            return Err(StatusWord::WrongLength);
        }

        let len = u16::from_be_bytes([body[1], body[2]]) as usize;
        let rest = &body[3..];
        if rest.is_empty() {
            // Nothing after the length, it's requesting a response
            let le = if len == 0 { 65536 } else { len };
            Ok(Apdu { cla, ins, p1, p2, data: &[], le: Some(le) })
        } else if rest.len() == len {
            // Exactly the right amount of data. Data only.
            Ok(Apdu { cla, ins, p1, p2, data: rest, le: None })
        } else if rest.len() == len + 2 {
            // x data bytes then 2 Le bytes.
            let data = &rest[..len];
            let le_raw = u16::from_be_bytes([rest[len], rest[len + 1]]) as usize;
            let le = if le_raw == 0 { 65536 } else { le_raw };
            Ok(Apdu { cla, ins, p1, p2, data, le: Some(le) })
        } else {
            Err(StatusWord::WrongLength) // Length doesn't match
        }
    }
}
