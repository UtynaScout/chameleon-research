use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameType {
    Data,
    Ack,
    Control,
    Chaff,
}

impl From<FrameType> for u8 {
    fn from(value: FrameType) -> Self {
        match value {
            FrameType::Data => 0,
            FrameType::Ack => 1,
            FrameType::Control => 2,
            FrameType::Chaff => 3,
        }
    }
}

impl TryFrom<u8> for FrameType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(FrameType::Data),
            1 => Ok(FrameType::Ack),
            2 => Ok(FrameType::Control),
            3 => Ok(FrameType::Chaff),
            _ => Err("invalid frame type"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficFrame {
    pub stream_id: u32,
    pub frame_type: FrameType,
    pub payload: Vec<u8>,
}

impl TrafficFrame {
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }
}
