use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameType {
    Data,
    Ack,
    Control,
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
