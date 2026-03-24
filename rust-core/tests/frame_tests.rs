use chameleon_core::frame::model::{FrameType, TrafficFrame};

#[test]
fn payload_len_matches_bytes() {
    let frame = TrafficFrame {
        stream_id: 7,
        frame_type: FrameType::Data,
        payload: vec![1, 2, 3, 4],
    };

    assert_eq!(frame.payload_len(), 4);
}
