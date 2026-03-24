use chameleon_core::frame::model::FrameType;
use chameleon_core::frame::ChameleonFrame;

#[test]
fn test_frame_encode_decode() {
    let frame = ChameleonFrame {
        stream_id: 42,
        frame_type: FrameType::Data,
        payload: vec![1, 2, 3, 4, 5],
    };

    let encoded = frame.encode();
    let decoded = ChameleonFrame::decode(&encoded).expect("decode should succeed");
    assert_eq!(decoded, frame);
}

#[test]
fn test_chaff_frame() {
    let frame = ChameleonFrame {
        stream_id: 9,
        frame_type: FrameType::Chaff,
        payload: vec![0_u8; 32],
    };

    let encoded = frame.encode();
    let decoded = ChameleonFrame::decode(&encoded).expect("decode should succeed");
    assert_eq!(decoded.frame_type, FrameType::Chaff);
    assert_eq!(decoded.payload.len(), 32);
}

#[test]
fn test_pad_to_size() {
    let mut frame = ChameleonFrame {
        stream_id: 1,
        frame_type: FrameType::Ack,
        payload: vec![7, 8, 9],
    };

    frame.pad_to_size(64);
    assert_eq!(frame.encode().len(), 64);
}

#[test]
fn test_encrypt_decrypt() {
    let key = [7_u8; 32];
    let nonce = [3_u8; 12];
    let frame = ChameleonFrame {
        stream_id: 77,
        frame_type: FrameType::Control,
        payload: b"synthetic-lab-frame".to_vec(),
    };

    let cipher = frame.encrypt(&key, &nonce).expect("encryption should succeed");
    let plain = ChameleonFrame::decrypt(&cipher, &key, &nonce).expect("decryption should succeed");
    assert_eq!(plain, frame);
}

#[test]
fn test_frame_type_conversion() {
    let code = u8::from(FrameType::Chaff);
    assert_eq!(code, 3);

    let parsed = FrameType::try_from(3).expect("chaff code should parse");
    assert_eq!(parsed, FrameType::Chaff);
}
