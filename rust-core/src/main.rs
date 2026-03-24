use chameleon_core::weaver::engine::WeaverEngine;

#[tokio::main]
async fn main() {
    let mut engine = WeaverEngine::default();
    let packets = engine.generate_session(5.0);
    println!("Generated packets: {}", packets.len());
}
