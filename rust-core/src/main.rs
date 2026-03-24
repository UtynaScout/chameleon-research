use chameleon_core::weaver::engine::WeaverEngine;

#[tokio::main]
async fn main() {
    let mut engine = WeaverEngine::default();
    let packets = engine.generate_packets(100).await;
    println!("Generated packets: {}", packets.len());
}
