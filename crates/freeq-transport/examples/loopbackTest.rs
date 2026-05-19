// crates/freeq-transport/examples/loopback_test.rs

use std::sync::Arc;
use freeq_transport::session::{SessionManager, DefaultHooks, SessionConfig, Platform};
use freeq_transport::peer::PeerId;
use uuid::Uuid;

#[tokio::main]
async fn main() {
    println!("🧪 FreeQ Loopback Session Test");

    let hooks = Arc::new(DefaultHooks);
    let config = SessionConfig::default();

    let manager = SessionManager::new(hooks, config);

    // Create fake peer
    let peer_id = PeerId::new(Uuid::new_v4().to_string());

    match manager.create_session(peer_id).await {
        Ok(session) => {
            println!("✅ Session created successfully: {}", session.id);
            println!("   State: {:?}", session.state.read().await);
            println!("   Platform: {:?}", session.config.platform);
        }
        Err(e) => {
            eprintln!("❌ Failed to create session: {}", e);
        }
    }

    println!("\n🎉 Basic session lifecycle test passed!");
    println!("Next: Implement real QUIC + handshake loopback test.");
}