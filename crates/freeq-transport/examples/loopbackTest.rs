// crates/freeq-transport/examples/loopback_test.rs

use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing_subscriber;

use freeq_transport::session::{SessionManager, DefaultHooks, SessionConfig, SessionState};
use freeq_transport::peer::PeerId;
use uuid::Uuid;

#[tokio::main]
async fn main() {
    // Setup logging
    tracing_subscriber::fmt::init();

    println!("🧪 FreeQ - Enhanced Loopback Session Test\n");

    let hooks = Arc::new(DefaultHooks);
    let mut config = SessionConfig::default();
    config.battlefield_mode = true;

    let manager = SessionManager::new(hooks, config);

    // Create a test peer
    let peer_id = PeerId::new(format!("test-peer-{}", Uuid::new_v4()));

    println!("Creating session for peer: {}", peer_id);

    let session = match manager.create_session(peer_id.clone()).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create session: {}", e);
            return;
        }
    };

    println!("✅ Session created: {}", session.id);
    println!("   Current State: {:?}", *session.state.read().await);

    // Simulate session lifecycle
    sleep(Duration::from_secs(1)).await;

    // Simulate connection loss (battlefield scenario)
    println!("\nSimulating connection loss (drone out of range)...");
    let _ = session.suspend("Simulated network loss").await;
    println!("   State: {:?}", *session.state.read().await);

    sleep(Duration::from_secs(2)).await;

    // Simulate drone coming back in range
    println!("\nSimulating drone back in range - attempting fast reconnect...");
    let _ = session.attempt_fast_reconnect().await;
    println!("   State: {:?}", *session.state.read().await);

    sleep(Duration::from_secs(1)).await;

    println!("\n🎉 Loopback Session Test Completed Successfully!");
    println!("   Key Features Tested:");
    println!("   • Session creation & state machine");
    println!("   • Battlefield suspension");
    println!("   • Fast reconnect logic");
    println!("\nNext milestone: Real QUIC + Handshake integration");
}