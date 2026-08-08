use std::env;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use freeq_crypto::FreeQKeyPair;
use freeq_tunnel::{TunnelConfig, TunnelInterface};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sysinfo::{CpuRefreshKind, RefreshKind, System};
use tokio::time::{interval, sleep, MissedTickBehavior};

static TOTAL_PACKETS_SENT: AtomicU64 = AtomicU64::new(0);
static TOTAL_BYTES_SENT: AtomicU64 = AtomicU64::new(0);
static TOTAL_DROPPED_PACKETS: AtomicU64 = AtomicU64::new(0);
static TOTAL_RECONNECTIONS: AtomicU64 = AtomicU64::new(0);
static CUMULATIVE_RECONNECT_TIME_MS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionState {
    Connected,
    Disconnected,
}

#[derive(Debug)]
struct SoakConfig {
    trucks: usize,
    duration: Duration,
    sample_interval: Duration,
    packet_interval: Duration,
    payload_bytes: usize,
    chaos: ChaosConfig,
}

#[derive(Clone, Copy, Debug)]
struct ChaosConfig {
    enabled: bool,
    disconnect_probability: f64,
    drop_probability: f64,
    base_backoff: Duration,
    max_backoff: Duration,
}

impl SoakConfig {
    fn from_env() -> Self {
        let trucks = env_usize("FREEQ_SOAK_TRUCKS", 1_000);
        let duration = Duration::from_secs(env_u64("FREEQ_SOAK_DURATION_SECS", 600));
        let sample_interval = Duration::from_secs(env_u64("FREEQ_SOAK_SAMPLE_SECS", 5).max(1));
        let hz = env_u64("FREEQ_SOAK_HZ", 10).max(1);
        let packet_interval = Duration::from_nanos(1_000_000_000 / hz);
        let payload_bytes = env_usize("FREEQ_SOAK_PAYLOAD_BYTES", 1_180).max(20);
        let chaos = ChaosConfig {
            enabled: env_bool("FREEQ_SOAK_CHAOS", false),
            disconnect_probability: env_f64("FREEQ_SOAK_DISCONNECT_PROBABILITY", 0.02),
            drop_probability: env_f64("FREEQ_SOAK_DROP_PROBABILITY", 0.05),
            base_backoff: Duration::from_millis(env_u64("FREEQ_SOAK_BASE_BACKOFF_MS", 100)),
            max_backoff: Duration::from_millis(env_u64("FREEQ_SOAK_MAX_BACKOFF_MS", 10_000)),
        };

        Self {
            trucks,
            duration,
            sample_interval,
            packet_interval,
            payload_bytes,
            chaos,
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let config = SoakConfig::from_env();
    let running = Arc::new(AtomicBool::new(true));
    let keys = FreeQKeyPair::generate_ephemeral_test_pair().expect("soak test keys");
    let tunnel = Arc::new(
        TunnelInterface::new(
            TunnelConfig {
                interface_name: "freeqbench0".into(),
                mtu: 1200,
            },
            keys,
        )
        .expect("real-path tunnel pipeline"),
    );

    println!("==========================================================");
    println!("INITIALIZING FREEQ CONCURRENCY SOAK TEST");
    println!("Simulating: {} virtual telemetry streams", config.trucks);
    println!("Target Duration: {:?}", config.duration);
    println!("Payload Size: {} bytes", config.payload_bytes);
    println!("Packet Interval: {:?}", config.packet_interval);
    println!("CPU Sample Interval: {:?}", config.sample_interval);
    if config.chaos.enabled {
        println!("Chaos Mode: enabled");
        println!(
            "Disconnect Probability: {:.2}%",
            config.chaos.disconnect_probability * 100.0
        );
        println!(
            "Drop Probability While Connected: {:.2}%",
            config.chaos.drop_probability * 100.0
        );
        println!(
            "Backoff: {:?} base, {:?} max, full jitter",
            config.chaos.base_backoff, config.chaos.max_backoff
        );
    } else {
        println!("Chaos Mode: disabled");
    }
    println!("==========================================================");

    let mut sys =
        System::new_with_specifics(RefreshKind::nothing().with_cpu(CpuRefreshKind::everything()));
    sys.refresh_cpu_all();

    let start_time = Instant::now();
    let mut handles = Vec::with_capacity(config.trucks);

    for truck_id in 0..config.trucks {
        let running = Arc::clone(&running);
        let tunnel = Arc::clone(&tunnel);
        let packet_interval = config.packet_interval;
        let payload_bytes = config.payload_bytes;
        let chaos = config.chaos;

        handles.push(tokio::spawn(async move {
            let payload = build_ipv4_packet(payload_bytes, truck_id);
            let mut ticker = interval(packet_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            let mut state = ConnectionState::Connected;
            let mut rng = StdRng::seed_from_u64(0xfee0_u64 ^ truck_id as u64);
            let mut retry_attempt = 0_u32;

            while running.load(Ordering::Relaxed) {
                match state {
                    ConnectionState::Connected => {
                        ticker.tick().await;

                        if chaos.enabled && rng.gen_bool(chaos.disconnect_probability) {
                            state = ConnectionState::Disconnected;
                            retry_attempt = 0;
                            continue;
                        }

                        if chaos.enabled && rng.gen_bool(chaos.drop_probability) {
                            TOTAL_DROPPED_PACKETS.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }

                        match transmit_real_freeq_packet_path(Arc::clone(&tunnel), &payload).await {
                            Ok(()) => {
                                TOTAL_PACKETS_SENT.fetch_add(1, Ordering::Relaxed);
                                TOTAL_BYTES_SENT.fetch_add(payload.len() as u64, Ordering::Relaxed);
                            }
                            Err(_) => {
                                TOTAL_DROPPED_PACKETS.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    ConnectionState::Disconnected => {
                        let reconnect_start = Instant::now();
                        TOTAL_RECONNECTIONS.fetch_add(1, Ordering::Relaxed);

                        let wait = jittered_backoff(chaos, retry_attempt, &mut rng);
                        retry_attempt = retry_attempt.saturating_add(1);
                        sleep(wait).await;

                        let reconnect_ms = reconnect_start.elapsed().as_millis() as u64;
                        CUMULATIVE_RECONNECT_TIME_MS.fetch_add(reconnect_ms, Ordering::Relaxed);
                        state = ConnectionState::Connected;
                    }
                }
            }
        }));
    }

    println!(
        "All {} virtual telemetry streams are online.",
        config.trucks
    );

    let mut cpu_samples = Vec::new();
    while start_time.elapsed() < config.duration {
        sleep(config.sample_interval).await;

        sys.refresh_cpu_all();
        let current_cpu = sys.global_cpu_usage();
        cpu_samples.push(current_cpu);

        let elapsed = start_time.elapsed().as_secs();
        let current_total = TOTAL_PACKETS_SENT.load(Ordering::Relaxed);
        let dropped = TOTAL_DROPPED_PACKETS.load(Ordering::Relaxed);
        let reconnects = TOTAL_RECONNECTIONS.load(Ordering::Relaxed);

        println!(
            "[{:02}m:{:02}s] Packets: {} | Dropped: {} | Reconnects: {} | CPU: {:.1}%",
            elapsed / 60,
            elapsed % 60,
            current_total,
            dropped,
            reconnects,
            current_cpu
        );
    }

    running.store(false, Ordering::Relaxed);
    for handle in handles {
        let _ = handle.await;
    }

    let total_duration_secs = start_time.elapsed().as_secs_f64();
    let total_packets = TOTAL_PACKETS_SENT.load(Ordering::Relaxed);
    let total_bytes = TOTAL_BYTES_SENT.load(Ordering::Relaxed);
    let dropped_packets = TOTAL_DROPPED_PACKETS.load(Ordering::Relaxed);
    let total_reconnects = TOTAL_RECONNECTIONS.load(Ordering::Relaxed);
    let total_reconnect_time = CUMULATIVE_RECONNECT_TIME_MS.load(Ordering::Relaxed);
    let avg_reconnect_ms = if total_reconnects > 0 {
        total_reconnect_time as f64 / total_reconnects as f64
    } else {
        0.0
    };
    let pps = total_packets as f64 / total_duration_secs;
    let gbps = (total_bytes as f64 * 8.0) / total_duration_secs / 1_000_000_000.0;
    let avg_cpu = average(&cpu_samples);
    let peak_cpu = cpu_samples.iter().copied().fold(0.0, f32::max);

    println!();
    println!("==========================================================");
    println!("SOAK TEST COMPLETE - FINAL RESULTS:");
    println!(
        "   - Total Duration Evaluated: {:.2} seconds",
        total_duration_secs
    );
    println!("   - Total Packets Processed: {}", total_packets);
    println!("   - Total Dropped Packets: {}", dropped_packets);
    println!("   - Total Reconnections Processed: {}", total_reconnects);
    println!(
        "   - Average Reconnect Resolution: {:.2} ms",
        avg_reconnect_ms
    );
    println!("   - Total Bytes Processed: {}", total_bytes);
    println!(
        "   - Real Path Packets Accepted by Tunnel: {}",
        tunnel.packets_processed()
    );
    println!(
        "   - Real Path Transport Frames Emitted: {}",
        tunnel.transport_frames()
    );
    println!("   - Average Packets Per Second: {:.0} PPS", pps);
    println!("   - Virtual Interface Throughput: {:.2} Gbps", gbps);
    println!("   - Average CPU Utilization: {:.1}%", avg_cpu);
    println!("   - Peak CPU Utilization: {:.1}%", peak_cpu);
    println!("   - Total CPU Samples Logged: {}", cpu_samples.len());
    println!("==========================================================");
}

fn jittered_backoff(chaos: ChaosConfig, retry_attempt: u32, rng: &mut StdRng) -> Duration {
    let exponent = retry_attempt.min(6);
    let multiplier = 1_u64 << exponent;
    let raw_ms = chaos.max_backoff.as_millis().min(
        chaos
            .base_backoff
            .as_millis()
            .saturating_mul(multiplier as u128),
    );
    let wait_ms = rng.gen_range(0..=raw_ms as u64);
    Duration::from_millis(wait_ms)
}

async fn transmit_real_freeq_packet_path(
    tunnel_instance: Arc<TunnelInterface>,
    mock_payload: &[u8],
) -> Result<(), freeq_tunnel::TunnelError> {
    tunnel_instance.write_packet(mock_payload).await
}

fn build_ipv4_packet(len: usize, stream_id: usize) -> Vec<u8> {
    let mut packet = vec![stream_id as u8; len];
    packet[0] = 0x45;
    packet[1] = 0;
    packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    packet[4..6].copy_from_slice(&(stream_id as u16).to_be_bytes());
    packet[6..8].copy_from_slice(&[0x40, 0]);
    packet[8] = 64;
    packet[9] = 17;
    packet[10..12].copy_from_slice(&[0, 0]);
    packet[12..16].copy_from_slice(&[10, 0, ((stream_id >> 8) & 0xff) as u8, stream_id as u8]);
    packet[16..20].copy_from_slice(&[10, 1, ((stream_id >> 8) & 0xff) as u8, stream_id as u8]);
    packet
}

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_f64(name: &str, default: f64) -> f64 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_bool(name: &str, default: bool) -> bool {
    env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.as_str(),
                "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
            )
        })
        .unwrap_or(default)
}

fn average(samples: &[f32]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }

    samples.iter().sum::<f32>() / samples.len() as f32
}
