use criterion::{black_box, criterion_group, criterion_main, Criterion};
use qtls_core::{QTLSConfig, QKDProtocolType, QuantumTLS};

async fn benchmark_bb84_key_generation() {
    let config = QTLSConfig {
        qkd_protocol: qtls_core::QKDConfig {
            protocol_type: QKDProtocolType::BB84,
            key_length: 256,
            error_threshold: 0.11,
            privacy_amplification_rounds: 2,
        },
        ..Default::default()
    };
    
    let mut qtls = QuantumTLS::new(config).unwrap();
    let _keys = qtls.generate_qkd_keys().await.unwrap();
}

async fn benchmark_e91_key_generation() {
    let config = QTLSConfig {
        qkd_protocol: qtls_core::QKDConfig {
            protocol_type: QKDProtocolType::E91,
            key_length: 256,
            error_threshold: 0.11,
            privacy_amplification_rounds: 2,
        },
        ..Default::default()
    };
    
    let mut qtls = QuantumTLS::new(config).unwrap();
    let _keys = qtls.generate_qkd_keys().await.unwrap();
}

fn qkd_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("QKD Protocols");
    
    group.bench_function("BB84 Key Generation", |b| {
        b.iter(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                benchmark_bb84_key_generation().await
            })
        });
    });
    
    group.bench_function("E91 Key Generation", |b| {
        b.iter(|| {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                benchmark_e91_key_generation().await
            })
        });
    });
    
    group.finish();
}

criterion_group!(benches, qkd_benchmarks);
criterion_main!(benches); 