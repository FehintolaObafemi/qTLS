fn main() {
    // Tell Cargo that if the given file changes, to rerun this build script.
    println!("cargo:rerun-if-changed=src/lib.rs");
    
    // Set build-time configuration
    println!("cargo:rustc-cfg=feature=\"quantum_tls\"");
    
    // Set version information
    println!("cargo:rustc-env=QTLS_VERSION=1.0.0");
    println!("cargo:rustc-env=QTLS_BUILD_DATE={}", chrono::Utc::now().format("%Y-%m-%d"));
    
    // Enable optimizations for release builds
    if cfg!(feature = "release") {
        println!("cargo:rustc-cfg=feature=\"optimized\"");
    }
} 