//! Cleanup utility for integration test resources
//!
//! This binary cleans up any leftover resources from integration tests.

use std::process::Command;

use integration_tests::INTEGRATION_TEST_LABEL;

fn main() {
    println!("Cleaning up integration test resources...");

    // Clean up podman containers with our label
    let output = Command::new("podman")
        .args([
            "ps",
            "-a",
            "--filter",
            &format!("label={}", INTEGRATION_TEST_LABEL),
            "-q",
        ])
        .output();

    if let Ok(output) = output {
        let container_ids = String::from_utf8_lossy(&output.stdout);
        for id in container_ids.lines() {
            if !id.is_empty() {
                println!("Removing container: {}", id);
                let _ = Command::new("podman").args(["rm", "-f", id]).output();
            }
        }
    }

    // Clean up podman images with our label
    let output = Command::new("podman")
        .args([
            "images",
            "--filter",
            &format!("label={}", INTEGRATION_TEST_LABEL),
            "-q",
        ])
        .output();

    if let Ok(output) = output {
        let image_ids = String::from_utf8_lossy(&output.stdout);
        for id in image_ids.lines() {
            if !id.is_empty() {
                println!("Removing image: {}", id);
                let _ = Command::new("podman").args(["rmi", "-f", id]).output();
            }
        }
    }

    println!("Cleanup complete.");
}
