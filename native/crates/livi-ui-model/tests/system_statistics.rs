// SPDX-FileCopyrightText: 2025-2026 Lasse Heitgres
// SPDX-License-Identifier: GPL-3.0-or-later
// Additional terms: see NOTICE

use livi_ui_model::i18n::Strings;
use livi_ui_model::settings::{
    schema,
    view::{Row, Screen, Settings},
};
use serde_json::{Value, json};

fn rows(statistics: Value) -> Vec<Row> {
    let settings = Settings::new(schema());
    let system = settings
        .node(&[])
        .unwrap()
        .children()
        .iter()
        .position(|node| node.route_key() == Some("system"))
        .unwrap();
    let statistics_page = settings
        .node(&[system])
        .unwrap()
        .children()
        .iter()
        .position(|node| node.route_key() == Some("statistics"))
        .expect("System settings must expose the live statistics page");
    let Some(Screen::List { rows, .. }) = settings.screen(
        &[system, statistics_page],
        &json!({"system": {"statistics": statistics}}),
        &Strings::new("en"),
    ) else {
        panic!("Statistics must be a readable list");
    };
    rows
}

fn value<'a>(rows: &'a [Row], label: &str) -> &'a str {
    &rows.iter().find(|row| row.label == label).unwrap().value
}

#[test]
fn live_statistics_show_usage_free_space_and_named_sensors() {
    let rows = rows(json!({
        "cpuUsagePercent": 37.5, "cpuFrequencyMhz": 1800,
        "gpuUsagePercent": 12.0, "gpuFrequencyMhz": 800,
        "memoryTotalBytes": 8589934592u64, "memoryAvailableBytes": 2147483648u64,
        "storageTotalBytes": 137438953472u64, "storageAvailableBytes": 34359738368u64,
        "storagePath": "/data/livi", "uptimeSeconds": 90061,
        "temperatures": [{"name": "soc-thermal", "celsius": 52.25}, {"name": "gpu-thermal", "celsius": 48.0}]
    }));
    assert_eq!(value(&rows, "CPU usage"), "37.5 %");
    assert_eq!(value(&rows, "CPU frequency"), "1800 MHz");
    assert_eq!(value(&rows, "GPU usage"), "12.0 %");
    assert_eq!(value(&rows, "GPU frequency"), "800 MHz");
    assert_eq!(value(&rows, "Memory"), "6.0 / 8.0 GiB used");
    assert_eq!(value(&rows, "Storage"), "32.0 / 128.0 GiB available");
    assert_eq!(value(&rows, "Storage location"), "/data/livi");
    assert_eq!(value(&rows, "Uptime"), "1d 1h 1m");
    assert_eq!(value(&rows, "soc-thermal"), "52.2 °C");
    assert_eq!(value(&rows, "gpu-thermal"), "48.0 °C");
    assert!(rows.iter().all(|row| row.action.is_none()));
}

#[test]
fn missing_sensors_are_unavailable_not_zero() {
    let rows = rows(json!({}));
    for label in [
        "CPU usage",
        "GPU usage",
        "Memory",
        "Storage",
        "Temperatures",
        "Uptime",
    ] {
        assert_eq!(value(&rows, label), "Unavailable");
    }
}

#[test]
fn invalid_metrics_are_not_presented_as_real_measurements() {
    let rows = rows(json!({
        "cpuUsagePercent": -1, "gpuUsagePercent": 102,
        "memoryTotalBytes": 10, "memoryAvailableBytes": 20,
        "storageTotalBytes": 0, "storageAvailableBytes": 0,
        "uptimeSeconds": -3, "temperatures": []
    }));
    for label in ["CPU usage", "GPU usage", "Memory", "Storage", "Uptime"] {
        assert_eq!(value(&rows, label), "Unavailable");
    }
}
