//! Cadence/statsd initialization. Must run before anything emits metrics:
//! cadence-macros panics when no global client is installed.

use std::net::UdpSocket;

use anyhow::Context;
use cadence::{BufferedUdpMetricSink, QueuingMetricSink, StatsdClient};
use cadence_macros::{set_global_default, statsd_count};

use crate::config::MetricsConfig;

pub fn init(config: &MetricsConfig) -> anyhow::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0").context("binding statsd socket")?;
    socket
        .set_nonblocking(true)
        .context("setting statsd socket nonblocking")?;
    let sink = BufferedUdpMetricSink::from(config.statsd_endpoint.as_str(), socket)
        .context("connecting statsd sink")?;
    let client = StatsdClient::from_sink(&config.prefix, QueuingMetricSink::from(sink));
    set_global_default(client);
    statsd_count!("boot", 1);
    Ok(())
}

#[cfg(test)]
pub(crate) fn init_for_tests() {
    use cadence::NopMetricSink;
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| set_global_default(StatsdClient::from_sink("test", NopMetricSink)));
}
