use std::{collections::HashMap, task::Context};

use log::info;
use proxy_wasm::{traits::{RootContext}, types::LogLevel};

/*
    A Envoy Wasm filter to integrate with live traffic of DNS carrying data breaches over DNS for live ONNX inferencing over deep learning for enhanced obfuscation detection
    live redirected via kernel eBPF programs running over kernel TC, sock layer, cgroup layer
    the node agent in go tracks the conn state in kernel sock sock maps for proxy filter
*/

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(DnsFilterSet { blocked_domains: HashMap::new() }) });
}}

struct DnsFilterSet {
    blocked_domains: HashMap<String, bool>
}

impl proxy_wasm::traits::Context for DnsFilterSet {}

impl RootContext for DnsFilterSet {
    fn on_vm_start(&mut self, _vm_configuration_size: usize) -> bool {
        info!("DNS Filter loaded");
        true
    }
}

