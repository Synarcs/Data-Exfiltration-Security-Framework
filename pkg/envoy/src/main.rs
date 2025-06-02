/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
*/

use std::any::Any;

static DNS_EGRESS_PORT: i32 = 53;
static DNS_EGRESS_MULTICAST_PORT: i32 = 5353;
static LLMNR_EGRESS_LOCAL_MULTICAST_PORT: i32 = 5355;
static NETBIOS_EGRESS_MULTICAST_PORT: i32 = 137;

pub enum Acts {
    DROP,
    FORWARD
}

pub trait FitlerActs {
    fn drop_packet(&self, l7_protocol: u32) -> Acts;
}
struct DnsDpi {}

impl FitlerActs for DnsDpi {
    fn drop_packet(&self, l7_protocol: u32) -> Acts {
        return Acts::DROP;
    }
}

fn main() {

}
