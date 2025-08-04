/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package events

// kernel eBPF maps over kernel network stack
const (
	EXFILL_SECURITY_EGRESS_REDIRECT_MAP                   = "exfil_security_egress_redirect_map"
	EXFILL_SECURITY_EGRESS_REDIRECT_TC_VERIFY_MAP         = "exfil_security_egress_redurect_ts_verify"
	EXFILL_SECURITY_KERNEL_CONFIG_MAP                     = "exfil_security_config_map"
	EXFILL_SECURITY_KERNEL_DNS_LIMITS_MAP                 = "exfil_security_egress_dns_limites"
	EXFILL_SECURITY_KERNEL_REDIRECT_COUNT_MAP             = "exfil_security_egress_redirect_count_map"
	EXFILL_SECURITY_EGRESS_REDIRECT_KERNEL_DROP_COUNT_MAP = "exfil_security_egress_redirect_drop_count_map"
	EXFILL_SECURITY_EGRESS_REDIRECT_LOOP_TIME             = "exfil_security_egress_redirect_loop_time"

	EXFIL_SECURITY_EGRESS_CLONE_REDIRECT_COUNT_MAP             = "exfil_security_egress_clone_redirect_count_map"
	EXFIL_SECURITY_EGRESS_CLONE_REDIRECT_DROP_KERNEL_COUNT_MAP = "exfil_security_egress_clone_redirect_drop_kernel_count_map"

	EXFIL_VXLAN_TRANSFER_EGRESS_PORT = "exfil_vxlan_transfer_egress_port" // vxlan is always tied to dedicated netdev in kernel
	EXFIL_TC_BRIDGE_CONFIG_MAP       = "exfil_security_tc_bridge_config_map"

	// tunnel map
	EXFIL_TUNNEL_DNS_ENCAP_TRANSFER = "exfil_tunnel_dns_encap_transfer"

	// all maps for deep scan from kernel maps
	EXFIL_SECURITY_EGREES_CLONE_REDIRECT_MAP_NON_STANDARD_PORT = "exfil_security_egrees_clone_redirect_map_non_standard_port"
	EXFIL_SECURITY_LOOPBACK_TRANSPORT_PORTS                    = "exfil_security_loopback_transport_ports"
)

// kernel eBPF ring buffers over kernel network stack
const (
	EXFIL_SECURITY_EGREES_REDIRECT_RING_BUFF_NON_STANDARD_PORT = "exfil_security_egrees_clone_redirect_ring_buff_non_standard_port"
	EXFIL_SECURITY_EGRESS_VXLAN_ENCAP_DROP                     = "exfil_security_egress_vxlan_encap_drop"
	EXFIL_SECURITY_EGRESSS_DPI_TIME                            = "exfil_security_egresss_dpi_time"
	EXFIL_SECURITY_ERROR_PIPE_AGENT                            = "exfil_security_error_pipe_agent"
)

// maps for kernel timers
const (
	EXFIL_SECURITY_TOKEN_BUCKET_DNS_RL = "exfil_security_token_bucket_dns_rl"
)

// pinned maps
const (
	EXFIL_SECURITY_EGRESS_PROC_MAL                          = "exfil_security_egress_proc_mal"
	EXFIL_SECURITY_EGRESS_NSP_MAP                           = "exfil_security_egress_nsp_map"
	EXFIL_SOCK_UDP_CONN_MAP                                 = "exfil_sock_udp_conn_map"
	EXFIL_SECURITY_EGRESS_L3_IPV4_DYNAMIC_NETPOOL_C2_FILTER = "exfil_security_egress_l3_ipv4_dynamic_netpool_c2_filter"
	EXFIL_SECURITY_EGRESS_L3_IPV6_DYNAMIC_NETPOOL_C2_FILTER = "exfil_security_egress_l3_ipv6_dynamic_netpool_c2_filter"
)

// lsm crypto maps in kernel
const (
	EXFIL_SECURITY_ORIGINAL_PROGRAM   = "exfil_security_original_program"
	EXFIL_SECURITY_MODIFIED_SIGNATURE = "exfil_security_modified_signature"
	EXFIL_SECURITY_KEYRING_MAP        = "exfil_security_keyring_map"
	EXFIL_SECURITY_COMBINED_DATA_MAP  = "exfil_security_combined_data_map"
)
