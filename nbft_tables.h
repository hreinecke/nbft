/*
 *  ACPI NBFT table structures (spec v0.65)
 */

#define NBFT_ACPI_SIG		"NBFT"

enum nbft_descriptor_type {
	NBFT_HEADER,
	NBFT_CONTROL,
	NBFT_HOST,
	NBFT_HFI,
	NBFT_SSNS,
	NBFT_SECURITY,
	NBFT_DISCOVERY,
	NBFT_HFI_TRANSPORT,
	RESERVED_8,
	NBFT_SSNS_EXTENDED_INFO,
};

typedef struct __attribute__((__packed__)) nbft_heap_obj_s {
	__u32 offset;
	__u16 length;
} nbft_heap_obj;

/*
 * HEADER (Figure 8)
 */
struct __attribute__((__packed__)) nbft_header {
	char signature[4];
	__u32 length;
	__u8 major_revision;
	__u8 checksum;
	char oem_id[6];
	char oem_table_id[8];
	__u32 oem_revision;
	__u32 creator_id;
	__u32 creator_revision;
	__u32 heap_offset;
	__u32 heap_length;
	nbft_heap_obj driver_dev_path_sig;
	__u8 minor_revision;
	__u8 reserved[13];
};

struct __attribute__((__packed__)) nbft_desc_offset {
	__u32 offset;
	__u16 length;
	__u8 version;
	__u8 num_desc;
};

/*
 * CONTROL (Figure 8)
 */
struct __attribute__((__packed__)) nbft_control {
	__u8 structure_id;
	__u8 major_revision;
	__u8 minor_revision;
	__u8 reserved1;
	__u16 length;
	__u8 flags;
	__u8 reserved2;

	struct {
		__u32 offset;
		__u16 length;
		__u8 version;
		__u8 reserved3;
	} host;

	struct nbft_desc_offset hfi;

	struct nbft_desc_offset ssns;

	struct nbft_desc_offset security;

	struct nbft_desc_offset discovery;

	__u8 reserved4[16];
};

#define CONTROLFLAG_VALID		0x01

/*
 * HOST DESCRIPTOR (Figure 9)
 */
struct __attribute__((__packed__)) nbft_host_desc {
	__u8 structure_id;
	__u8 flags;
	__u8 identifier[16];
	nbft_heap_obj nqn;
	__u8 reserved[8];
};

#define HOSTFLAG_VALID			0x01
#define HOSTFLAG_HOSTID_CONFIGURED	0x02
#define HOSTFLAG_HOSTNQN_CONFIGURED	0x04
#define HOSTFLAG_PRIMARY_ADMIN_HOST	0x18

enum nbft_transport_types {
	nbft_trtype_tcp = 3,
};

/*
 * HFI DESCRIPTOR (Figure 11)
 */
struct __attribute__((__packed__)) nbft_hfi_desc {
	__u8 structure_id;
	__u8 index;
	__u8 flags;
	__u8 transport_type;
	__u8 reserved1[12];
	nbft_heap_obj transport_descriptor;
	__u8 reserved2[10];
};

#define HFIFLAG_VALID		0x01

enum  {
    NBFT_IPORIGIN_OTHER = 0,
    NBFT_IPORIGIN_MANUAL,
    NBFT_IPORIGIN_WELLKNOWN,
    NBFT_IPORIGIN_DHCP,
    NBFT_IPORIGIN_RADV,
    NBFT_IPORIGIN_UNCHANGED = 16,
};

/*
 * HFI TRANSPORT INFO DESCRIPTOR (Figure 13)
 */
struct __attribute__((__packed__)) nbft_hfi_info_tcp_desc {
	__u8 structure_id;
	__u8 version;
	__u8 hfi_transport_type;
	__u8 transport_info_version;
	__u16 hfi_index;
	__u8 transport_flags;
	__u32 pci_sbdf;
	__u8 mac_addr[6];
	__u16 vlan;
	__u8 ip_origin;
	__u8 ip_address[16];
	__u8 subnet_mask_prefix;
	__u8 ip_gateway[16];
	__u8 reserved1;
	__u16 route_metric;
	__u8 primary_dns[16];
	__u8 secondary_dns[16];
	__u8 dhcp_server[16];
	nbft_heap_obj host_name;
	__u8 reserved2[18];
};

#define HFIINFOTCPFLAG_VALID		0x01
#define HFIINFOTCPFLAG_GLOBAL_ROUTE	0x02
#define HFIINFOTCPFLAG_DHCP_OVERRIDE	0x04

/*
 * SUBSYSTEM NAMESPACE DESCRIPTOR (Figure 15)
 */
struct __attribute__((__packed__)) nbft_ssns_desc {
	__u8 structure_id;
	__u16 index;
	__u16 flags;
	__u8 transport_type;
	__u16 transport_specific_flags;
	__u8 primary_discovery_ctrl_index;
	__u8 reserved1;
	nbft_heap_obj transport_address;
	nbft_heap_obj transport_svcid;
	__u16 port_id;
	__u32 nsid;
	__u8 nid_type;
	__u8 nid[16];
	__u8 security_descriptor_index;
	__u8 primary_hfi_descriptor_index;
	__u8 reserved2;
	nbft_heap_obj secondary_hfi_associations;
	nbft_heap_obj namespace_nqn;
	nbft_heap_obj extended_info_descriptor;
	__u8 reserved3[62];
};

#define SSNSFLAG_VALID				0x0001
#define SSNSFLAG_NON_BOOTABLE_ENTRY		0x0002
#define SSNSFLAG_USE_SECURITY_FIELD		0x0004
#define SSNSFLAG_DHCP_ROOT_PATH_OVERRIDE	0x0008
#define SSNSFLAG_EXTENDED_INFO_IN_USE		0x0010
#define SSNSFLAG_SEPARATE_DISCOVERY_CONTROLLER	0x0020
#define SSNSFLAG_DISCOVERED_NAMESPACE		0x0040
#define SSNSFLAG_UNAVAILABLE_NAMESPACE		0x0180
#define SSNSFLAG_UNAVAILABLE_NAMESPACE_NOTIND	 0x0000
#define SSNSFLAG_UNAVAILABLE_NAMESPACE_AVAIL	 0x0080
#define SSNSFLAG_UNAVAILABLE_NAMESPACE_UNAVAIL	 0x0100
#define SSNSFLAG_UNAVAILABLE_NAMESPACE_RESV	 0x0180

#define SSNS_TCP_FLAG_VALID		0x01
#define SSNS_TCP_FLAG_PDU_HEADER_DIGEST	0x02
#define SSNS_TCP_FLAG_DATA_DIGEST	0x04

/*
 * SUBSYSTEM AND NAMESPACE EXTENDED INFORMATION DESCRIPTOR (Figure 19)
 */
struct __attribute__((__packed__)) nbft_ssns_extended_info_desc {
	__u8 structure_id;
	__u8 version;
	__u16 ssns_index;
	__u32 flags;
	__u16 controller_id;
	__u16 asqsz;
	nbft_heap_obj dhcp_root_path_string;
};

#define SSNS_EXTINFO_FLAG_VALID		0x01
#define SSNS_EXTINFO_FLAG_ADMIN_ASQSZ	0x02

/*
 * SECURITY DESCRIPTOR (Figure 21)
 */
struct __attribute__((__packed__)) nbft_security_desc {
	__u8 structure_id;
	__u8 index;
	__u16 flags;
	__u8 secret_type;
	__u8 reserved1;
	nbft_heap_obj secure_channel_algorithm;
	nbft_heap_obj authentication_protocols;
	nbft_heap_obj cipher_suite;
	nbft_heap_obj dh_groups;
	nbft_heap_obj secure_hash_functions;
	nbft_heap_obj secret_keypath;
	__u8 reserved2[22];
};

#define SECFLAG_VALID(x)					0x0001 
#define SECFLAG_IN_BAND_AUTHENTICATION_REQUIRED			0x0006
#define SECFLAG_AUTHENTICATION_POLICY_LIST			0x0018
#define SECFLAG_AUTHENTICATION_POLICY_LIST_NOT_SUP		 0x0000
#define SECFLAG_AUTHENTICATION_POLICY_LIST_SUP			 0x0008
#define SECFLAG_AUTHENTICATION_POLICY_LIST_REQ			 0x0010
#define SECFLAG_AUTHENTICATION_POLICY_LIST_RSVD			 0x0018
#define SECFLAG_SECURE_CHANNEL_NEGOTIATION			0x0060
#define SECFLAG_SECURE_CHANNEL_NEGOTIATION_NOT_SUP		 0x0000
#define SECFLAG_SECURE_CHANNEL_NEGOTIATION_SUP			 0x0020
#define SECFLAG_SECURE_CHANNEL_NEGOTIATION_REQ			 0x0040
#define SECFLAG_SECURE_CHANNEL_NEGOTIATION_RSVD			 0x0060
#define SECFLAG_SECURITY_POLICY_LIST				0x0180
#define SECFLAG_SECURITY_POLICY_LIST_NOT_PRES			 0x0000
#define SECFLAG_SECURITY_POLICY_LIST_PRES			 0x0080
#define SECFLAG_SECURITY_POLICY_LIST_PRES_ADMINSET		 0x0100
#define SECFLAG_SECURITY_POLICY_LIST_RSVD			 0x0180
#define SECFLAG_CIPHER_SUITES_RESTRICTED_BY_POLICY		0x0200
#define SECFLAG_AUTH_DH_GROUPS_RESTRICTED_BY_POLICY_LIST	0x0400
#define SECFLAG_SECURE_HASH_FUNCTIONS_POLICY_LIST		0x0800

enum secret_type {
	SECRET_TYPE_RESERVED,
	SECRET_TYPE_REDFISH_HOST_INTERFACE_URI,
};

/*
 * DISCOVERY DESCRIPTOR (Figure 24)
 */
struct __attribute__((__packed__)) nbft_discovery_desc {
	__u8 structure_id;
	__u8 flags;
	__u8 index;
	__u8 hfi_index;
	__u8 security_index;
	__u8 reserved1;
	nbft_heap_obj controller_addr;
	nbft_heap_obj controller_nqn;
	__u8 reserved2[14];
};

#define DISCOVERYFLAG_VALID	0x01
