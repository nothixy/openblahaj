#ifndef OB_IP_H
#define OB_IP_H

extern const char* IP_PROTOCOLS[146];

enum T_IP_PROTOCOL {
    T_IP_PROTOCOL_HOPOPT,
    T_IP_PROTOCOL_ICMP,
    T_IP_PROTOCOL_IGMP,
    T_IP_PROTOCOL_GGP,
    T_IP_PROTOCOL_IP_in_IP,
    T_IP_PROTOCOL_ST,
    T_IP_PROTOCOL_TCP,
    T_IP_PROTOCOL_CBT,
    T_IP_PROTOCOL_EGP,
    T_IP_PROTOCOL_IGP,
    T_IP_PROTOCOL_BBN_RCC_MON,
    T_IP_PROTOCOL_NVP_II,
    T_IP_PROTOCOL_PUP,
    T_IP_PROTOCOL_ARGUS,
    T_IP_PROTOCOL_EMCON,
    T_IP_PROTOCOL_XNET,
    T_IP_PROTOCOL_CHAOS,
    T_IP_PROTOCOL_UDP,
    T_IP_PROTOCOL_MUX,
    T_IP_PROTOCOL_DCN_MEAS,
    T_IP_PROTOCOL_HMP,
    T_IP_PROTOCOL_PRM,
    T_IP_PROTOCOL_XNS_IDP,
    T_IP_PROTOCOL_TRUNK_1,
    T_IP_PROTOCOL_TRUNK_2,
    T_IP_PROTOCOL_LEAF_1,
    T_IP_PROTOCOL_LEAF_2,
    T_IP_PROTOCOL_RDP,
    T_IP_PROTOCOL_IRTP,
    T_IP_PROTOCOL_ISO_TP4,
    T_IP_PROTOCOL_NETBLT,
    T_IP_PROTOCOL_MFE_NSP,
    T_IP_PROTOCOL_MERIT_INP,
    T_IP_PROTOCOL_DCCP,
    T_IP_PROTOCOL_3PC,
    T_IP_PROTOCOL_IDPR,
    T_IP_PROTOCOL_XTP,
    T_IP_PROTOCOL_DDP,
    T_IP_PROTOCOL_IDPR_CMTP,
    T_IP_PROTOCOL_TP_PLUS_PLUS,
    T_IP_PROTOCOL_IL,
    T_IP_PROTOCOL_IPv6,
    T_IP_PROTOCOL_SDRP,
    T_IP_PROTOCOL_IPv6_Route,
    T_IP_PROTOCOL_IPv6_Frag,
    T_IP_PROTOCOL_IDRP,
    T_IP_PROTOCOL_RSVP,
    T_IP_PROTOCOL_GRE,
    T_IP_PROTOCOL_DSR,
    T_IP_PROTOCOL_BNA,
    T_IP_PROTOCOL_ESP,
    T_IP_PROTOCOL_AH,
    T_IP_PROTOCOL_I_NLSP,
    T_IP_PROTOCOL_SwIPe,
    T_IP_PROTOCOL_NARP,
    T_IP_PROTOCOL_MOBILE,
    T_IP_PROTOCOL_TLSP,
    T_IP_PROTOCOL_SKIP,
    T_IP_PROTOCOL_IPv6_ICMP,
    T_IP_PROTOCOL_IPv6_NoNxt,
    T_IP_PROTOCOL_IPv6_Opts,
    T_IP_PROTOCOL_CFTP = 0x3E,
    T_IP_PROTOCOL_SAT_EXPAK = 0x40,
    T_IP_PROTOCOL_KRYPTOLAN,
    T_IP_PROTOCOL_RVD,
    T_IP_PROTOCOL_IPPC,
    T_IP_PROTOCOL_SAT_MON = 0x45,
    T_IP_PROTOCOL_VISA,
    T_IP_PROTOCOL_IPCU,
    T_IP_PROTOCOL_CPNX,
    T_IP_PROTOCOL_CPHB,
    T_IP_PROTOCOL_WSN,
    T_IP_PROTOCOL_PVP,
    T_IP_PROTOCOL_BR_SAT_MON,
    T_IP_PROTOCOL_SUN_ND,
    T_IP_PROTOCOL_WB_MON,
    T_IP_PROTOCOL_WB_EXPAK,
    T_IP_PROTOCOL_ISO_IP,
    T_IP_PROTOCOL_VMTP,
    T_IP_PROTOCOL_SECURE_VMTP,
    T_IP_PROTOCOL_VINES,
    T_IP_PROTOCOL_TTP_IPTM,
    T_IP_PROTOCOL_NSFNET_IGP,
    T_IP_PROTOCOL_DGP,
    T_IP_PROTOCOL_TCF,
    T_IP_PROTOCOL_EIGRP,
    T_IP_PROTOCOL_OSPF,
    T_IP_PROTOCOL_Sprite_RPC,
    T_IP_PROTOCOL_LARP,
    T_IP_PROTOCOL_MTP,
    T_IP_PROTOCOL_AX_25,
    T_IP_PROTOCOL_OS,
    T_IP_PROTOCOL_MICP,
    T_IP_PROTOCOL_SCC_SP,
    T_IP_PROTOCOL_ETHERIP,
    T_IP_PROTOCOL_ENCAP,
    T_IP_PROTOCOL_GMTP = 0x64,
    T_IP_PROTOCOL_IFMP,
    T_IP_PROTOCOL_PNNI,
    T_IP_PROTOCOL_PIM,
    T_IP_PROTOCOL_ARIS,
    T_IP_PROTOCOL_SCPS,
    T_IP_PROTOCOL_QNX,
    T_IP_PROTOCOL_A_N,
    T_IP_PROTOCOL_IPComp,
    T_IP_PROTOCOL_SNP,
    T_IP_PROTOCOL_Compaq_Peer,
    T_IP_PROTOCOL_IPX_in_IP,
    T_IP_PROTOCOL_VRRP,
    T_IP_PROTOCOL_PGM,
    T_IP_PROTOCOL_L2TP = 0x73,
    T_IP_PROTOCOL_DDX,
    T_IP_PROTOCOL_IATP,
    T_IP_PROTOCOL_STP,
    T_IP_PROTOCOL_SRP,
    T_IP_PROTOCOL_UTI,
    T_IP_PROTOCOL_SMP,
    T_IP_PROTOCOL_SM,
    T_IP_PROTOCOL_PTP,
    T_IP_PROTOCOL_IS_IS_over_IPv4,
    T_IP_PROTOCOL_FIRE,
    T_IP_PROTOCOL_CRTP,
    T_IP_PROTOCOL_CRUDP,
    T_IP_PROTOCOL_SSCOPMCE,
    T_IP_PROTOCOL_IPLT,
    T_IP_PROTOCOL_SPS,
    T_IP_PROTOCOL_PIPE,
    T_IP_PROTOCOL_SCTP,
    T_IP_PROTOCOL_FC,
    T_IP_PROTOCOL_RSVP_E2E_IGNORE,
    T_IP_PROTOCOL_UDPLite = 0x88,
    T_IP_PROTOCOL_MPLS_in_IP,
    T_IP_PROTOCOL_manet,
    T_IP_PROTOCOL_HIP,
    T_IP_PROTOCOL_Shim6,
    T_IP_PROTOCOL_WESP,
    T_IP_PROTOCOL_ROHC,
    T_IP_PROTOCOL_Ethernet,
    T_IP_PROTOCOL_AGGFRAG,
    T_IP_PROTOCOL_NSH
};

#endif
