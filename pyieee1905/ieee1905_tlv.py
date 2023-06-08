import struct

from scapy.packet import Packet
from scapy.fields import BitField, XByteField, XShortField, MACField, IPField, \
        X3BytesField, XIntField, ConditionalField, \
        StrLenField, StrFixedLenField, FieldLenField, FieldListField, PacketListField

from scapy.layers.inet6 import IP6Field
from scapy.compat import orb
from scapy.config import conf


class IEEE1905_TLV(Packet):
    name = "IEEE1905 TLV"

    fields_desc = [
        XByteField("type", None),
        XShortField("len", None)
    ]

    def post_build(self, p, pay):
        if self.len is None:
            l = len(p) - 3
            p = p[:1] + struct.pack("!H", l) + p[3:]
        return p + pay

    def do_dissect_payload(self, s):
        if s:
            try:
                p = IEEE1905_TLV(s, _internal=1, _underlayer=self)
            except KeyboardInterrupt:
                raise
            except:
                p = conf.raw_layer(s, _internal=1, _underlayer=self)
            self.add_payload(p)

    registered_tlv_types = {}
    @classmethod
    def register_variant(cls):
        cls.registered_tlv_types[cls.type.default] = cls
    @classmethod
    def dispatch_hook(cls, pkt=None, *args, **kargs):
        if pkt:
            t = orb(pkt[0])
            if t in cls.registered_tlv_types:
                return cls.registered_tlv_types[t]
        return cls


# End of Message TLV (0x00)
class EOM(IEEE1905_TLV):
    name = "End of Message TLV"
    fields_desc = [
        XByteField("type", 0),
        XShortField("len", None)
    ]


# AL MAC Address Type TLV (0x01)
class AlMacAddrType(IEEE1905_TLV):
    name = "AL MAC Address Type TLV"
    fields_desc = [
        XByteField("type", 0x01),
        XShortField("len", None),
        MACField("mac", None)
    ]


# MAC Address Type TLV (0x02)
class MacAddrType(IEEE1905_TLV):
    name = "MAC Address Type TLV"
    fields_desc = [
        XByteField("type", 0x02),
        XShortField("len", None),
        MACField("mac", None)
    ]


# Device Information Type TLV (0x03)
class DevInfoType_LocalIface(Packet):
    name = "Local Interface"
    fields_desc = [
        MACField("mac", None),
        XShortField("media_type", None),
        FieldLenField("media_specific_data_size", None, length_of="media_specific_data"),
        FieldListField("media_specific_data", None, XByteField("byte", None),
                       length_from=lambda p:p.media_specific_data_size)
    ]

    def extract_padding(self, s):
        return "", s

class DevInfoType(IEEE1905_TLV):
    name = "Device Information Type TLV"
    fields_desc = [
        XByteField("type", 0x03),
        XShortField("len", None),
        MACField("al_mac", None),
        FieldLenField("local_iface_cnt", None, fmt='B', count_of="local_iface_list"),
        PacketListField("local_iface_list", None, DevInfoType_LocalIface,
                        count_from=lambda p:p.local_iface_cnt)
    ]


# Device Bridging Capability TLV (0x04)
class DevBridgingCap_BridgingTuple(Packet):
    name = "Bridging Tuple"
    fields_desc = [
        FieldLenField("bridging_tuple_cnt", None, fmt='B', count_of="bridging_tuple_list"),
        FieldListField("bridging_tuple_list", None, MACField("mac", None),
                       count_from=lambda p:p.bridging_tuple_cnt)
    ]

    def extract_padding(self, s):
        return "", s


class DevBridgingCap(IEEE1905_TLV):
    name = "Device Bridging Capability TLV"
    fields_desc = [
        XByteField("type", 0x04),
        XShortField("len", None),
        FieldLenField("bridging_tuple_cnt", None, fmt='B', count_of="bridging_tuple_list"),
        PacketListField("bridging_tuple_list", None, DevBridgingCap_BridgingTuple,
                        count_from=lambda p:p.bridging_tuple_cnt)
    ]



# Non-1905 Neighbor Device List TLV (0x06)
class Non1905NeighDevList(IEEE1905_TLV):
    name = "Non-1905 Neighbor Device List TLV"
    fields_desc = [
        XByteField("type", 0x06),
        XShortField("len", None),
        MACField("local_mac", None),
        FieldLenField("non1905_neigh_cnt", None, fmt='B', count_of="non1905_neigh_list"),
        FieldListField("non1905_neigh_list", None, MACField("mac", None),
                       count_from=lambda p:p.non1905_neigh_cnt)
    ]



# Neighbor Device TLV (0x07)
class NeighDevice_Entry(Packet):
    name = "Entry"
    fields_desc = [
        MACField("al_mac", None),
        BitField("bridge_flag", None, 1),
        BitField("reserved", None, 7)
    ]

    def extract_padding(self, s):
        return "", s


class NeighDevice(IEEE1905_TLV):
    name = "Neighbor Device TLV"
    fields_desc = [
        XByteField("type", 0x07),
        XShortField("len", None),
        MACField("local_mac", None),
        FieldLenField("neigh_cnt", None, fmt='B', count_of="neigh_list"),
        PacketListField("neigh_list", None, NeighDevice_Entry, count_from=lambda p:p.neigh_cnt)
    ]



# Link Metric Query TLV (0x08)
class LinkMetricQuery(IEEE1905_TLV):
    name = "Link Metric Query TLV"
    fields_desc = [
        XByteField("type", 0x08),
        XShortField("len", None),
        XByteField("dest", None),
        ConditionalField(MACField("specific_neigh_mac", None),lambda p:p.dest==0x01),
        XByteField("link_metrics_type", None)
    ]


# Transmitter Link Metric TLV (0x09)
class TxLinkMetric_Entry(Packet):
    name = "Entry"
    fields_desc = [
        MACField("local_al_mac", None),
        MACField("neigh_al_mac", None),
        XShortField("media_type", None),
        XByteField("bridge_flag", None),
        XIntField("packet_errors", None),
        XIntField("tx_packets", None),
        XShortField("mac_throughput_capacity", None),
        XShortField("link_availability", None),
        XShortField("phy_rate", None)
    ]

    def extract_padding(self, s):
        return "", s


class TxLinkMetric(IEEE1905_TLV):
    name = "Transmitter Link Metric TLV"
    fields_desc = [
        XByteField("type", 0x09),
        XShortField("len", None),
        MACField("local_al_mac", None),
        MACField("neigh_al_mac", None),
        FieldLenField("metric_cnt", None, fmt='B', count_of="metric_list"),
        PacketListField("metric_list", None, TxLinkMetric_Entry,
                        count_from=lambda p:p.metric_cnt)
    ]


# Receiver Link Metric TLV (0x0A)
class RxLinkMetric_Entry(Packet):
    name = "Entry"
    fields_desc = [
        MACField("local_al_mac", None),
        MACField("neigh_al_mac", None),
        XShortField("media_type", None),
        XIntField("packet_errors", None),
        XIntField("rx_packets", None),
        XByteField("rssi", None)
    ]

    def extract_padding(self, s):
        return "", s


class RxLinkMetric(IEEE1905_TLV):
    name = "Receiver Link Metric TLV"
    fields_desc = [
        XByteField("type", 0x0A),
        XShortField("len", None),
        MACField("local_al_mac", None),
        MACField("neigh_al_mac", None),
        FieldLenField("metric_cnt", None, fmt='B', count_of="metric_list"),
        PacketListField("metric_list", None, RxLinkMetric_Entry,
                        count_from=lambda p:p.metric_cnt)
    ]


# Vendor Specific TLV (0x0B)
class VendorSpecific(IEEE1905_TLV):
    name = "Vendor Specific TLV"
    fields_desc = [
        XByteField("type", 0x0B),
        XShortField("len", None),
        X3BytesField("vendor_oui", None),
        FieldListField("vendor_data", None, XByteField("byte", None),
                       count_from=lambda p:p.vendor_data_len)
    ]



# Link Metric Result Code TLV (0x0C)
class LinkMetricResultCode(IEEE1905_TLV):
    name = "Link Metric Result Code TLV"
    fields_desc = [
         XByteField("type", 0x0C),
         XShortField("len", None),
         XByteField("result_code", None)
    ]



# Searched Role TLV (0x0D)
class SearchedRole(IEEE1905_TLV):
    name = "Searched Role TLV"
    fields_desc = [
         XByteField("type", 0x0D),
         XShortField("len", None),
         XByteField("role", None)
    ]


# Autoconfig Frequency Band TLV (0x0E)
class AutoconfigFreqBand(IEEE1905_TLV):
    name = "Autoconfig Frequency Band TLV"
    fields_desc = [
        XByteField("type", 0x0E),
        XShortField("len", None),
        XByteField("freq_band", None)
    ]


# Supported Role TLV (0x0F)
class SupportedRole(IEEE1905_TLV):
    name = "Supported Role TLV"
    fields_desc = [
        XByteField("type", 0x0F),
        XShortField("len", None),
        XByteField("role", None)
    ]


# Supported Frequency Band TLV (0x10)
class SupportedFreqBand(IEEE1905_TLV):
    name = "Supported Frequency Band TLV"
    fields_desc = [
        XByteField("type", 0x10),
        XShortField("len", None),
        XByteField("freq_band", None)
    ]



# WSC TLV (0x11)
class WSC(IEEE1905_TLV):
    name = "WSC TLV"
    fields_desc = [
        XByteField("type", 0x11),
        XShortField("len", None),
        FieldListField("wsc_frame", None, XByteField("byte", None),
                       count_from=lambda p:p.wsc_frame_size)
    ]


# Push Button Event Notification TLV (0x12)
class PushBtnEventNotif_MediaTypeEntry(Packet):
    name = "Media Type"
    fields_desc = [
        XShortField("media_type", None),
        FieldLenField("media_specific_data_size", None, fmt='B', length_of="media_specific_data"),
        FieldListField("media_specific_data", None, XByteField("byte", None),
                       length_from=lambda p:p.media_specific_data_size)
    ]

    def extract_padding(self, s):
        return "", s


class PushBtnEventNotif(IEEE1905_TLV):
    name = "Push Button Event Notification TLV"
    fields_desc = [
        XByteField("type", 0x12),
        XShortField("len", None),
        FieldLenField("media_type_cnt", None, fmt='B', count_of="media_type_list"),
        PacketListField("media_type_list", None, PushBtnEventNotif_MediaTypeEntry,
                        count_from=lambda p:p.media_type_cnt)
    ]


# Push Button Join Notification TLV (0x13)
class PushBtnJoinNotif(IEEE1905_TLV):
    name = "Push Button Join Notification TLV"
    fields_desc = [
        XByteField("type", 0x13),
        XShortField("len", None),
        MACField("al_mac", None),
        XShortField("msg_id", None),
        MACField("mac", None),
        MACField("new_mac", None)
    ]


# Generic PHY Device Information TLV (0x14)
class GenericPhyDevInfo_LocalIface(Packet):
    name = "Local Interface"
    fields_desc = [
        MACField("mac", None),
        X3BytesField("oui", None),
        XByteField("variant_index", None),
        FieldLenField("media_specific_bytes_nr", None, fmt='B', count_of="media_specific_bytes"),
        FieldListField("media_specific_bytes", None, XByteField("byte", None),
                       count_from=lambda p:p.media_specific_bytes_nr),
        StrFixedLenField("variant_name", None, length=32),
        FieldLenField("generic_phy_desc_xml_url_len", None, fmt='B', length_of="generic_phy_desc_xml_url"),
        StrLenField("generic_phy_desc_xml_url", None, length_from=lambda p:p.generic_phy_desc_xml_url_len)
    ]

    def extract_padding(self, s):
        return "", s


class GenericPhyDevInfo(IEEE1905_TLV):
    name = "Generic PHY Device Information TLV"
    fields_desc = [
        XByteField("type", 0x14),
        XShortField("len", None),
        MACField("al_mac", None),
        FieldLenField("local_iface_cnt", None, fmt='B', count_of="local_iface_list"),
        PacketListField("local_iface_list", None, GenericPhyDevInfo_LocalIface,
                        count_from=lambda p:p.local_iface_cnt)
    ]



# Device Identification Type TLV (0x15)
class DevIdType(IEEE1905_TLV):
    name = "Device Identification Type TLV"
    fields_desc = [
        XByteField("type", 0x15),
        XShortField("len", None),
        StrFixedLenField("friendly_name", None, length=64),
        StrFixedLenField("mfr_name", None, length=64),
        StrFixedLenField("mfr_model", None, length=64)
    ]


# Control URL Type TLV (0x16)
class CtrlURLType(IEEE1905_TLV):
    name = "Control URL Type TLV"
    fields_desc = [
        XByteField("type", 0x16),
        XShortField("len", None),
        StrLenField("url", "", length_from=lambda p:p.len)
    ]


# IPv4 Type TLV (0x17)
class IPv4Entry(Packet):
    name = "IPv4 Entry"
    fields_desc = [
        XByteField("type", None),
        IPField("iface_addr", None),
        IPField("dhcp_server_addr", None)
    ]

    def extract_padding(self, s):
        return "", s


class IPv4IfaceEntry(Packet):
    name = "Interface Entry"
    fields_desc = [
        MACField("iface_mac", None),
        FieldLenField("ipv4_entry_cnt", None, fmt='B', count_of="ipv4_entry_list"),
        PacketListField("ipv4_entry_list", None, IPv4Entry, count_from=lambda p:p.ipv4_entry_cnt)
    ]

    def extract_padding(self, s):
        return "", s


class IPv4Type(IEEE1905_TLV):
    name = "IPv4 Type TLV"
    fields_desc = [
        XByteField("type", 0x17),
        XShortField("len", None),
        FieldLenField("ipv4_iface_cnt", None, fmt='B', count_of="ipv4_iface_list"),
        PacketListField("ipv4_iface_list", None, IPv4IfaceEntry, count_from=lambda p:p.ipv4_iface_cnt)
    ]


# IPv6 Type TLV (0x18)
class IPv6Entry(Packet):
    name = "IPv6 Entry"
    fields_desc = [
        XByteField("type", None),
        IP6Field("iface_addr", "::"),
        IP6Field("addr_origin", "::")
    ]

    def extract_padding(self, s):
        return "", s


class IPv6IfaceEntry(Packet):
    name = "Interface Entry"
    fields_desc = [
        MACField("iface_mac", None),
        IP6Field("lladdr", "::"),
        FieldLenField("ipv6_entry_cnt", None, fmt='B', count_of="ipv6_entry_list"),
        PacketListField("ipv6_entry_list", None, IPv6Entry, count_from=lambda p:p.ipv6_entry_cnt)
    ]

    def extract_padding(self, s):
        return "", s


class IPv6Type(IEEE1905_TLV):
    name = "IPv6 Type TLV"
    fields_desc = [
        XByteField("type", 0x18),
        XShortField("len", None),
        FieldLenField("ipv6_iface_cnt", None, fmt='B', count_of="ipv6_iface_list"),
        PacketListField("ipv6_iface_list", None, IPv6IfaceEntry, count_from=lambda p:p.ipv6_iface_cnt)
    ]


# Push Button Generic PHY Event Notification TLV (0x19)
class PushBtnGenericPhyEventNotif_LocalIface(Packet):
    name = "Generic PHY Info"
    fields_desc = [
        X3BytesField("oui", None),
        XByteField("variant_index", None),
        FieldLenField("media_specific_bytes_nr", None, fmt='B', count_of="media_specific_bytes"),
        FieldListField("media_specific_bytes", None, XByteField("byte", None),
                       count_from=lambda p:p.media_specific_bytes_nr),
    ]

    def extract_padding(self, s):
        return "", s


class PushBtnGenericPhyEventNotif(IEEE1905_TLV):
    name = "Push Button Generic PHY Event Notification TLV"
    fields_desc = [
        XByteField("type", 0x19),
        XShortField("len", None),
        FieldLenField("local_iface_cnt", None, fmt='B', count_of="local_iface_list"),
        PacketListField("local_iface_list", None, PushBtnGenericPhyEventNotif_LocalIface,
                        count_from=lambda p:p.local_iface_cnt)
    ]


# 1905 Profile Version TLV (0x1A)
class IEEE1905ProfileVersion(IEEE1905_TLV):
    name = "1905 Profile Version TLV"
    fields_desc = [
        XByteField("type", 0x1A),
        XShortField("len", None),
        XByteField("profile", None)
    ]


# Power Off Interface TLV (0x1B)
class PowerOffIface_Entry(Packet):
    name = "Interface Entry"
    fields_desc = [
        MACField("mac", None),
        XShortField("media_type", None),
        X3BytesField("oui", None),
        XByteField("variant_index", None),
        FieldLenField("media_specific_bytes_nr", None, fmt='B', count_of="media_specific_bytes"),
        FieldListField("media_specific_bytes", None, XByteField("byte", None),
                       count_from=lambda p:p.media_specific_bytes_nr)
    ]

    def extract_padding(self, s):
        return "", s


class PowerOffIface(IEEE1905_TLV):
    name = "Power Off Interface TLV"
    fields_desc = [
        XByteField("type", 0x1B),
        XShortField("len", None),
        FieldLenField("entry_cnt", None, fmt='B', count_of="entry_list"),
        PacketListField("entry_list", None, PowerOffIface_Entry,
                        count_from=lambda p:p.entry_cnt)
    ]


# Interface Power Change Information TLV (0x1C)
class IfacePowerChangeInfo_Entry(Packet):
    name = "Interface Entry"
    fields_desc = [
        MACField("mac", None),
        XByteField("power_state", None)
    ]

    def extract_padding(self, s):
        return "", s


class IfacePowerChangeInfo(IEEE1905_TLV):
    name = "Interface Power Change Information TLV"
    fields_desc = [
        XByteField("type", 0x1C),
        XShortField("len", None),
        FieldLenField("entry_cnt", None, fmt='B', count_of="entry_list"),
        PacketListField("entry_list", None, IfacePowerChangeInfo_Entry,
                        count_from=lambda p:p.entry_cnt)
    ]


# Interface Power_Change Status TLV (0x1D)
class IfacePowerChangeStatus_Entry(Packet):
    name = "Interface Entry"
    fields_desc = [
        MACField("mac", None),
        XByteField("power_state", None)
    ]

    def extract_padding(self, s):
        return "", s


class IfacePowerChangeStatus(IEEE1905_TLV):
    name = "Interface Power Change Status TLV"
    fields_desc = [
        XByteField("type", 0x1D),
        XShortField("len", None),
        FieldLenField("entry_cnt", None, fmt='B', count_of="entry_list"),
        PacketListField("entry_list", None, IfacePowerChangeStatus_Entry,
                        count_from=lambda p:p.entry_cnt)
    ]


# L2 Neighbor Device TLV (0x1E)
class L2NeighDevice_NeighEntry(Packet):
    name = "Neighbor Entry"
    fields_desc = [
        MACField("neigh_mac", None),
        FieldLenField("behind_mac_cnt", None, fmt='B', count_of="behind_mac_list"),
        FieldListField("behind_mac_list", None, MACField("mac", None), count_from=lambda p:p.behind_mac_cnt)
    ]

    def extract_padding(self, s):
        return "", s


class L2NeighDevice_IfaceEntry(Packet):
    name = "Interface Entry"
    fields_desc = [
        MACField("mac", None),
        FieldLenField("neigh_entry_cnt", None, fmt='B', count_of="neigh_entry_list"),
        PacketListField("neigh_entry_list", None, L2NeighDevice_NeighEntry,
                        count_from=lambda p:p.neigh_entry_cnt)
    ]

    def extract_padding(self, s):
        return "", s


class L2NeighDevice(IEEE1905_TLV):
    name = "L2 Neighbor Device TLV"
    fields_desc = [
        XByteField("type", 0x1E),
        XShortField("len", None),
        FieldLenField("iface_entry_cnt", None, fmt='B', count_of="iface_entry_list"),
        PacketListField("iface_entry_list", None, L2NeighDevice_IfaceEntry,
                        count_from=lambda p:p.iface_entry_cnt)
    ]


