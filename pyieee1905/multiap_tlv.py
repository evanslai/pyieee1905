import struct
from scapy.packet import Packet
from scapy.fields import BitField, XByteField, XShortField, SignedByteField, MACField, \
        X3BytesField, IntField, XIntField, XLongField, ConditionalField, \
        StrLenField, FieldLenField, FieldListField, PacketListField, MultipleTypeField, \
        StrFixedLenField, ThreeBytesField, ByteField


from pyieee1905.ieee1905_tlv import IEEE1905_TLV


# Supported Service TLV (0x80)
class SupportedService(IEEE1905_TLV):
    name = "Supported Service TLV"
    fields_desc = [
        XByteField("type", 0x80),
        XShortField("len", None),
        FieldLenField("service_cnt", None, fmt='B', count_of="service_list"),
        FieldListField("service_list", None, XByteField("service_type", None),
                       count_from=lambda pkt:pkt.service_cnt)
    ]


# Searched Service TLV (0x81)
class SearchedService(IEEE1905_TLV):
    name = "Searched Service TLV"
    fields_desc = [
        XByteField("type", 0x81),
        XShortField("len", None),
        FieldLenField("service_cnt", None, fmt='B', count_of="service_list"),
        FieldListField("service_list", None, XByteField("service_type", None),
                       count_from=lambda p:p.service_cnt)
    ]


# AP Radio Identifier TLV (0x82)
class APRadioId(IEEE1905_TLV):
    name = "AP Radio Identifier TLV"
    fields_desc = [
        XByteField("type", 0x82),
        XShortField("len", None),
        MACField("radio_id", None)
    ]


# AP operational BSS TLV (0x83)
class APOpBSS_BSS(Packet):
    name = "BSS"
    fields_desc = [
        MACField("bssid", None),
        FieldLenField("ssid_len", None, fmt="B", length_of="ssid"),
        StrLenField("ssid", '', length_from=lambda p:p.ssid_len)
    ]

    def extract_padding(self, s):
        return "", s


class APOpBSS_Radio(Packet):
    name = "Radio"
    fields_desc = [
        MACField("radio_id", None),
        FieldLenField("bss_cnt", None, fmt='B', count_of="bss_list"),
        PacketListField("bss_list", None, APOpBSS_BSS, count_from=lambda p:p.bss_cnt)
    ]

    def extract_padding(self, s):
        return "", s


class APOpBSS(IEEE1905_TLV):
    name = "AP operational BSS TLV"
    fields_desc = [
        XByteField("type", 0x83),
        XShortField("len", None),
        FieldLenField("radio_cnt", None, fmt='B', count_of="radio_list"),
        PacketListField("radio_list", [], APOpBSS_Radio, count_from=lambda p:p.radio_cnt)
    ]


# Associated Clients TLV (0x84)
class AssocClients_Client(Packet):
    name = "Client"
    fields_desc = [
        MACField("mac", None),
        XShortField("uptime", None)
    ]

    def extract_padding(self, s):
        return "", s


class AssocClients_BSS(Packet):
    name = "BSS"
    fields_desc = [
        MACField("bssid", None),
        FieldLenField("assoc_sta_cnt", None, count_of="assoc_sta_list"),
        PacketListField("assoc_sta_list", None, AssocClients_Client,
                        count_from=lambda p:p.assoc_sta_cnt)
    ]

    def extract_padding(self, s):
        return "", s


class AssocClients(IEEE1905_TLV):
    name = "Associated Clients TLV"
    fields_desc = [
        XByteField("type", 0x84),
        XShortField("len", None),
        FieldLenField("bss_cnt", None, fmt='B', count_of="bss_list"),
        PacketListField("bss_list", None, AssocClients_BSS, count_from=lambda p:p.bss_cnt)
    ]


# AP Radio Basic Capabilities TLV (0x85)
class APRadioBasicCaps_OpClass(Packet):
    name = "Operating Class"
    fields_desc = [
        XByteField("op_class", None),
        SignedByteField("eirp", None),
        FieldLenField("nop_chnl_cnt", None, fmt='B', count_of="nop_chnl_list"),
        FieldListField("nop_chnl_list", None, XByteField("nop_chnl", None),
                       count_from=lambda p:p.nop_chnl_cnt)
    ]

    def extract_padding(self, s):
        return "", s


class APRadioBasicCaps(IEEE1905_TLV):
    name = "AP Radio Basic Capabilities TLV"
    fields_desc = [
        XByteField("type", 0x85),
        XShortField("len", None),
        MACField("radio_id", None),
        XByteField("max_bss_cnt", None),
        FieldLenField("op_class_cnt", None, fmt='B', count_of="op_class_list"),
        PacketListField("op_class_list", None, APRadioBasicCaps_OpClass,
                        count_from=lambda p:p.op_class_cnt)
    ]


# AP HT Capabilities TLV (0x86)
class APHTCaps(IEEE1905_TLV):
    name = "AP HT Capabilities TLV"
    fields_desc = [
        XByteField("type", 0x86),
        XShortField("len", None),
        MACField("radio_id", None),
        BitField("max_tx_streams", 0x00, 2),
        BitField("max_rx_streams", 0x00, 2),
        BitField("short_gi_20mhz_flag", 0, 1),
        BitField("short_gi_40mhz_flag", 0, 1),
        BitField("ht_40mhz_flag", 0, 1),
        BitField("reserved", 0, 1)
    ]


# AP VHT Capabilities (0x87)
class APVHTCaps(IEEE1905_TLV):
    name = "AP VHT Capabilities TLV"
    fields_desc = [
        XByteField("type", 0x87),
        XShortField("len", None),
        MACField("radio_id", None),
        XShortField("tx_mcs", None),
        XShortField("rx_mcs", None),
        BitField("max_tx_streams", 0, 3),
        BitField("max_rx_streams", 0, 3),
        BitField("short_gi_80mhz_flag", 0, 1),
        BitField("short_gi_160mhz_flag", 0, 1),
        BitField("vht_80mhz_plus_flag", 0, 1),
        BitField("vht_160mhz_flag", 0, 1),
        BitField("su_beamformer_flag", 0, 1),
        BitField("mu_beamformer_flag", 0, 1),
        BitField("reserved", 0, 4)
    ]


# AP VHT Capabilities TLV (0x88)
class APHECaps(IEEE1905_TLV):
    name = "AP VHT Capabilities TLV"
    fields_desc = [
        XByteField("type", 0x88),
        XShortField("len", None),
        MACField("radio_id", None),
        FieldLenField("he_mcs_len", None, fmt='B', count_of="he_mcs"),
        FieldListField("he_mcs", None, XByteField("byte", None), count_from=lambda p:p.he_mcs_len),
        BitField("max_tx_streams", 0, 3),
        BitField("max_rx_streams", 0, 3),
        BitField("he_80mhz_plus_flag", 0, 1),
        BitField("he_160mhz_flag", 0, 1),
        BitField("su_beamformer_cap_flag", 0, 1),
        BitField("mu_beamformer_cap_flag", 0, 1),
        BitField("ul_mu_mmio_cap_flag", 0, 1),
        BitField("ul_mu_mmio_ofdma_cap_flag", 0, 1),
        BitField("dl_mu_mmio_ofdma_cap_flag", 0, 1),
        BitField("ul_ofdma_cap_flag", 0, 1),
        BitField("dl_ofdma_cap_flag", 0, 1),
        BitField("reserved", 0, 1)
    ]


# Steering Policy TLV (0x89)
class StrgPolicy_Policy(Packet):
    name = "Policy"
    fields_desc = [
        MACField("radio_id", None),
        XByteField("strg_policy", None),
        XByteField("chnl_util_th", None),
        XByteField("rcpi_strg_th", None)
    ]

    def extract_padding(self, s):
        return "", s


class StrgPolicy(IEEE1905_TLV):
    name = "Steering Policy TLV"
    fields_desc = [
        XByteField("type", 0x89),
        XShortField("len", None),
        FieldLenField("strg_disallowed_cnt", None, fmt='B',
                      count_of="strg_disallowed_list"),
        FieldListField("strg_disallowed_list", None, MACField("sta_mac", None),
                       count_from=lambda p:p.strg_disallowed_cnt),
        FieldLenField("btm_strg_disallowed_cnt", None, fmt='B',
                      count_of="btm_strg_disallowed_list"),
        FieldListField("btm_strg_disallowed_list", None, MACField("sta_mac", None),
                       count_from=lambda p:p.btm_strg_disallowed_cnt),
        FieldLenField("policy_cnt", None, fmt='B', count_of="policy_list"),
        PacketListField("policy_list", None, StrgPolicy_Policy,
                        count_from=lambda p:p.policy_cnt)
    ]



# Metric Reporting Policy TLV (0x8A)
class MetricReportingPolicy_Policy(Packet):
    name = "Policy"
    fields_desc = [
        MACField("radio_id", None),
        XByteField("rcpi_th", None),
        XByteField("rcpi_hysteresis", None),
        XByteField("chnl_util_th", None),
        BitField("assoc_sta_traffic_stats_flag", None, 1),
        BitField("assoc_sta_link_metrics_flag", None, 1),
        BitField("reserved", None, 6)
    ]

    def extract_padding(self, s):
        return "", s


class MetricReportingPolicy(IEEE1905_TLV):
    name = "Metric Reporting Policy TLV"
    fields_desc = [
        XByteField("type", 0x8A),
        XShortField("len", None),
        XByteField("reporting_interval", None),
        FieldLenField("policy_cnt", None, fmt='B', count_of="policy_list"),
        PacketListField("policy_list", None, MetricReportingPolicy_Policy,
                        count_from=lambda p:p.policy_cnt)
    ]


# Channel Preference TLV (0x8B)
class ChnlPref_Setting(Packet):
    name = "Setting"
    fields_desc = [
        XByteField("op_class", None),
        FieldLenField("chnl_cnt", None, fmt='B', count_of="chnl_list"),
        FieldListField("chnl_list", None, XByteField("chnl", None), count_from=lambda p:p.chnl_cnt),
        BitField("chnl_pref", None, 4),
        BitField("reason_code", None, 4),
    ]

    def extract_padding(self, s):
        return "", s


class ChnlPref(IEEE1905_TLV):
    name = "Channel Preference TLV"
    fields_desc = [
        XByteField("type", 0x8B),
        XShortField("len", None),
        MACField("radio_id", None),
        FieldLenField("setting_cnt", None, fmt='B', count_of="setting_list"),
        PacketListField("setting_list", None, ChnlPref_Setting, count_from=lambda p:p.setting_cnt)
    ]


# Radio Operation Restriction TLV (0x8C)
class RadioOpRestr_Chnl(Packet):
    name = "Channel"
    fields_desc = [
        XByteField("chnl_num", None),
        XByteField("min_freq_sep", None)
    ]

    def extract_padding(self, s):
        return "", s


class RadioOpRestr_OpClass(Packet):
    name = "Operating Class"
    fields_desc = [
        XByteField("op_class", None),
        FieldLenField("chnl_cnt", None, fmt='B', count_of="chnl_list"),
        PacketListField("chnl_list", None, RadioOpRestr_Chnl, count_from=lambda p:p.chnl_cnt)
    ]

    def extract_padding(self, s):
        return "", s


class RadioOpRestr(IEEE1905_TLV):
    name = "Radio Operation Restriction TLV"
    fields_desc = [
        XByteField("type", 0x8C),
        XShortField("len", None),
        MACField("radio_id", None),
        FieldLenField("op_class_cnt", None, fmt='B', count_of="op_class_list"),
        PacketListField("op_class_list", None, RadioOpRestr_OpClass, count_from=lambda p:p.op_class_cnt)
    ]


# Transmit Power Limit TLV (0x8D)
class TxPowerLimit(IEEE1905_TLV):
    name = "Transmit Power Limit TLV"
    fields_desc = [
        XByteField("type", 0x8D),
        XShortField("len", None),
        MACField("radio_id", None),
        XByteField("eirp", None)
    ]


# Channel Selection Response TLV (0x8E)
class ChnlSelResponse(IEEE1905_TLV):
    name = "Channel Selection Response TLV"
    fields_desc = [
        XByteField("type", 0x8E),
        XShortField("len", None),
        MACField("radio_id", None),
        XByteField("status", None)
    ]


# Operating Channel Report TLV (0x8F)
class OpChnlReport_OpClass(Packet):
    name = "Operating Class"
    fields_desc = [
        XByteField("op_class", None),
        XByteField("curr_chnl_num", None)
    ]

    def extract_padding(self, s):
        return "", s


class OpChnlReport(IEEE1905_TLV):
    name = "Operating Channel Report TLV"
    fields_desc = [
        XByteField("type", 0x8F),
        XShortField("len", None),
        MACField("radio_id", None),
        FieldLenField("op_class_cnt", None, fmt='B', count_of="op_class_list"),
        PacketListField("op_class_list", None, OpChnlReport_OpClass, count_from=lambda p:p.op_class_cnt),
        XByteField("eirp", None)
    ]


# Client Info TLV (0x90)
class ClientInfo(IEEE1905_TLV):
    name = "Client Info TLV"
    fields_desc = [
        XByteField("type", 0x90),
        XShortField("len", None),
        MACField("bssid", None),
        MACField("sta_mac", None)
    ]


# Client Capability Report TLV (0x91)
# FIXME: Refine the assoc_req_frame field.
class ClientCapReport(IEEE1905_TLV):
    name = "Client Capability Report TLV"
    fields_desc = [
        XByteField("type", 0x91),
        XShortField("len", None),
        XByteField("status", None),
        StrLenField("assoc_req_frame", "", length_from=lambda p:p.len-1)
    ]


# Client Association Event TLV (0x92)
class ClientAssocEvent(IEEE1905_TLV):
    name = "Client Association Event TLV"
    fields_desc = [
        XByteField("type", 0x92),
        XShortField("len", None),
        MACField("mac", None),
        MACField("bssid", None),
        BitField("assoc_flag", None, 1),
        BitField("reserved", None, 7)
    ]


# AP Metric Query TLV (0x93)
class APMetricQuery(IEEE1905_TLV):
    name = "AP Metric Query TLV"
    fields_desc = [
        XByteField("type", 0x93),
        XShortField("len", None),
        FieldLenField("bssid_cnt", None, fmt='B', count_of="bssid_list"),
        FieldListField("bssid_list", None, MACField("bssid", None), count_from=lambda p:p.bssid_cnt)
    ]


# AP Metrics TLV (0x94)
# FIXME: Refine the esp_param_be, esp_param_bk, esp_param_vo and esp_param_vi fields.
class APMetrics(IEEE1905_TLV):
    name = "AP Metrics TLV"
    fields_desc = [
        XByteField("type", 0x94),
        XShortField("len", None),
        MACField("bssid", None),
        XByteField("chnl_util", None),
        XShortField("assoc_sta_cnt", None),
        BitField("ac_be_flag", 1, 1),
        BitField("ac_bk_flag", 0, 1),
        BitField("ac_vo_flag", 0, 1),
        BitField("ac_vi_flag", 0, 1),
        BitField("reserved", 0, 4),
        X3BytesField("esp_param_be", None),
        ConditionalField(X3BytesField("esp_param_bk", None), lambda pkt:pkt.ac_bk_flag==1),
        ConditionalField(X3BytesField("esp_param_vo", None), lambda pkt:pkt.ac_vo_flag==1),
        ConditionalField(X3BytesField("esp_param_vi", None), lambda pkt:pkt.ac_vi_flag==1)
    ]


# STA MAC Address Type TLV (0x95)
class STAMACAddrType(IEEE1905_TLV):
    name = "STA MAC Address Type TLV"
    fields_desc = [
        XByteField("type", 0x95),
        XShortField("len", None),
        MACField("mac", None)
    ]


# Associated STA Link Metrics TLV (0x96)
class AssocSTALinkMetrics_BSSID(Packet):
    name = "BSSID"
    fields_desc = [
        MACField("bssid", None),
        XIntField("time_delta", None),
        XIntField("downlink_rate", None),
        XIntField("uplink_rate", None),
        XByteField("uplink_rcpi", None)
    ]

    def extract_padding(self, s):
        return "", s


class AssocSTALinkMetrics(IEEE1905_TLV):
    name = "Associated STA Link Metrics TLV"
    fields_desc = [
        XByteField("type", 0x96),
        XShortField("len", None),
        MACField("mac", None),
        FieldLenField("bssid_cnt", None, fmt='B', count_of="bssid_list"),
        PacketListField("bssid_list", None, AssocSTALinkMetrics_BSSID, count_from=lambda p:p.bssid_cnt)
    ]


# Unassociated STA Link Metrics Query TLV (0x97)
class UnassocSTALinkMetricsQuery_Chnl(Packet):
    name = "Channel"
    fields_desc = [
        XByteField("chnl_num", None),
        FieldLenField("sta_cnt", None, fmt='B', count_of="sta_list"),
        FieldListField("sta_list", None, MACField("mac", None), count_from=lambda p:p.sta_cnt)
    ]

    def extract_padding(self, s):
        return "", s


class UnassocSTALinkMetricsQuery(IEEE1905_TLV):
    name = "Unassociated STA Link Metrics Query TLV"
    fields_desc = [
        XByteField("type", 0x97),
        XShortField("len", None),
        XByteField("op_class", None),
        FieldLenField("chnl_cnt", None, fmt='B', count_of="chnl_list"),
        PacketListField("chnl_list", [], UnassocSTALinkMetricsQuery_Chnl, count_from=lambda p:p.chnl_cnt)
    ]


# Unassociated STA Link Metrics Response TLV (0x98)
class UnassocSTALinkMetricsResponse_STA(Packet):
    name = "Unassociated STA"
    fields_desc = [
        MACField("mac", None),
        XByteField("chnl_num", None),
        XIntField("time_delta", None),
        XByteField("uplink_rcpi", None)
    ]

    def extract_padding(self, s):
        return "", s


class UnassocSTALinkMetricsResponse(IEEE1905_TLV):
    name = "Unassociated STA Link Metrics Response TLV"
    fields_desc = [
        XByteField("type", 0x98),
        XShortField("len", None),
        XByteField("op_class", None),
        FieldLenField("sta_cnt", None, fmt='B', count_of="sta_list"),
        PacketListField("sta_list", None, UnassocSTALinkMetricsResponse_STA,
                        count_from=lambda p:p.sta_cnt)
    ]


# Beacon Metrics Query TLV (0x99)
class BeaconMetricsQuery_ChnlReport(Packet):
    name = "Channel Report"
    fields_desc = [
        FieldLenField("len", None, fmt='B', length_of="chnl_list", adjust=lambda p,x:x+1),
        XByteField("op_class", None),
        FieldListField("chnl_list", None, XByteField("chnl", None), length_from=lambda p:p.len-1)
    ]

    def extract_padding(self, s):
        return "", s


class BeaconMetricsQuery(IEEE1905_TLV):
    name = "Beacon Metrics Query TLV"
    fields_desc = [
        XByteField("type", 0x99),
        XShortField("len", None),
        MACField("assoc_sta_mac", None),
        XByteField("op_class", None),
        XByteField("chnl_num", None),
        MACField("bssid", None),
        XByteField("detail", None),
        FieldLenField("ssid_len", None, fmt='B', length_of="ssid"),
        StrLenField("ssid", None, length_from=lambda p:p.ssid_len),

        MultipleTypeField(
            [
                (XByteField("chnl_report_cnt", 0),
                    lambda p:p.chnl_num!=255)
            ],
            FieldLenField("chnl_report_cnt", None, fmt='B', count_of="chnl_report_list")
        ),
        ConditionalField(PacketListField("chnl_report_list", None, BeaconMetricsQuery_ChnlReport, count_from=lambda p:p.chnl_report_cnt),
                         lambda p:p.chnl_num==255),

        FieldLenField("elt_cnt", None, fmt='B', count_of="elt_list"),
        FieldListField("elt_list", None, XByteField("elt_id", None), count_from=lambda p:p.elt_cnt)
    ]


# Beacon Metrics Response TLV (0x9A)
class Dot11SubElt(Packet):
    name = "IEEE 802.11 Subelement (General)"
    fields_desc = [
        XByteField("id", 0),
        FieldLenField("len", None, fmt='B', count_of="data"),
        FieldListField("data", None, XByteField("byte", None), count_from=lambda p:p.len)
    ]

    def extract_padding(self, s):
        return "", s


class Dot11EltMeasReport(Packet):
    name = "IEEE 802.11 Measurement Report Element"
    fields_desc = [
        XByteField("id", 39),
        XByteField("len", None),
        XByteField("op_class", None),
        XByteField("chnl_num", None),
        XLongField("meas_start_time", None),
        XShortField("meas_duration", None),
        XByteField("reported_frame_info", None),
        XByteField("rcpi", None),
        XByteField("rsni", None),
        MACField("bssid", None),
        XByteField("ant_id", None),
        XIntField("parent_tsf", None),
        PacketListField("sub_elt_list", [], Dot11SubElt, length_from=lambda p:p.len-26)
    ]

    def post_build(self, p, pay):
        if self.len is None:
            l = len(p) - 2
            p = p[:1] + struct.pack("!B", l) + p[2:]
        return p + pay

    def extract_padding(self, s):
        return "", s


class BeaconMetricsResponse(IEEE1905_TLV):
    name = "Beacon Metrics Response TLV"
    fields_desc = [
        XByteField("type", 0x9A),
        XShortField("len", None),
        MACField("assoc_sta_mac", None),
        XByteField("reserved", None),
        FieldLenField("meas_report_elt_cnt", None, fmt='B', count_of="meas_report_elt_list"),
        PacketListField("meas_report_elt_list", None, Dot11EltMeasReport,
                        count_from=lambda p:p.meas_report_elt_cnt)
    ]


# Steering Request TLV (0x9B)
class StrgRequest_TargetBSSID(Packet):
    name = "Target BSSID"
    fields_desc = [
        MACField("bssid", None),
        XByteField("op_class", None),
        XByteField("chnl_num", None)
    ]

    def extract_padding(self, s):
        return "", s


class StrgRequest(IEEE1905_TLV):
    name = "Steering Request TLV"
    fields_desc = [
        XByteField("type", 0x9B),
        XShortField("len", None),
        MACField("bssid", None),
        BitField("request_flag", 0, 1),
        BitField("btm_disassoc_imminent_flag", 0, 1),
        BitField("btm_abriged_flag", 0, 1),
        BitField("reserved", 0, 5),
        XShortField("strg_op_window", 0),
        XShortField("btm_disassoc_timer", 0),
        FieldLenField("sta_cnt", None, fmt='B', count_of="sta_list"),
        FieldListField("sta_list", None, MACField("mac", None), count_from=lambda p:p.sta_cnt),
        FieldLenField("target_bssid_cnt", None, fmt='B', count_of="target_bssid_list"),
        PacketListField("target_bssid_list", None, StrgRequest_TargetBSSID,
                        count_from=lambda p:p.target_bssid_cnt)
    ]


# Steering BTM Report TLV (0x9C)
class StrgBTMReport(IEEE1905_TLV):
    name = "Steering BTM Report TLV"
    fields_desc = [
        XByteField("type", 0x9C),
        XShortField("len", None),
        MACField("bssid", None),
        MACField("sta_mac", None),
        XByteField("btm_status", None),
        StrLenField("target_bssid", None, length_from=lambda p:p.len-13),
    ]


# Client Association Control Request TLV (0x9D)
class ClientAssocCtrlRequest(IEEE1905_TLV):
    name = "Client Association Control Request TLV"
    fields_desc = [
        XByteField("type", 0x9D),
        XShortField("len", None),
        MACField("bssid", None),
        XByteField("assoc_ctrl", 0x00),
        XShortField("validity_period", 0),
        FieldLenField("sta_cnt", None, fmt='B', count_of="sta_list"),
        FieldListField("sta_list", None, MACField("mac", None), count_from=lambda p:p.sta_cnt)
    ]


# Backhaul Steering Request TLV (0x9E)
class BhStrgRequest(IEEE1905_TLV):
    name = "Backhaul Steering Request TLV"
    fields_desc = [
        XByteField("type", 0x9E),
        XShortField("len", None),
        MACField("bh_sta_mac", None),
        MACField("target_bssid", None),
        XByteField("op_class", 0),
        XByteField("chnl_num", 0)
    ]


# Backhaul Steering Response TLV (0x9F)
class BhStrgResponse(IEEE1905_TLV):
    name = "Backhaul Steering Response TLV"
    fields_desc = [
        XByteField("type", 0x9F),
        XShortField("len", None),
        MACField("bh_sta_mac", None),
        MACField("target_bssid", None),
        XByteField("status", 0x00)
    ]


# Higher Layer Data TLV (0xA0)
class HigherLayerData(IEEE1905_TLV):
    name = "Higher Layer Data TLV"
    fields_desc = [
        XByteField("type", 0xA0),
        XShortField("len", None),
        XByteField("proto", 0x00),
        StrLenField("data", "", length_from=lambda pkt:pkt.len-1)
    ]


# AP Capability TLV (0xA1)
class APCapability(IEEE1905_TLV):
    name = "AP Capability TLV"
    fields_desc = [
        XByteField("type", 0xA1),
        XShortField("len", None),
        BitField("unassoc_sta_metrics_oper_flag", 0, 1),
        BitField("unassoc_sta_metrics_non_oper_flag", 0, 1),
        BitField("agent_init_steering", 0, 1),
        BitField("reserved", 0, 5)
    ]


# Associated STA Traffic Stats TLV (0xA2)
class AssocSTATrafficStats(IEEE1905_TLV):
    name = "Associated STA Traffic Stats TLV"
    fields_desc = [
        XByteField("type", 0xA2),
        XShortField("len", None),
        MACField("assoc_sta_mac", None),
        IntField("bytes_sent", 0),
        IntField("bytes_rcvd", 0),
        IntField("packets_sent", 0),
        IntField("packets_rcvd", 0),
        IntField("tx_pkt_errs", 0),
        IntField("rx_pkt_errs", 0),
        IntField("retrans_count", 0)
    ]


# Error Code TLV (0xA3)
class ErrorCode(IEEE1905_TLV):
    name = "Error Code TLV"
    fields_desc = [
        XByteField("type", 0xA3),
        XShortField("len", None),
        XByteField("error_code", None),
        MACField("sta_mac", None)
    ]


# Multi_AP Version TLV (0xB3)
class MultiAPVersion(IEEE1905_TLV):
    name = "Multi AP Version TLV"
    fields_desc = [
        XByteField("type", 0xB3),
        XShortField("len", None),
        XByteField("multi_ap_version", None),
    ]


# Associated STA Extended Link Metrics TLV (0xC8)
class AssocSTAExtendedLinkMetrics_BSSID(Packet):
    name = "BSSID"
    fields_desc = [
        MACField("bssid", None),
        XIntField("last_data_downlink_rate", None),
        XIntField("last_data_uplink_rate", None),
        XIntField("utilization_receive", None),
        XIntField("utilization_transmit", None)
    ]

    def extract_padding(self, s):
        return "", s

class AssociatedSTAExtendedLinkMetrics(IEEE1905_TLV):
    name = "Associated STA Extended Link Metrics"
    fields_desc = [
        XByteField("type", 0xC8),
        XShortField("len", None),
        MACField("sta_mac", None),
        FieldLenField("bssid_cnt", None, fmt='B', count_of="bssid_list"),
        PacketListField("bssid_list", None, AssocSTAExtendedLinkMetrics_BSSID, count_from=lambda p:p.bssid_cnt)
    ]


# AP Extended Metrics (0xC7)
# UC = Unicast, MC = Multicast, BC = Broadcast
class APExtendedMetrics(IEEE1905_TLV):
    name = "AP Extended Metrics"
    fields_desc = [
        XByteField("type", 0xC7),
        XShortField("len", None),
        MACField("bssid", None),
        IntField("uc_bytes_sent", 0),
        IntField("uc_bytes_rcvd", 0),
        IntField("mc_bytes_sent", 0),
        IntField("mc_bytes_rcvd", 0),
        IntField("bc_bytes_sent", 0),
        IntField("bc_bytes_rcvd", 0)
    ]


# AP Wi-Fi 6 Capabilities TLV (0xAA)
class APWiFi6Capabilities_Role(Packet):
    name = "Role"
    fields_desc = [
        BitField("agent_role", None, 2),
        BitField("he_160", None, 1),
        BitField("he_80plus80", None, 1),
        BitField("reserved", 0, 4),
        IntField("mcs_nss", None),
        ConditionalField(IntField("he_mcs_nss_160", None), lambda pkt:pkt.he_160==1),
        ConditionalField(IntField("he_mcs_nss_80plus80", None), lambda pkt:pkt.he_80plus80==1),
        BitField("su_beamformer", None, 1),
        BitField("su_beamformee", None, 1),
        BitField("mu_beamformer_staus", None, 1),
        BitField("beamformee_sts_less_80", None, 1),
        BitField("beamformee_sts_greater_80", None, 1),
        BitField("ul_mu_mimo", None, 1),
        BitField("ul_ofdma", None, 1),
        BitField("dl_ofdma", None, 1),
        BitField("max_dl_mu_mimo_tx", None, 4),
        BitField("max_ul_mu_mimo_rx", None, 4),
        XByteField("max_dl_ofdma_tx", 0),
        XByteField("max_ul_ofdma_rx", 0),
        BitField("rts", None, 1),
        BitField("mu_rts", None, 1),
        BitField("multi_bssid", None, 1),
        BitField("mu_edca", None, 1),
        BitField("twt_requester", None, 1),
        BitField("twt_responder", None, 1),
        BitField("spatial_reuse", None, 1),
        BitField("anticipated_channel_usage", None, 1),
    ]

    def extract_padding(self, s):
        return "", s


class APWiFi6Capabilities(IEEE1905_TLV):
    name = "AP Wi-Fi 6 Capabilities TLV"
    fields_desc = [
        XByteField("type", 0xAA),
        XShortField("len", None),
        MACField("radio_id", None),
        FieldLenField("role_cnt", None, fmt='B', count_of="role_list"),
        PacketListField("role_list", None, APWiFi6Capabilities_Role,
                        count_from=lambda p:p.role_cnt)
    ]

# CAC Capabilities TLV (0xB2)
class CACCapabilities_Class(Packet):
    name = "CAC Operating Class"
    fields_desc = [
        ByteField("operating_class", None),
        FieldLenField("channels_len", None, fmt='B', count_of="channels"),
        FieldListField("channels", None, ByteField("channel", None), count_from=lambda p:p.channels_len)
    ]

    def extract_padding(self, s):
        return "", s

class CACCapabilities_Type(Packet):
    name = "CAC Type"
    fields_desc = [
        XByteField("method", None),
        ThreeBytesField("duration", None),
        FieldLenField("class_cnt", None, fmt='B', count_of="class_list"),
        PacketListField("class_list", None, CACCapabilities_Class,
                count_from=lambda p:p.class_cnt)
    ]

    def extract_padding(self, s):
        return "", s

class CACCapabilities_Radio(Packet):
    name = "CAC Radio"
    fields_desc = [
        MACField("ruid", None),
        FieldLenField("type_cnt", None, fmt='B', count_of="type_list"),
        PacketListField("type_list", None, CACCapabilities_Type,
                count_from=lambda p:p.type_cnt)
    ]

    def extract_padding(self, s):
        return "", s

class CACCapabilities(IEEE1905_TLV):
    name = "CAC Capabilities TLV"
    fields_desc = [
        XByteField("type", 0xB2),
        XShortField("len", None),
        StrFixedLenField("country_code", None, length=2),
        FieldLenField("radio_cnt", None, fmt='B', count_of="radio_list"),
        PacketListField("radio_list", None, CACCapabilities_Radio,
                count_from=lambda p:p.radio_cnt)
    ]


# Channel Scan Capabilities TLV (0xA5)
class ChannelScanCapabilities_Class(Packet):
    name = "Channel Scan Operating Class"
    fields_desc = [
        ByteField("operating_class", None),
        FieldLenField("channels_len", None, fmt='B', count_of="channels"),
        FieldListField("channels", None, ByteField("channel", None), count_from=lambda p:p.channels_len)
    ]

    def extract_padding(self, s):
        return "", s

class ChannelScanCapabilities_Radio(Packet):
    name = "Channel Scan Radio"
    fields_desc = [
        MACField("ruid", None),
        BitField("on_boot_only", 0x00, 1),
        BitField("scan_impact", 0x00, 2),
        BitField("reserved", 0x00, 5),
        IntField("min_scan_interval", 0),
        FieldLenField("class_cnt", None, fmt='B', count_of="class_list"),
        PacketListField("class_list", None, ChannelScanCapabilities_Class,
                count_from=lambda p:p.class_cnt)
    ]

    def extract_padding(self, s):
        return "", s

class ChannelScanCapabilities(IEEE1905_TLV):
    name = "Channel Scan Capabilities TLV"
    fields_desc = [
        XByteField("type", 0xA5),
        XShortField("len", None),
        FieldLenField("radio_cnt", None, fmt='B', count_of="radio_list"),
        PacketListField("radio_list", None, ChannelScanCapabilities_Radio,
                count_from=lambda p:p.radio_cnt)
    ]

# Unsuccessful Association Policy TLV (0xC4)
class UnsuccessfulAssociationPolicy(IEEE1905_TLV):
    name = "Unsuccessful Association Policy TLV"
    fields_desc = [
        XByteField("type", 0xC4),
        XShortField("len", None),
        BitField("report_unsuccessful_associations_flag", 0, 1),
        BitField("reserved", 0, 7),
        IntField("maximum_reporting_rate", 0)
    ]

    def extract_padding(self, s):
        return "", s
