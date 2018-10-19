from pyieee1905.ieee1905_tlv import IEEE1905_TLV
from scapy.packet import Packet, bind_layers
from scapy.fields import BitField, XByteField, XShortField, XShortEnumField
from scapy.layers.l2 import Ether



IEEE1905_MCAST = "01:80:c2:00:00:13"


ieee1905_msg_type = {
    0x0000:"TOPOLOGY_DISCOVERY_MESSAGE",
    0x0001:"TOPOLOGY_NOTIFICATION_MESSAGE",
    0x0002:"TOPOLOGY_QUERY_MESSAGE",
    0x0003:"TOPOLOGY_RESPONSE_MESSAGE",
    0x0004:"VENDOR_SPECIFIC_MESSAGE",
    0x0005:"LINK_METRIC_QUERY_MESSAGE",
    0x0006:"LINK_METRIC_RESPONSE_MESSAGE",
    0x0007:"AP_AUTOCONFIGURATION_SEARCH_MESSAGE",
    0x0008:"AP_AUTOCONFIGURATION_RESPONSE_MESSAGE",
    0x0009:"AP_AUTOCONFIGURATION_WSC_MESSAGE",
    0x000A:"AP_AUTOCONFIGURATION_RENEW_MESSAGE",
    0x000B:"IEEE1905_PUSH_BUTTON_EVENT_NOTIFICATION_MESSAGE",
    0x000C:"IEEE1905_PUSH_BUTTON_JOIN_NOTIFICATION_MESSAGE",
    0x000D:"HIGHER_LAYER_QUERY_MESSAGE",
    0x000E:"HIGHER_LAYER_RESPONSE_MESSAGE",
    0x000F:"INTERFACE_POWER_CHANGE_REQUEST_MESSAGE",
    0x0010:"INTERFACE_POWER_CHANGE_RESPONSE_MESSAGE",
    0x0011:"GENERIC_PHY_QUERY_MESSAGE",
    0x0012:"GENERIC_PHY_RESPONSE_MESSAGE",
    0x8000:"IEEE1905_ACK_MESSAGE",
    0x8001:"AP_CAPABILITY_QUERY_MESSAGE",
    0x8002:"AP_CAPABILITY_REPORT_MESSAGE",
    0x8003:"MULTI_AP_POLICY_CONFIG_REQUEST_MESSAGE",
    0x8004:"CHANNEL_PREFERENCE_QUERY_MESSAGE",
    0x8005:"CHANNEL_PREFERENCE_REPORT_MESSAGE",
    0x8006:"CHANNEL_SELECTION_REQUEST_MESSAGE",
    0x8007:"CHANNEL_SELECTION_RESPONSE_MESSAGE",
    0x8008:"OPERATING_CHANNEL_REPORT_MESSAGE",
    0x8009:"CLIENT_CAPABILITIES_QUERY_MESSAGE",
    0x800A:"CLIENT_CAPABILITIES_REPORT_MESSAGE",
    0x800B:"AP_METRICS_QUERY_MESSAGE",
    0x800C:"AP_METRICS_RESPONSE_MESSAGE",
    0x800D:"ASSOCIATED_STA_LINK_METRICS_QUERY_MESSAGE",
    0x800E:"ASSOCIATED_STA_LINK_METRICS_RESPONSE_MESSAGE",
    0x800F:"UNASSOCIATED_STA_LINK_METRICS_QUERY_MESSAGE",
    0x8010:"UNASSOCIATED_STA_LINK_METRICS_RESPONSE_MESSAGE",
    0x8011:"BEACON_METRICS_QUERY_MESSAGE",
    0x8012:"BEACON_METRICS_REPONSE_METRICS",
    0x8013:"COMBINED_INFRASTRUCTURE_METRICS_MESSAGE",
    0x8014:"CLIENT_STEERING_REQUEST_MESSAGE",
    0x8015:"CLIENT_STEERING_BTM_REPORT_MESSAGE",
    0x8016:"CLIENT_ASSOCIATION_CONTROL_REQUEST_MESSAGE",
    0x8017:"STEERING_COMPLETED_MESSAGE",
    0x8018:"HIGHER_LAYER_DATA_MESSAGE",
    0x8019:"BACKHAUL_STEERING_REQUEST_MESSAGE",
    0x801A:"BACKHAUL_STEERING_RESPONSE_MESSAGE"
}

class MultiAP_Message(Packet):
    name = "IEEE 1905 MultiAP Message"
    fields_desc = [
        XByteField("msg_version", None),
        XByteField("msg_reserved", None),
        XShortEnumField("msg_type", None, ieee1905_msg_type),
        XShortField("msg_id", None),
        XByteField("frag_id", None),
        BitField("flag_last_frag_ind", 0, 1),
        BitField("flag_relay_ind", 0, 1),
        BitField("flag_reserved", 0, 6)
    ]


bind_layers(Ether, MultiAP_Message, type=0x893a)
bind_layers(MultiAP_Message, IEEE1905_TLV, )


