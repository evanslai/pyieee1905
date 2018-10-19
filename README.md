# pyieee1905
IEEE1905 implementation using Python and Scapy

# Installation

Run `python3 setup.py install` to install `pyieee1905`.

# Example

To generate the Topology Notification message and send it via the eth0 interface:

```
from scapy.all import *
from pyieee1905.multiap_tlv import *
from pyieee1905.multiap_msg import *
import os
import sys

# Setup MultiAP message
msg = MultiAP_Message()
msg.msg_type = "TOPOLOGY_NOTIFICATION_MESSAGE"
msg.msg_id = int.from_bytes(os.urandom(2), sys.byteorder)
msg.flag_last_frag_ind = 1

# Setup TLV
tlv = ClientAssocEvent()
tlv.mac = os.urandom(6)
tlv.bssid = os.urandom(6)
tlv.assoc_flag = 1

# Generate the packet
p = Ether(type=0x893a, dst=IEEE1905_MCAST)/msg/tlv/b"\x00\x00\x00"

# Debug purpose
#p.show2()

# Send the packet
sendp(p, iface="eth0")
```


