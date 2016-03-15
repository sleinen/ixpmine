# ixpmine

Know thy neighbor's MAC addresses

## The problem

Your network connects to Internet Exchange Points (IXPs) to
interconnect with other networks.  These peerings may be explicitly
configured, or indirect through route servers.

Traffic from and to many peers is exchanged over a single interface,
typically an Ethernet.  For accounting purposes, it can be useful to
map Layer 2 (MAC) addresses to peers.

The code here helps generate such mappings, based on

* Layer 3 to Layer 2 mapping (ARP/IPv6 ND) information from your
  routers.  This can be extracted from the routers using SNMP.
* Information about Layer 3 (IPv4/IPv6) addresses and AS numbers of
  the peers on the exchange.  Several IXPs publish this on the Web,
  some even in relatively parseable forms.  Where such information is
  not available, the script can also use the output of `show ip bgp
  summary` from a Cisco router.

## Requirements

This code requires

* Perl
* Net-SNMP
* Standard MIB files installed for Net-SNMP, in particular IP-MIB

## Author

Simon Leinen  <simon.leinen@gmail.com>
