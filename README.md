# ixpmine

Know thy neighbor's MAC addresses

Copyright (C) 2016  Simon Leinen  <simon.leinen@gmail.com>

## The Problem

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

## Usage

The script currently doesn't take any arguments.  The header comment
at the top of the script explains how to generate the necessary input
files.  The bottom of the script contains subroutine calls to generate
MAC-to-AS mapping files for various IXPs.  Adapt these commands to
your local needs and run the script without arguments.

## Contributions

If you're interested in running this script on your network, please
let me know.  I'm willing to make the script more generally and
readily useful to others.  For this I need to know more about how
others might use it.

Of course bug reports - with or without fixes - and other code
contributions are welcome.  If you're familiar with GitHub, feel free
to fork the repo and send Pull Requests.  If not, just send code in
any form.

## License

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

## Author

Simon Leinen  <simon.leinen@gmail.com>
