#!/usr/bin/perl -w
##
## Collect MAC-address to AS number mappings from ARP/ND caches and
## lists of peers at exchange points.
##
## To create the input files:
##
##   get_nd () { snmptable -Ci -Cb -v 2c -c "$COMMUNITY" "$1" ipNetToPhysicalTable > "$1".np; }
##   get_arp () { snmptable -Cb -v 2c -c "$COMMUNITY" "$1" ipNetToMediaTable > "$1".arp; }
##   fping -g IXP_NET_FIRST_ADDRESS IXP_NET_LAST_ADDRESS # to fill ARP cache
##   for router in ...; do get_nd $router; get_arp $router; done
##
##   curl https://my.ams-ix.net/api/v1/members.tsv > amsix.tsv
##   curl https://www.swissix.ch/ss/api.php/getParticipantList/Y > swissix.json
##   curl http://cixp.web.cern.ch/technical/peering > cixp.html (NOT YET SUPPORTED)
##   clogin -c "show ip bgp summary" $router > $router-bgpsum.txt
##
## The script generates a few files with MAC-to-AS mappings, in the
## form of lines of the form AS-MAC, e.g.
##
##   123-01:23:45:67:89
##   456-ab:cd:ef:01:23
##   ...
##
use warnings;
use strict;
use JSON::PP;

sub unquote ($ ) {
    my ($q) = @_;
    die "Junk in $q" if $q =~ /\\/;
    return $1 if $q =~ /^"(.*)"$/;
    die "Malformed quotes in $q";
}

sub canon_ipv6_addr($ ) {
    my ($ip) = @_;
    my ($x);
    $ip = join ('', map { $_ eq '' ? '@' : sprintf("%04x", hex($_)); } split(':', $ip));
    $x = '0' x (33-length $ip), $ip =~ s/@/$x/e if length $ip < 32;
    return $ip;
}

sub process_arp_file($ ) {
    my ($arp_file) = @_;
    my ($ipv4_to_mac, $mac_to_ipv4);
    open ARP, $arp_file or die "Cannot open ARP file $arp_file: $!";
    $_ = <ARP>;
    die "ARP file must start with \"SNMP table: IP-MIB::ipNetToMediaTable\", not $_"
	unless /^SNMP table: IP-MIB::ipNetToMediaTable$/;
    $_ = <ARP>;
    die "ARP file must start with \"SNMP table: IP-MIB::ipNetToMediaTable\" followed by an empty line, not $_"
	unless /^$/;
    $_ = <ARP>;
    die "ARP file should have a header of IfIndex       PhysAddress     NetAddress    Type, not $_"
	unless /^\s+IfIndex\s+PhysAddress\s+NetAddress\s+Type$/;
    while (<ARP>) {
	my ($ifIndex, $mac, $ipv4);
	next if /^\s+\?\s+\?\s+\?\s+dynamic$/;
	die "Malformed ARP table line $_"
	    unless (($ifIndex, $mac, $ipv4)
		    = /^\s*(\d+)\s+(\S+)\s+(\S+)\s+(static|dynamic)$/);
	$mac = join(':',map { sprintf("%02x", hex($_)) } split(':', $mac));
	if (defined $ipv4_to_mac->{$ipv4}) {
	    if ($ipv4_to_mac->{$ipv4} ne $mac) {
		warn "IPv4 address $ipv4 already maps to ".$ipv4_to_mac->{$ipv4}.", overwriting with $mac";
	    }
	}
	$ipv4_to_mac->{$ipv4} = $mac;

	$mac_to_ipv4->{$mac} = [] unless defined $mac_to_ipv4->{$mac};
	push @{$mac_to_ipv4->{$mac}}, $ipv4;
    }
    close ARP or die "Error closing ARP file $arp_file: $!";
    return ($ipv4_to_mac, $mac_to_ipv4);
}

sub process_nd_file($ ) {
    my ($nd_file) = @_;
    my ($ipv6_to_mac, $mac_to_ipv6);
    open ND, $nd_file or die "Cannot open ND file $nd_file: $!";
    $_ = <ND>;
    die "ND file must start with \"SNMP table: IP-MIB::ipNetToPhysicalTable\", not $_"
	unless /^SNMP table: IP-MIB::ipNetToPhysicalTable$/;
    $_ = <ND>;
    die "ND file must start with \"SNMP table: IP-MIB::ipNetToPhysicalTable\" followed by an empty line, not $_"
	unless /^$/;
    $_ = <ND>;
    die "ND file should have a header of index       PhysAddress     LastUpdated    Type     State RowStatus, not $_"
	unless /^\s+index\s+PhysAddress\s+LastUpdated\s+Type\s+State\s+RowStatus$/;
    while (<ND>) {
	my ($ifIndex, $mac, $ipv6, $last_updated, $type, $state, $row_status);
	die "Malformed ND table line $_"
	    unless (($ifIndex, $ipv6, $mac, $last_updated, $type, $state, $row_status)
		    = /^\s*(\d+)\.ipv6\."(.*)"\s+(\S*)\s+(\S+)\s+(static|dynamic|[?])\s+(reachable|stale|delay|probe|[?])\s+(active)\s*$/);
	$mac = join(':',map { sprintf("%02x", hex($_)) } split(':', $mac));
	$ipv6 = join('', map { sprintf("%02x", hex($_)) } split(':', $ipv6));
	if (defined $ipv6_to_mac->{$ipv6}) {
	    if ($ipv6_to_mac->{$ipv6} ne $mac) {
		warn "Ipv6 address $ipv6 already maps to ".$ipv6_to_mac->{$ipv6}.", overwriting with $mac";
	    }
	}
	$ipv6_to_mac->{$ipv6} = $mac;

	$mac_to_ipv6->{$mac} = [] unless defined $mac_to_ipv6->{$mac};
	push @{$mac_to_ipv6->{$mac}}, $ipv6;
    }
    close ND or die "Error closing ND file $nd_file: $!";
    return ($ipv6_to_mac, $mac_to_ipv6);
}

sub output_mac_as_table($$$$$ ) {
    my ($out_file, $mac_to_ipv4, $ipv4_to_as, $mac_to_ipv6, $ipv6_to_as) = @_;
    my (%mac_to_as);
    my %all_macs = ();

    foreach my $mac (keys %{$mac_to_ipv4}) { ++$all_macs{$mac}; }
    foreach my $mac (keys %{$mac_to_ipv6}) { ++$all_macs{$mac}; }

    foreach my $mac (keys %all_macs) {
	my $guess_as;
	foreach my $ipv4 (@{$mac_to_ipv4->{$mac}}) {
	    if (exists $ipv4_to_as->{$ipv4}) {
		if (defined $guess_as and $guess_as != $ipv4_to_as->{$ipv4}) {
		    warn "$mac maps (via $ipv4) to ".$ipv4_to_as->{$ipv4}.", but also $guess_as";
		}
		$guess_as = $ipv4_to_as->{$ipv4};
	    }
	}
	foreach my $ipv6 (@{$mac_to_ipv6->{$mac}}) {
	    if (exists $ipv6_to_as->{$ipv6}) {
		if (defined $guess_as and $guess_as != $ipv6_to_as->{$ipv6}) {
		    warn "$mac maps (via $ipv6) to ".$ipv6_to_as->{$ipv6}.", but also $guess_as";
		}
		$guess_as = $ipv6_to_as->{$ipv6};
	    }
	}
	if (defined $guess_as) {
	    $mac_to_as{$mac} = $guess_as;
	}
    }

    open OUT, ">$out_file" or die "Cannot create output file $out_file: $!";
    foreach my $mac (sort { $mac_to_as{$a} <=> $mac_to_as{$b} } keys %mac_to_as) {
	print OUT $mac_to_as{$mac}.'-'.$mac."\n";
    }
    close OUT or die "Error closing output file $out_file: $!";
}

sub parse_amsix_file($ ) {
    my ($amsix_tsv_file) = @_;
    my ($header, @heads, %field_index, $i, $as_index, $ipv4_index, $ipv6_index);
    my ($ipv4_to_as, $ipv6_to_as);

    open AMSIX_TSV, $amsix_tsv_file or die "Cannot open file $amsix_tsv_file: $!";
    $header = <AMSIX_TSV>;
    die unless $header;
    chomp $header;
    @heads = map { unquote $_ } split(/\t/, $header);
    $i = 0; $field_index{$_} = $i++ for (@heads);
    $as_index = $field_index{'AS number'} || die;
    $ipv4_index = $field_index{'ISP (v4)'} || die;
    $ipv6_index = $field_index{'ISP (v6)'} || die;
    # print join (',',@heads), "\n";

    while (<AMSIX_TSV>) {
	chomp;
	#print $_;
	s/^"(.*)"$/$1/;
	my @fields = split(/"\t"/, $_);
	my ($as, $ipv4, $ipv6) =
	    ($fields[$as_index], $fields[$ipv4_index], $fields[$ipv6_index]);
	$ipv4 =~ s@/.*@@;
	$ipv6 =~ s@/.*@@;
	$ipv6 = canon_ipv6_addr($ipv6);
	$ipv4_to_as->{$ipv4} = $as;
	$ipv4_to_as->{$ipv6} = $as;
	# print "$as $ipv4 $ipv6\n";
	# print join (',',@fields), "\n";
    }
    close AMSIX_TSV or die "Error closing file $amsix_tsv_file: $!";
    return ($ipv4_to_as, $ipv6_to_as);
}

sub parse_swissix_file($ ) {
    my ($swissix_json_file) = @_;
    my ($header, @heads, %field_index, $i, $as_index, $ipv4_index, $ipv6_index);
    my ($ipv4_to_as, $ipv6_to_as);

    open SWISSIX_JSON, $swissix_json_file or die "Cannot open file $swissix_json_file: $!";
    local $/ = undef;
    my $glob = <SWISSIX_JSON>;
    close SWISSIX_JSON or die "Error closing file $swissix_json_file: $!";
    my $swissix = decode_json($glob);
    my $json = JSON::PP->new->ascii->pretty->allow_nonref;
    die "Malformed JSON" unless $swissix->{'status'} eq 'OK';
    foreach my $as (@{$swissix->{'data'}}) {
	my $asn = $as->{'ASNumber'};
	next if $asn eq '';
	my $ipv4 = $as->{'IPv4'};
	my $ipv6 = $as->{'IPv6'};
	$ipv6 = canon_ipv6_addr($ipv6);
	$ipv4_to_as->{$ipv4} = $asn unless $ipv4 eq '';
	$ipv6_to_as->{$ipv6} = $asn unless $ipv6 eq '';
    }
    return ($ipv4_to_as, $ipv6_to_as);
}

sub parse_bgpsum_file($ ) {
    my ($file) = @_;
    my ($ipv4_to_as, $ipv6_to_as);

    open (FILE, $file) or die "Cannot open file $file: $!";
    while (<FILE>) {
	if (/^([0-9.]+)\s+4\s+(\d+)\s+.*/) {
	    my ($ipv4, $asn) = ($1, $2);
	    $ipv4_to_as->{$ipv4} = $asn unless $ipv4 eq '';
	}
    }
    close FILE or die "Error closing file $file: $!";
    return ($ipv4_to_as, $ipv6_to_as);
}

sub process_amsix_file($$$$) {
    my ($out_file, $amsix_tsv_file, $arp_file, $nd_file) = @_;

    my ($ipv4_to_mac, $mac_to_ipv4) = process_arp_file($arp_file);
    my ($ipv6_to_mac, $mac_to_ipv6) = process_nd_file($nd_file);

    my ($ipv4_to_as, $ipv6_to_as) = parse_amsix_file($amsix_tsv_file);

    output_mac_as_table($out_file, $mac_to_ipv4, $ipv4_to_as, $mac_to_ipv6, $ipv6_to_as);
}

sub process_swissix_file($$$$) {
    my ($out_file, $swissix_json_file, $arp_file, $nd_file) = @_;

    my ($ipv4_to_mac, $mac_to_ipv4) = process_arp_file($arp_file);
    my ($ipv6_to_mac, $mac_to_ipv6) = process_nd_file($nd_file);

    my ($ipv4_to_as, $ipv6_to_as) = parse_swissix_file($swissix_json_file);

    output_mac_as_table($out_file, $mac_to_ipv4, $ipv4_to_as, $mac_to_ipv6, $ipv6_to_as);
}

sub process_bgp_file($$$$) {
    my ($out_file, $ix_file, $arp_file, $nd_file) = @_;

    my ($ipv4_to_mac, $mac_to_ipv4) = process_arp_file($arp_file);
    my ($ipv6_to_mac, $mac_to_ipv6) = process_nd_file($nd_file);

    my ($ipv4_to_as, $ipv6_to_as) = parse_bgpsum_file($ix_file);

    output_mac_as_table($out_file, $mac_to_ipv4, $ipv4_to_as, $mac_to_ipv6, $ipv6_to_as);
}

process_amsix_file    ('amsix-as-mac.txt',   'amsix.tsv',       'ce3.arp', 'ce3.np');
process_swissix_file  ('swissix-as-mac.txt', 'swissix.json',    'ix2.arp', 'ix2.np');
process_bgp_file      ('tix-as-mac.txt',     'tix-bgpsum.txt',  'ix1.arp', 'ix1.np');
process_bgp_file      ('cixp-as-mac.txt',    'cixp-bgpsum.txt', 'ce3.arp', 'ce3.np');
1;
