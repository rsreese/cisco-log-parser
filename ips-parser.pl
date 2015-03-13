#!/usr/bin/perl
use strict;
use warnings;
#
# ips-parser.pl - simple parsing of Cisco syslog ACL message
#
# Copyright (C) 2008 Stephen Reese
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# http://www.rsreese.com or http://code.google.com/p/cisco-log-parser/
# Original script that doesn't seem to work may be found here: http://www.oreillynet.com/pub/a/network/excerpt/CISCO_Chap1/index.html?page=2#example19-1
#
# Author: Stephen Reese <http://www.rsreese.com>
#	  Jacksonville, FL USA
#
# Usage: ./ips-parser.pl
#
# 2008-09-26:0.1 Initial Release
# 
# Set behaviour
my $log='/var/log/cisco.log';
my $ntop=10;

my $sig = $ARGV[ 0 ] || '.*';
   
open LOG, '<', $log or die "Cannot open '$log' $!";

my $re = qr/
 IPS-4-SIGNATURE:\s+    # Initial Pattern
 Sig:\s*(\d+)\s+     # $1
 Subsig:\s*(\d+)\s+  # $2
 Sev:\s*(\d+)\s+     # $3
 (.*?)\s+            # $4
 \[
   ([\d.]+):(\d+)\s*->\s*([\d.]+):(\d+)     # $5:$6 -> $7:$8
 \]
/x;

my ( %mess, %quad, %port );

while (<LOG>) {
 next unless /$re/;
 my $summ = sprintf '%-9s %-s', $1, $4;
 my $conn = sprintf '%-16s %-5s -> %-16s %-5s', $5, ,$6, $7, $8;
 my $port = sprintf '%-6s %-6s %-6s', $1, $2, $3;
 $mess{$summ}++;
 $quad{$conn}++;
 $port{$port}++;
}

my $n;

print "\nMost Frequent IPS Messages:\n";
print "Number Signature Message\n";
foreach my $i ( sort { $mess{$b} <=> $mess{$a} } keys %mess) {
 if ($n++ >= $ntop) { last };
 printf ("%5s: %s\n", $mess{$i},$i);
}

$n=0;

print "\nConnection Summary:\n";
print "Number Source                    Destination\n";
foreach my $i ( sort { $quad{$b} <=> $quad{$a} } keys %quad) {
 if ($n++ >= $ntop) { last };
 printf ("%5s: %s\n", $quad{$i},$i);
}

$n=0;

print "\nSignature Information:\n";
print "Number Sig  Subsig Severity\n";
foreach my $i ( sort { $port{$b} <=> $port{$a} } keys %port) {
 if ($n++ >= $ntop) { last };
 printf ("%5s: %s\n", $port{$i},$i);
}
