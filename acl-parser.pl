#!/usr/bin/perl
use warnings;
use strict;
#
# acl-parse.pl - simple parsing of Cisco syslog ACL message
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
# Usage: ./acl-parse.pl
#
# 2008-09-23:0.1 Initial Release
# 2008-09-24:0.2 Minor code tweeks
# 
# Set behaviour
my $log='/var/log/cisco.log';
my $ntop=10;

my $acl = $ARGV[ 0 ] || '.*';
   
open LOG, '<', $log or die "Cannot open '$log' $!";

my ( %srca, %quad, %port );

while (<LOG>) {
next unless /IPACCESSLOGP: list $acl denied ([tcpud]+) ([0-9.]+)\([0-9]+\)\s*->\s*([0-9.]+)\(([0-9]+)\), ([0-9]+) /;
   $srca{ $2 } += $5;
   $quad{ sprintf '%16s  -> %16s  %3s port %-6s', $2, $3, $1, $4 } += $5;
   $port{ sprintf '%3s port %-6s', $1, $4 } += $5;
}

my $n;

print "Connection Summary:\n";
foreach my $i (sort { $quad{$b} <=> $quad{$a} } keys %quad) {
   if ($n++ >= $ntop) { last };
   printf ("%6s:%s\n", $quad{$i},$i);
}
$n=0;

print "\nDestination Port Summary:\n";
foreach my $i ( sort { $port{$b} <=> $port{$a} } keys %port) {
   if ($n++ >= $ntop) { last };
   printf ("%6s: %s\n", $port{$i},$i);
}
$n=0;

print "\nSource Address Summary:\n";
foreach my $i ( sort { $srca{$b} <=> $srca{$a} } keys %srca) {
   if ($n++ >= $ntop) { last };
   printf ("%6s: %s\n", $srca{$i},$i);
}
