#!/usr/bin/perl

use strict;
my %dirs;

#for (`for i in * ; do if [ -d "\"\${i}\"" ] ; then if [ ! -L "\"\${i}\"" ] ; then du -s "\"\$i\"" 2>/dev/null; fi ; fi ; done`) {
for (`export IFS=\$'\n'; for i in \$(find . -maxdepth 1 -type d); do du -s \"\$i\"; done`) {
  chomp;
  #next if not m/^([^\s]*?)\s*?([^\s]*)$/;
  next if not m/^([\d]*)\s*?(.*)$/;
  $dirs{$2} = $1;
}


my @sorted = sort { $dirs{$a} <=> $dirs{$b} } keys %dirs;

foreach ( @sorted ) {
  $dirs{$_} = sprintf("% 14d", $dirs{$_});
  print $dirs{$_}."\t$_\n";
}