#!/usr/bin/perl

sub prhex {
    my $x,$v = shift;
    print pack("H*",$v);
}

if ($ARGV[0] eq "-h") {
   prhex ($ARGV[1]);
   exit(0);
}

while (<>) {
   chop;
   prhex($_);
   print("\n");
}

