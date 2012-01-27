# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl BadTraffic.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test::More tests => 5;
BEGIN { use_ok('BadTraffic') };
BEGIN { use_ok('DBI') };
BEGIN { use_ok('Socket') };
BEGIN { use_ok('Net::CIDR::Lite') };

ok( my $bt = BadTraffic->new(), "constructor works" );
#########################

# Insert your test code below, the Test::More module is use()ed here so read
# its man page ( perldoc Test::More ) for help writing this test script.
