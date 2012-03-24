package BadTraffic;

use strict;
use warnings;
use DBI;
use Socket;
use Sys::Hostname;
use Net::CIDR::Lite;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration  use BadTraffic ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = (
    'all' => [
        qw(
          get_fw_blocks
          get_whitelist
          fw_block
          fw_unblock
          db_block
          db_unblock
          db_block_expire
          wl_add
          wl_remove
          )
    ]
);

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
  get_fw_blocks
  get_whitelist
  fw_block
  fw_unblock
  db_block
  db_unblock
  db_block_expire
  wl_add
  wl_remove
);

our $VERSION = 1.3.5;

=head1 NAME

BadTraffic - Perl extension for automatic firewall management.

=head1 SYNOPSIS

  my $bt = BadTraffic->new(
    DB_PASS => "<password>",
    DB_HOST => "<hostname>",
    DB_USER => "<username>",
    DB_NAME => "<dbname>"
  );
  $bt->fw_block("address");
  $bt->wl_add("address");

=head1 DESCRIPTION

BadTraffic reads and writes to a MySQL database and blocks traffic
according entries found.  It provides facilities for whitelisting
addresses or networks using CIDR formatting.


=head1 SEE ALSO

DBD::mysql and Net::CIDR::Lite are required used to greater or
lesser extent in this module.  There is also a heavy reliance on shelling
out to call /sbin/iptables and /sbin/ipfw to actually manipulate the
firewall blocks.

=head1 AUTHOR

Breandan Dezendorf, E<lt>bwdezend@ncsu.eduE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011-2012 by Breandan Dezendorf

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.10.0 or,
at your option, any later version of Perl 5 you may have available.

=cut

=head1 PUBLIC METHODS

Each public function/method is described here.
These are how you should interact with this module.

=cut

=head2 new

 Usage    : my $bt = new BadTraffic;
 Purpose  : Create a new BadTraffic object.
 Returns  : An object in the form of a blessed hash ref.
 Argument : hash or hashref of values to set:
               _DB_NAME => MySQL database name (default: badtraffic_db)
               _DB_USER => MySQL username (default: autoblock)
               _DB_PASS => MySQL password (default: none)
               _DB_HOST => MySQL hostname (default: localhost)
               _FW_TYPE => type of firewall (default: iptables)
 Comments : The only valid firewall types are "iptables", "ipfw", and "route"
 
=cut

sub new {
    my $class  = shift;
    my %params = @_;
    my $self   = {
        _DB_TYPE => shift,
        _DB_USER => shift,
        _DB_PASS => shift,
        _DB_HOST => shift,
        _DB_NAME => shift,
        _FW_TYPE => shift,
        _VERBOSE => shift,
        _DECOMPOSED_LIST => {},
    };


    unless ( $params{'DB_TYPE'} ) { $params{'DB_TYPE'} = "mysql" }
    unless ( $params{'DB_USER'} ) { $params{'DB_USER'} = "autoblock" }
    unless ( $params{'DB_PASS'} ) { $params{'DB_PASS'} = "mysql" }
    unless ( $params{'DB_HOST'} ) { $params{'DB_HOST'} = "localhost" }
    unless ( $params{'DB_NAME'} ) { $params{'DB_NAME'} = "bad_traffic" }
    unless ( $params{'VERBOSE'} ) { $params{'VERBOSE'} = "0" }
    
    $params{'USER_NAME'} = (getpwuid $>);
    
    if ( -x "/sbin/iptables" ) {
        $self->{'_FW_TYPE'} = "iptables";
    }
    elsif ( -x "/sbin/ipfw" ) {
        $self->{'_FW_TYPE'} = "ipfw";
    }
    elsif ( -x "/usr/sbin/route" ) {
        $self->{'_FW_TYPE'} = "route";
    }
    else {
        $self->{'_FW_TYPE'} = "unknown";
    }

    $self->{'_DB_TYPE'} = $params{'DB_TYPE'} if ( $params{'DB_TYPE'} );
    $self->{'_DB_USER'} = $params{'DB_USER'} if ( $params{'DB_USER'} );
    $self->{'_DB_PASS'} = $params{'DB_PASS'} if ( $params{'DB_PASS'} );
    $self->{'_DB_HOST'} = $params{'DB_HOST'} if ( $params{'DB_HOST'} );
    $self->{'_DB_HOST'} = $params{'DB_HOST'} if ( $params{'DB_HOST'} );
    $self->{'_DB_NAME'} = $params{'DB_NAME'} if ( $params{'DB_NAME'} );

    $self->{'_USER_NAME'} = $params{'USER_NAME'} if ( $params{'USER_NAME'} );

    $self->{'_VERBOSE'} = $params{'VERBOSE'};

    bless( $self, $class );
    return $self;
}

=head2 db_connect

 Usage    : $bt->db_connect;
 Purpose  : Opens a connection to the MySQL database.
 Returns  : A DBI database handle
 Argument : None
 Comments : The username, password, and database names are setup in new()
 
=cut

sub db_connect {
    my $self = shift;
    my $DBSERVER =
      "DBI:mysql:database=$self->{'_DB_NAME'};host=$self->{'_DB_HOST'}";
    my $dbh =
      DBI->connect( $DBSERVER, $self->{'_DB_USER'}, $self->{'_DB_PASS'} );
    if ( !$dbh ) {
        die("Unable to connect to MySQL database.\n");
    }
    $self->{_DB_TYPE} = "mysql";
    return $dbh;
}

=head2 get_whitelist

 Usage    : $bt->get_whitelist;
 Purpose  : Get a list of the currently whitelisted IP/CIDR addresses.
 Returns  : A Net::CIDR::Lite object containing the whitelisted CIDR address ranges
 Argument : None
 
=cut

sub get_whitelist {
    my $self    = shift;
    my $dbh     = $self->db_connect();
	my $cidr    = Net::CIDR::Lite->new();
    my %wl_hash = ();
    my $SQL =
"SELECT ipaddress FROM blocked_hosts WHERE whitelisted = '1' AND expired = '0'";

    my $sth = $dbh->prepare($SQL);
    $sth->execute();

    while ( my $r = $sth->fetchrow_hashref() ) {
        $wl_hash{ $r->{ipaddress} } = '1';
    }
    $self->{_WL_HASH} = %wl_hash;

    foreach my $k ( sort keys %wl_hash ) {
        if ( $k =~ m/\d+\/\d+/ ) {
            $cidr->add($k);
        }
        else {
            $cidr->add_ip($k);
        }
    }

    return $cidr;
}

=head2 wl_add

 Usage    : $bt->wl_add("address", "reason", "days");
 Purpose  : Add an IP or CIDR address to the whitelist.
 Returns  : Nothing
 Argument : 
   address => IP address or CIDR address as a string
   reason => textual description of the entry
   days => number of days the block will last
 Comment  : The first two arguments (address and reason) are required.  The days argument will be set to 3650 (10 years) unless an argument is given.
 
=cut

sub wl_add {
    my $self     = shift;

    my %args = @_;

    my $block    = undef;
    my $reason   = undef;
    my $days     = "1";
    my $category = undef;
    my $hostname = hostname();

    if ( $args{'address'} )  { $block    = $args{'address'} }
    if ( $args{'reason'} )   { $reason   = $args{'reason'} }
    if ( $args{'days'} )     { $days     = $args{'days'} }
    if ( $args{'category'} ) { $category = $args{'category'} }

    unless ($block) {
        warn "WARNING: An address to be whitelisted must be specified\n";
        return 1;
    }
    unless ($reason) {
        warn "WARNING: A reason to whitelist $block must be specified\n";
        return 1;
    }
    unless ( defined $days ) { $days = '1' }

    unless ( $block =~ m/\/\d/ ) {
        $block .= "/32";
    }
    
    my $dbh = $self->db_connect();

    my $SQL =
"INSERT INTO blocked_hosts (ipaddress, reason, category, date_blocked, date_expired, reporting_host, whitelisted) VALUES (?, ?, ?, NOW(), NOW()+Interval ? day, ?, '1')";

    print "Adding $block to whitelist\n" if ($self->{'_VERBOSE'});
    my $sth = $dbh->prepare($SQL);
    $sth->execute( "$block", "$reason", "$category", "$days", "$hostname" );

    my $fw_cidr = $self->get_fw_blocks();
    my $wl_cidr = $self->get_whitelist();

	my @fw_cidr_list = $fw_cidr->list;
	my @wl_cidr_list = $wl_cidr->list;


    for my $e (@fw_cidr_list) {
        if ( $wl_cidr->find($e) ) {
            print
"$e is blocked in the $self->{_FW_TYPE} firewall, but is whitelisted!\n";
            $self->fw_unblock($e);
        }
    }
}

=head2 wl_remove

 Usage    : $bt->wl_remove("address");
 Purpose  : Remove an IP or CIDR address from the whitelist.
 Returns  : Nothing
 Argument : 
   address => IP address or CIDR address as a string
 
=cut

sub wl_remove {
    my $self  = shift;
    my $block = shift;
    unless ( $block =~ m/\/\d/ ) {
        $block .= "/32";
    }
    unless ($block) {
        warn "WARNING: No IP address was specified to unblock\n";
        return 1;
    }
    print "Removing $block from whitelist\n" if ($self->{'_VERBOSE'});
    my $SQL = "UPDATE blocked_hosts SET expired = '1' WHERE ipaddress = ? AND whitelisted = '1'";
    my $dbh = $self->db_connect();
    my $sth = $dbh->prepare($SQL);
    $sth->execute("$block");
    $dbh->disconnect();
}


=head2 get_fw_blocks

 Usage    : $bt->get_fw_blocks();
 Purpose  : Get list of active blocks on the local system's firewall.
 Returns  : A hash containg the blocked CIDR/IP addresses
 
=cut

sub get_fw_blocks {
    my $self = shift;

	unless ($self->{_USER_NAME} eq "root"){
	  warn "Only root can change firewall rules\n";
	  return 1;
	}

    my %hash = ();
	my $cidr    = Net::CIDR::Lite->new();
    if ( $self->{_FW_TYPE} eq "iptables" ) {
        if ( !-x "/sbin/iptables" ) { return %hash }
        my @IPTABLES = `/sbin/iptables -L INPUT-AUTO -n -v | grep 0.0.0.0`;
        foreach my $line (@IPTABLES) {
            my @part = split( ' ', $line );
            $hash{ $part[7] } = '1';
        }
    }
    if ( $self->{_FW_TYPE} eq "ipfw" ) {
        if ( !-x "/sbin/ipfw" ) { return %hash }
        my $result   = `sysctl  -w net.inet.ip.fw.autoinc_step=5`;
        my @IPTABLES = `/sbin/ipfw list`;
        foreach my $line (@IPTABLES) {
            if ( $line =~ m/(\d+) deny ip from (.+) to me/ ) {
                my $addy = $2;
                unless ($addy  =~ m/\/\d/){ $addy  .= "/32" }
                $hash{$addy} = '$1';
            }

            if ( $line =~ m/(\d+) deny ip from me to (.+)/ ) {
                my $addy = $2;
                unless ($addy  =~ m/\/\d/){ $addy  .= "/32" }
                $hash{$addy} = '$1';
            }
        }
    }
    if ( $self->{_FW_TYPE} eq "route" ) {
        if ( !-x "/usr/bin/netstat" ) { return %hash }
        my @NETSTAT = `/usr/bin/netstat -rnv`;
        foreach my $line (@NETSTAT) {
            if ( $line =~ m/^127.0.0.1/ ) { next }
            if ( $line =~ m/^((\d+|\.)+) +((\d+|\.)+) +127.0.0.1/ ) {

                #print "converting $1 $3 into CIDR\n";
                my $tmp = $self->netmask2cidr( "$1", "$3" );
                $hash{$tmp} = '1';
            }
        }
    }

    foreach my $k ( sort keys %hash ) {
        if ( $k =~ m/\d+\/\d+/ ) {
            $cidr->add($k);
        }
        else {
            $cidr->add_ip($k);
        }
    }
    return $cidr;
}

=head2 fw_block

 Usage    : $bt->fw_block("address");
 Purpose  : Block an address on the local system's firewall.
 Arguments: The address or network to be blocked.
 Returns  : Nothing
 
=cut

sub fw_block {
    my $self   = shift;

	unless ($self->{_USER_NAME} eq "root"){
	  warn "Only root can change firewall rules\n";
	  return 1;
	}

    my $block  = shift;
    my $result = undef;
    my $cidr   = $self->get_whitelist();

    if ( $cidr->find($block) ) {
        warn
"WARNING: $block is whitelisted.  Aborting $self->{_FW_TYPE} block.\n";
        return 1;
    }

    unless ($block) {
        warn "WARNING: No IP address was specified to block\n";
        return 1;
    }

    if ( $self->{_FW_TYPE} eq "iptables" ) {
        if ( !-x "/sbin/iptables" ) { return 1 }
        $result = `/sbin/iptables -I INPUT-AUTO 1 -s $block -j DROP`;
        print "Blocking $block from iptables INPUT-AUTO chain\n" if ($self->{'_VERBOSE'});
        print "/sbin/iptables -I INPUT-AUTO 1 -s $block -j DROP resulted in:\n"
          if ($result && $self->{'_VERBOSE'});
        print $result if ($result && $self->{'_VERBOSE'});
        $result = `/sbin/iptables -I OUTPUT-AUTO 1 -d $block -j DROP`;
        print "Blocking $block from iptables OUTPUT-AUTO chain\n" if ($self->{'_VERBOSE'});
        print "/sbin/iptables -I OUTPUT-AUTO 1 -s $block -j DROP resulted in:\n"
          if ($result && $self->{'_VERBOSE'});
        print $result if ($result && $self->{'_VERBOSE'});
    }

    if ( $self->{_FW_TYPE} eq "ipfw" ) {
        if ( !-x "/sbin/ipfw" ) { return 1 }
        print "Blocking $block from ipfw\n" if ($self->{'_VERBOSE'});
        $result = `/sbin/ipfw add deny ip from $block to me`;
        print $result if ($result && $self->{'_VERBOSE'});
        $result = `/sbin/ipfw add deny ip from me to $block`;
        print $result if ($result && $self->{'_VERBOSE'});
    }

    if ( $self->{_FW_TYPE} eq "route" ) {
        if ( !-x "/usr/sbin/route" ) { return 1 }
        print "Blocking $block from route\n" if ($self->{'_VERBOSE'});
        $result = `/usr/sbin/route add $block 127.0.0.1 -blackhole`;
        print $result if ($result && $self->{'_VERBOSE'});
    }
}

=head2 fw_unblock

 Usage    : $bt->fw_unblock("address");
 Purpose  : Removed an active block on the local system's firewall.
 Arguments: The address or network to be unblocked.
 Returns  : Nothing
 
=cut

sub fw_unblock {
    my $self  = shift;

	unless ($self->{_USER_NAME} eq "root"){
	  warn "Only root can change firewall rules\n";
	  return 1;
	}
    my $block = shift;
    unless ($block) {
        warn "No IP address was specified to unblock\n";
        return 1;
    }

    if ( $self->{_FW_TYPE} eq "iptables" ) {
        if ( !-x "/sbin/iptables" ) { next }

		print "Unblocking $block from iptables\n" if ($self->{'_VERBOSE'});
        my $result = undef;
        $result = `/sbin/iptables -D INPUT-AUTO -s $block -j DROP`;
        print "/sbin/iptables -D INPUT-AUTO -s $block -j DROP resulted in:\n"
          if ($result && $self->{'_VERBOSE'});
        print $result if ($result && $self->{'_VERBOSE'});
        $result = `/sbin/iptables -D OUTPUT-AUTO -d $block -j DROP`;
        print "/sbin/iptables -D OUTPUT-AUTO -s $block -j DROP resulted in:\n"
          if ($result && $self->{'_VERBOSE'});
        print $result if ($result && $self->{'_VERBOSE'});
    }
    if ( $self->{_FW_TYPE} eq "ipfw" ) {
        if ($block =~ m/(.+)\/32/){$block = $1}
        my @result = `/sbin/ipfw list | grep $block`;
        foreach my $line (@result) {
            if ( $line =~ m/(\d+) deny ip from (.*)/ ) {
                print "Unblocking $2 from ipfw (rule #$1)\n" if ($self->{'_VERBOSE'});
                `/sbin/ipfw delete $1`;
            }
        }
    }

    if ( $self->{_FW_TYPE} eq "route" ) {

        my @tmp = $self->cidr2netmask($block);

        print
"Unblocking $block from route\n /usr/sbin/route delete $tmp[0] 127.0.0.1 $tmp[1]\n" if ($self->{'_VERBOSE'});
        my @result = `/usr/sbin/route delete $tmp[0] 127.0.0.1 $tmp[1]`;
    }

}

=head2 db_block

 Usage    : $bt->db_block("address", "reason", "days");
 Purpose  : Add a CIDR address to the blacklist.
 Returns  : Nothing
 Argument : 
   address => IP address or CIDR address as a string
   reason => textual description of the entry
   days => number of days the block will last
 Comment  : The first two arguments (address and reason) are required.  The days argument will be set to 1 day unless an argument is given.
 
=cut

sub db_block {
    my $self = shift;
    my %args = @_;

    my $block    = undef;
    my $reason   = undef;
    my $days     = "1";
    my $category = undef;
    my $hostname = hostname();

    if ( $args{'address'} )  { $block    = $args{'address'} }
    if ( $args{'reason'} )   { $reason   = $args{'reason'} }
    if ( $args{'days'} )     { $days     = $args{'days'} }
    if ( $args{'category'} ) { $category = $args{'category'} }

    unless ($block) {
        warn "WARNING: An address to be blocked must be specified\n";
        return 1;
    }
    unless ($reason) {
        warn "WARNING: A reason to block $block must be specified\n";
        return 1;
    }
    unless ( defined $days ) { $days = '1' }

    unless ( $block =~ m/\/\d/ ) {
        $block .= "/32";
    }

	print "Adding a databse block for $block\n" if ($self->{'_VERBOSE'});

    my $SQL =
"INSERT INTO blocked_hosts (ipaddress, reason, date_blocked, date_expired, reporting_host, category) VALUES (?, ?, NOW(), NOW()+Interval ? day, ?, ?)";
    my $dbh = $self->db_connect();
    my $sth = $dbh->prepare($SQL);
    $sth->execute( "$block", "$reason", "$days", "$hostname", "$category" );
    $dbh->disconnect();
}

=head2 db_unblock

 Usage    : $bt->db_block("address");
 Purpose  : Remove an IP or CIDR address from the blacklist.
 Returns  : Nothing
 Argument : 
   address => IP address or CIDR address as a string
 
=cut

sub db_unblock {
    my $self  = shift;
    my $block = shift;
    unless ( $block =~ m/\/\d/ ) {
        $block .= "/32";
    }
    unless ($block) {
        warn "WARNING: No IP address was specified to unblock\n";
        return 1;
    }
    
    print "Removing database blocks for $block\n" if ($self->{'_VERBOSE'});
    
    my $SQL = "UPDATE blocked_hosts SET expired = '1' WHERE ipaddress = ? AND whitelisted = '0'";
    my $dbh = $self->db_connect();
    my $sth = $dbh->prepare($SQL);
    $sth->execute("$block");
    $dbh->disconnect();
}

=head2 db_block_expire

 Usage    : $bt->db_block_expire();
 Purpose  : Sets expired flag for all entries that have expired.
 Returns  : Nothing
 Comments : This function is always called when get_db_blocks() is called.
 
=cut

sub db_block_expire {
    my $self = shift;
    my %hash = ();
    my $dbh  = $self->db_connect();
    print "Expiring old database blocks\n" if ($self->{'_VERBOSE'});
    my $SQL =
"UPDATE blocked_hosts SET expired = '1' WHERE date_expired < NOW() AND expired != '1'";
    my $sth = $dbh->prepare($SQL);
    $sth->execute();
    $dbh->disconnect();
}

=head2 get_db_blocks

 Usage    : $bt->get_db_blocks();
 Purpose  : Get list of active blacklist entries from the database.
 Returns  : A hash containg the blacklisted CIDR/IP addresses
 
=cut

sub get_db_blocks {
    my $self     = shift;
    my $category = shift;
    my $cidr = Net::CIDR::Lite->new();
    unless ($category) { $category = ""; }
    $category = "\%" . $category . "\%";
    $self->db_block_expire();
    my %hash = ();
    my $SQL =
"SELECT ipaddress FROM blocked_hosts WHERE date_expired > NOW() AND expired != '1' AND whitelisted = '0' AND ( category LIKE ? OR category = 'all' )";
    my $dbh = $self->db_connect();
    my $sth = $dbh->prepare($SQL);

    $sth->execute("$category");
    while ( my $r = $sth->fetchrow_hashref() ) {
    	print "$r->{ipaddress} is currently blocked in the database\n" if ($self->{'_VERBOSE'});
        $hash{ $r->{ipaddress} } = '1';
    }
    $dbh->disconnect();

    foreach my $k ( sort keys %hash ) {
        if ( $k =~ m/\d+\/\d+/ ) {
            $cidr->add($k);
        }
        else {
            $cidr->add_ip($k);
        }
    }

    return $cidr;
}



=head2 get_recent_blocks

 Usage    : $bt->get_recent_blocks();
 Purpose  : Get list of all IP Addresses blacklisted in the last 30 days.
 Returns  : A hash containg the blacklisted CIDR/IP addresses, with the IP being the key, and the number of entries being the value.
 Argument : The number of days to look back through.  Defaults to 30.

=cut

sub get_recent_blocks {
    my $self = shift;
    my $days = shift;
    my $cidr = Net::CIDR::Lite->new();
    unless ($days) { $days = "30"; }
    my %hash = ();
    my $dbh  = $self->db_connect();
    my $SQL =
"SELECT ipaddress FROM blocked_hosts WHERE date_blocked > NOW()-Interval $days day AND expired = '1'";
    my $sth = $dbh->prepare($SQL);
    $sth->execute();
    while ( my $r = $sth->fetchrow_hashref() ) {
		print "$r->{ipaddress} has been bad in the last $days days\n" if ($self->{'_VERBOSE'});
        $hash{ $r->{ipaddress} }++;
    }
    $dbh->disconnect();
    foreach my $k ( sort keys %hash ) {
        if ( $k =~ m/\d+\/\d+/ ) {
            $cidr->add($k);
        }
        else {
            $cidr->add_ip($k);
        }
    }
    return $cidr;
}

=head2 get_recent_blocks_count

 Usage    : $bt->get_recent_blocks();
 Purpose  : Get list of all IP Addresses blacklisted in the last 30 days.
 Returns  : A hash containg the blacklisted CIDR/IP addresses, with the IP being the key, and the number of entries being the value.
 Argument : The number of days to look back through.  Defaults to 30.

=cut

sub get_recent_blocks_count {
    my $self = shift;
    my $days = shift;
    unless ($days) { $days = "30"; }
    my %hash = ();
    my $dbh  = $self->db_connect();
    my $SQL =
"SELECT ipaddress FROM blocked_hosts WHERE date_blocked > NOW()-Interval $days day AND expired = '1'";
    my $sth = $dbh->prepare($SQL);
    $sth->execute();
    while ( my $r = $sth->fetchrow_hashref() ) {
		print "$r->{ipaddress} has been bad in the last $days days\n" if ($self->{'_VERBOSE'});
        $hash{ $r->{ipaddress} }++;
    }
    $dbh->disconnect();
    return %hash;
}

=head2 check_iptables_setup

 Usage    : $bt->check_iptables_setup();
 Purpose  : Sets up iptables for use with BadTraffic
 Returns  : Nothing
 
=cut

sub check_iptables_setup {
    my $self = shift;
    if ( $self->{_FW_TYPE} ne "iptables" ) {
 		#Setting up iptables firewalls won't help if you aren't running iptables
        return 0;
    }

	unless ($self->{_USER_NAME} eq "root"){
	  warn "Only root can change firewall rules\n";
	  return 1;
	}


    my @result = ();

    my $action = 1;

    @result = `/sbin/iptables -L INPUT-AUTO -n -v`;
    foreach my $line (@result) {
        if ( $line =~ m/Chain INPUT-AUTO \((\d) references\)/ ) {
            #print "INPUT-AUTO jump rule is in place with $1 references\n";
            $action = 0;
        }
    }

    if ($action) {
        print "Adding iptables chain INPUT-AUTO\n";
        @result = `/sbin/iptables -N INPUT-AUTO`;
    }

    $action = 1;
    @result = `/sbin/iptables -L OUTPUT-AUTO -n -v`;
    foreach my $line (@result) {
        if ( $line =~ m/Chain OUTPUT-AUTO \((\d) references\)/ ) {
            #print "OUTPUT-AUTO jump rule is in place with $1 references\n";
            $action = 0;
        }
    }
    if ($action) {
        print "Adding iptables chain OUTPUT-AUTO\n";
        @result = `/sbin/iptables -N OUTPUT-AUTO`;
    }

    $action = 1;

    @result = `/sbin/iptables -L INPUT -n -v`;
    foreach my $line (@result) {
        if ( $line =~ m/INPUT-AUTO  all +-- +\* +\* +0.0.0.0/ ) {
            #print "INPUT-AUTO jump rule is in place in the INPUT chain\n";
            $action = 0;
        }
    }
    if ($action) {
        print "Adding iptables jump rule for INPUT chain jump to INPUT-AUTO\n";
        @result = `/sbin/iptables -I INPUT -j INPUT-AUTO`;
    }

    $action = 1;

    @result = `/sbin/iptables -L OUTPUT -n -v`;
    foreach my $line (@result) {
        if ( $line =~ m/OUTPUT-AUTO  all +-- +\* +\* +0.0.0.0/ ) {
            #print "OUTPUT-AUTO jump rule is in place in the OUTPUT chain\n";
            $action = 0;
        }
    }
    if ($action) {
        print
          "Adding iptables jump rule for OUTPUT chain jump to OUTPUT-AUTO\n";
        @result = `/sbin/iptables -I OUTPUT -j OUTPUT-AUTO`;
    }
}

=head2 netmask2cidr

 Usage    : $bt->netmask2cidr("address", "netmask");
 Purpose  : Convert an IP address and a netmask into a CIDR address
 Arguments: Two strings, an address and a netmask
 Returns  : A string containing the CIDR address
 
=cut

sub netmask2cidr {
    my %mask = (
        "255.255.255.255" => "32",
        "255.255.255.254" => "31",
        "255.255.255.252" => "30",
        "255.255.255.248" => "29",
        "255.255.255.240" => "28",
        "255.255.255.224" => "27",
        "255.255.255.192" => "26",
        "255.255.255.128" => "25",
        "255.255.255.0"   => "24",
        "255.255.254.0"   => "23",
        "255.255.252.0"   => "22",
        "255.255.248.0"   => "21",
        "255.255.240.0"   => "20",
        "255.255.224.0"   => "19",
        "255.255.192.0"   => "18",
        "255.255.128.0"   => "17",
        "255.255.0.0"     => "16",
        "255.254.0.0"     => "15",
        "255.252.0.0"     => "14",
        "255.248.0.0"     => "13",
        "255.240.0.0"     => "12",
        "255.224.0.0"     => "11",
        "255.192.0.0"     => "10",
        "255.128.0.0"     => "9",
        "255.0.0.0"       => "8",
        "254.0.0.0"       => "7",
        "252.0.0.0"       => "6",
        "248.0.0.0"       => "5",
        "240.0.0.0"       => "4",
        "224.0.0.0"       => "3",
        "192.0.0.0"       => "2",
        "128.0.0.0"       => "1",
        "0.0.0.0"         => "0"
    );

    my %reverse = reverse %mask;
    my $self = shift;
    my $ipaddress = shift;
    my $netmask   = shift;
    my $cidr      = undef;
    $cidr = $ipaddress . "/" . $mask{$netmask};
    return $cidr;
}

=head2 cidr2netmask

 Usage    : $bt->cidr2netmask("cidr");
 Purpose  : Convert a CIDR address into an IP address and a netmask
 Arguments: A string containing the CIDR address
 Returns  : An array containing the address and the netmask
 
=cut

sub cidr2netmask {
    my %mask = (
        "255.255.255.255" => "32",
        "255.255.255.254" => "31",
        "255.255.255.252" => "30",
        "255.255.255.248" => "29",
        "255.255.255.240" => "28",
        "255.255.255.224" => "27",
        "255.255.255.192" => "26",
        "255.255.255.128" => "25",
        "255.255.255.0"   => "24",
        "255.255.254.0"   => "23",
        "255.255.252.0"   => "22",
        "255.255.248.0"   => "21",
        "255.255.240.0"   => "20",
        "255.255.224.0"   => "19",
        "255.255.192.0"   => "18",
        "255.255.128.0"   => "17",
        "255.255.0.0"     => "16",
        "255.254.0.0"     => "15",
        "255.252.0.0"     => "14",
        "255.248.0.0"     => "13",
        "255.240.0.0"     => "12",
        "255.224.0.0"     => "11",
        "255.192.0.0"     => "10",
        "255.128.0.0"     => "9",
        "255.0.0.0"       => "8",
        "254.0.0.0"       => "7",
        "252.0.0.0"       => "6",
        "248.0.0.0"       => "5",
        "240.0.0.0"       => "4",
        "224.0.0.0"       => "3",
        "192.0.0.0"       => "2",
        "128.0.0.0"       => "1",
        "0.0.0.0"         => "0"
    );

    my %reverse = reverse %mask;
    my $self = shift;
    my $cidr = shift;
    my @tmp = split( '/', $cidr );
    $tmp[1] = $reverse{ $tmp[1] };
    return @tmp;
}

sub network_address {
  my $self = shift;
  my $cidr = shift;

  my @ip_array = $self->cidr2netmask($cidr);

  my @addrarr=split(/\./,$ip_array[0]);
  my ( $ipaddress ) = unpack( "N", pack( "C4",@addrarr ) );
  
  my @maskarr=split(/\./,$ip_array[1]);
  my ( $netmask ) = unpack( "N", pack( "C4",@maskarr ) );
  
  my $netadd = ($ipaddress & $netmask);
  my @netarray = unpack( "C4", pack( "N", $netadd) );
  my $netaddress = join(".", @netarray);
  
  $cidr = $self->netmask2cidr($netaddress, $ip_array[1]);
  
  return "$cidr";
  
}

sub broadcast_address {
  my $self = shift;
  my $cidr = shift;

  my @ip_array = $self->cidr2netmask($cidr);

  my @addrarr=split(/\./,$ip_array[0]);
  my ( $ipaddress ) = unpack( "N", pack( "C4",@addrarr ) );
  
  my @maskarr=split(/\./,$ip_array[1]);
  my ( $netmask ) = unpack( "N", pack( "C4",@maskarr ) );
  
  my $netadd = ($ipaddress & $netmask);
  my @netarray = unpack( "C4", pack( "N", $netadd) );
  my $netaddress = join(".", @netarray);
  
  my $bcast = ( $ipaddress & $netmask ) + ( ~ $netmask );
  my @bcastarr=unpack( "C4", pack( "N",$bcast ) ) ;
  my $broadcast=join(".",@bcastarr);

  $cidr = $self->netmask2cidr($broadcast, $ip_array[1]);
  
  return "$cidr";
  
}

sub both_halves {
  my $self = shift;
  my $address = shift;
  my $bottom = $self->network_address($address);
  my $top = $self->broadcast_address($address);

  my @ip = split("/", $address);
  my $network = $ip[1];
  $network++;
  
  if ($network >= 32){ $network = '32' };
  
  #print "looking for $address - splitting into $bottom and $top\n";

  my @top_array = split("/", $top);
  my $newtop = $top_array[0] . "/" . $network;

  my @bottom_array = split("/", $bottom);
  my $newbottom = $bottom_array[0] . "/" . $network;

  my @return = ();

  $return[0] = $self->network_address($newtop);
  $return[1] = $self->network_address($newbottom);

  return @return;
}

sub cidr_contains {
  my $self = shift;
  my $cidr1 = shift;
  my $cidr2 = shift;

  my @host1_array = split("/", $cidr1);
  my @host2_array = split("/", $cidr2);
  my $host1_check = $host2_array[0] . "/" . $host1_array[1];
  my $network1 = $self->network_address($host1_check);
  if ($network1 eq $cidr1){ return 1 };
  return 0;
}

sub decompose {
  my $self = shift;
  my $target = shift;
  my $address = shift;
  my $limit = shift;
  my %remove = ();
  #our %decomposed_list = ();
  unless ($limit){ die "no limit given"; }

  #print "  decomposing $address, looking for $target\n";

  my @both = $self->both_halves($address);

  my @newmask = split('/', $both[0]);

  unless ($newmask[1] >= "32"){
    #print "$both[0] and $target\n";

    if ($self->cidr_contains($both[0], $target) ) {
      $self->decompose($target, $both[0], $limit);
    } else {
      #print "   putting back $both[0]\n";
      $self->{'_DECOMPOSED_LIST'}{$both[0]} = '1';
    }

    if ($self->cidr_contains($both[1], $target) ) {
      $self	->decompose($target, $both[1], $limit);
    } else {
      #print "   putting back $both[1]\n";
      $self->{'_DECOMPOSED_LIST'}{$both[1]} = '1';
    }



  }
  return %remove;
  #return $self->{'_DECOMPOSED_LIST'};
}

sub cidr_subtract {
  #Does $cidr1 contain $cidr2?
  my $self = shift;
  my $cidr1 = shift;
  my $cidr2 = shift;

  my @cidr1_list = $cidr1->list;
  my @cidr2_list = $cidr2->list;
  
  my $saftey_count = @cidr2_list;
  if ($saftey_count > 200){
    warn "Giving Up: cidr_subtract cannot process lists over 200 entries long\n";
    return 1;
  }
  
  my %cidr1_hash = map { $_ => '1' } @cidr1_list;
  my %cidr2_hash = map { $_ => '1' } @cidr2_list;
  
  foreach my $host1 (@cidr2_list){ #preserves IP sort order from Net::CIDR::Lite
  #foreach my $host1 (sort keys %cidr2_hash){
    #print "processing cidr2_hash $host1\n";
    $self->{'_DECOMPOSED_LIST'} = undef;
    $self->{'_DECOMPOSED_LIST'} = {};
    
    foreach my $host2 (sort {
		my @a = split /\./, $a;
		my @b = split /\./, $b;
		$a[0] <=> $b[0] or 
		$a[1] <=> $b[1] or 
		$a[2] <=> $b[2] ;#or 
		#$a[3] <=> $b[3];
	} keys %cidr1_hash){
       #print " processing cidr1_hash $host2\n";
       my @host1_array = split("/", $host1);
       my @host2_array = split("/", $host2);

       my $host2_check = $host1_array[0] . "/" . $host2_array[1];
       my $network2 = $self->network_address($host2_check);
       
       if ($network2 eq $host2){
         #print "  removing $host2 from cidr1_hash as it conflicts with $host1\n";
         delete $cidr1_hash{$host2};
         my %final_list = ();
         my %remove = $self->decompose($host1, $host2, $host1_array[1]);
         
         foreach my $e ( sort keys %{$self->{'_DECOMPOSED_LIST'}} ){ 
           #print "  adding $e to cidr_hash1\n";
           $cidr1_hash{$e} = '1';
         }
       }       
    }
  }

  foreach my $host1 (sort keys %cidr2_hash){
    foreach my $host2 (sort keys %cidr1_hash){
       my @host1_array = split("/", $host1);
       my @host2_array = split("/", $host2);
		#print ".";
       my $host1_check = $host2_array[0] . "/" . $host1_array[1];
       my $network1 = $self->network_address($host1_check);
       if ($network1 eq $host1){ delete $cidr1_hash{$host2} }
    }
  }

  my $new_cidr = Net::CIDR::Lite->new();
  foreach my $key (sort keys %cidr1_hash){ $new_cidr->add("$key") }
  return $new_cidr;
}

1;
__END__
