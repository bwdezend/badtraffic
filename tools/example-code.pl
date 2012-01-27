#!/usr/bin/perl

use BadTraffic;
my $bt = BadTraffic->new(
    DB_PASS => "password",  #Password for db
    DB_HOST => "db_hostname.example.com",  #db hostname
    DB_USER => "autoblocker",  #default username is autoblocker   
    DB_NAME => "badtraffic_db",  #default db name is badtraffic_db
    VERBOSE => "1"
);

my %db_hash = $bt->get_db_blocks('web');   #gets any block from the database that matches LIKE %web%
my %fw_hash = $bt->get_fw_blocks();        #gets a list of the currently blocked IPs and networks
my %wl_hash = $bt->get_whitelist();        #gets a list of the currently whitelisted IPs and networks

my $db_cidr = $bt->get_db_blocks_cidr('web'); #gets a Net::CIDR::Lite object with active database blocks that match LIKE %web%
my $wl_cidr = $bt->get_whitelist_cidr();      #gets a Net::CIDR::Lite object with current whitelist blocks 
my $fw_cidr = $bt->get_fw_blocks_cidr();      #gets a Net::CIDR::Lite object with active fw blocks on localhost

my %rb_hash = $bt->get_recent_blocks('3'); #gets a hash of recently blocked addresses over the past 3 days.


$bt->db_block_expire(); #Looks for blocks that are past-due, and sets their "expired" flag to "1",
                        #it's also called every time get_db_blocks() is called

my $address  = "8.8.8.8";
my $reason   = "Test block of the Google DNS server at $address";
my $days     = "1";
my $category = "test";

$bt->db_block(
  address  => "$address",  #block $address (ideally in cidr notation)
  reason   => "$reason",   #for a valid $reason,
  days     => "$days",     #for a number of $days,
  category => "$category"  #and assign it to a $category
);

$bt->db_unblock($address); #expire any blocks in the system for $address

$reason = "Test whitelist of the Google DNS server at $address";
$category = "oit-ss-sts-ais";

$bt->wl_add(
  address  => "$address",  #whitelist $address (ideally in cidr notation)
  reason   => "$reason",   #for a valid $reason,
  days     => "$days",     #for a number of $days,
  category => "$category"  #and assign it to a $category, although whitelist categories don't matter - if it's whitelisted, it's whitelisted
);

$bt->wl_remove($address); #expire any whitelist entries for $address