use strict;
use warnings;
use lib 't/lib';
use RT::Extension::LDAPImport::Test tests => 24;
eval { require Net::LDAP::Server::Test; 1; } or do {
    plan skip_all => 'Unable to test without Net::Server::LDAP::Test';
};

use Net::LDAP::Entry;
use RT::User;

my ($url, $m) = RT::Test->started_ok;

my $importer = RT::Extension::LDAPImport->new;
isa_ok($importer,'RT::Extension::LDAPImport');

my $ldap_port = 1024 + int rand(10000) + $$ % 1024;
ok( my $server = Net::LDAP::Server::Test->new( $ldap_port, auto_schema => 1 ),
    "spawned test LDAP server on port $ldap_port");
my $ldap = Net::LDAP->new("localhost:$ldap_port");
$ldap->bind();

my @ldap_user_entries;
for ( 1 .. 12 ) {
    my $username = "testuser$_";
    my $dn = "uid=$username,ou=foo,dc=bestpractical,dc=com";
    my $entry = { 
                    dn   => $dn,
                    cn   => "Test User $_ ".int rand(200),
                    mail => "$username\@invalid.tld",
                    uid  => $username,
                    objectClass => 'User',
                };
    push @ldap_user_entries, $entry;
    $ldap->add( $dn, attr => [%$entry] );
}

my @ldap_group_entries;
for ( 1 .. 4 ) {
    my $groupname = "Test Group $_";
    my $dn = "cn=$groupname,ou=groups,dc=bestpractical,dc=com";
    my $entry = {
        cn   =>  $groupname,
        member => [ map { $_->{dn} } @ldap_user_entries[($_-1),($_+3),($_+7)] ],
        objectClass => 'Group',
    };
    $ldap->add( $dn, attr => [%$entry] );
    push @ldap_group_entries, $entry;
}

RT->Config->Set('LDAPHost',"ldap://localhost:$ldap_port");
RT->Config->Set('LDAPMapping',
                   {Name         => 'uid',
                    EmailAddress => 'mail',
                    RealName     => 'cn'});
RT->Config->Set('LDAPBase','dc=bestpractical,dc=com');
RT->Config->Set('LDAPFilter','(objectClass=User)');

$importer->screendebug(1) if ($ENV{TEST_VERBOSE});

ok($importer->import_users( import => 1 ));
for my $entry (@ldap_user_entries) {
    my $user = RT::User->new($RT::SystemUser);
    $user->LoadByCols( EmailAddress => $entry->{mail},
                       Realname => $entry->{cn},
                       Name => $entry->{uid} );
    ok($user->Id, "Found $entry->{cn} as ".$user->Id);
}

RT->Config->Set('LDAPGroupBase','dc=bestpractical,dc=com');
RT->Config->Set('LDAPGroupFilter','(objectClass=Group)');
RT->Config->Set('LDAPGroupMapping',
                   {Name         => 'cn',
                    Member_Attr  => 'mail',
                   });
# XXX come back and test skipping the import
ok( $importer->import_groups( import => 1 ) );

for my $entry (@ldap_group_entries) {
    my $group = RT::Group->new($RT::SystemUser);
    $group->LoadUserDefinedGroup( $entry->{cn} );
    ok($group->Id, "Found $entry->{cn} as ".$group->Id);
}
