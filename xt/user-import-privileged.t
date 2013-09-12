use strict;
use warnings;
use lib 'xt/lib';
use RT::Extension::LDAPImport::Test tests => 8 + 13*2;
eval { require Net::LDAP::Server::Test; 1; } or do {
    plan skip_all => 'Unable to test without Net::Server::LDAP::Test';
};

use Net::LDAP::Entry;
use RT::User;

my $importer = RT::Extension::LDAPImport->new;
isa_ok($importer,'RT::Extension::LDAPImport');

my $ldap_port = 1024 + int rand(10000) + $$ % 1024;
ok( my $server = Net::LDAP::Server::Test->new( $ldap_port, auto_schema => 1 ), 
    "spawned test LDAP server on port $ldap_port");

my $ldap = Net::LDAP->new("localhost:$ldap_port");
$ldap->bind();
$ldap->add("ou=foo,dc=bestpractical,dc=com");

my @ldap_entries;
for ( 1 .. 13 ) {
    my $username = "testuser$_";
    my $dn = "uid=$username,ou=foo,dc=bestpractical,dc=com";
    my $entry = { 
                    cn   => "Test User $_ ".int rand(200),
                    mail => "$username\@invalid.tld",
                    uid  => $username,
                    objectClass => 'User',
                };
    push @ldap_entries, $entry;
    $ldap->add( $dn, attr => [%$entry] );
}


RT->Config->Set('LDAPHost',"ldap://localhost:$ldap_port");
RT->Config->Set('LDAPMapping',
                   {Name         => 'uid',
                    EmailAddress => 'mail',
                    RealName     => 'cn'});
RT->Config->Set('LDAPBase','ou=foo,dc=bestpractical,dc=com');
RT->Config->Set('LDAPFilter','(objectClass=User)');
RT->Config->Set('LDAPCreatePrivileged', 1);

$importer->screendebug(1) if ($ENV{TEST_VERBOSE});

# check that we don't import
ok($importer->import_users());
{
    my $users = RT::Users->new($RT::SystemUser);
    for my $username (qw/RT_System root Nobody/) {
        $users->Limit( FIELD => 'Name', OPERATOR => '!=', VALUE => $username, ENTRYAGGREGATOR => 'AND' );
    }
    is($users->Count,0);
}

# check that we do import
ok($importer->import_users( import => 1 ));
for my $entry (@ldap_entries) {
    my $user = RT::User->new($RT::SystemUser);
    $user->LoadByCols( EmailAddress => $entry->{mail},
                       Realname => $entry->{cn},
                       Name => $entry->{uid} );
    ok($user->Id, "Found $entry->{cn} as ".$user->Id);
    ok($user->Privileged, "User created as Privileged");
}

# can't unbind earlier or the server will die
$ldap->unbind;
