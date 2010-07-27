use strict;
use warnings;
use lib 't/lib';
use RT::Extension::LDAPImport::Test tests => 22;
eval { require Net::LDAP::Server::Test; 1; } or do {
    plan skip_all => 'Unable to test without Net::Server::LDAP::Test';
};

use Net::LDAP::Entry;
use RT::User;

my ($url, $m) = RT::Test->started_ok;

my $importer = RT::Extension::LDAPImport->new;
isa_ok($importer,'RT::Extension::LDAPImport');

my @ldap_entries;
for ( 1 .. 13 ) {
    my $entry = Net::LDAP::Entry->new();
    my $username = "testuser$_";
    my $dn = "uid=$username,ou=foo,dc=bestpractical,dc=com";
    $entry->dn($dn);
    $entry->add(
        dn   => $dn,
        cn   => "Test User $_ ".int rand(200),
        mail => "$username\@invalid.tld",
        uid  => $username,
    );
    push @ldap_entries, $entry;
}

my $ldap_port = 1024 + int rand(10000) + $$ % 1024;
ok( my $server = Net::LDAP::Server::Test->new( $ldap_port, data => \@ldap_entries ),
    "spawned test LDAP server on port $ldap_port");

RT->Config->Set('LDAPHost',"ldap://localhost:$ldap_port");
RT->Config->Set('LDAPMapping',
                   {Name         => 'uid',
                    EmailAddress => 'mail',
                    RealName     => 'cn'});
RT->Config->Set('LDAPBase','ou=foo,dc=bestpractical,dc=com');
RT->Config->Set('LDAPFilter','(objectClass=User)');

$importer->screendebug(1) if ($ENV{TEST_VERBOSE});

# check that we don't import
ok($importer->import_users());
{
    my $users = RT::Users->new($RT::SystemUser);
    for my $username (qw/RT_SYSTEM root Nobody/) {
        $users->Limit( FIELD => 'Name', OPERATOR => '!=', VALUE => $username, ENTRYAGGREGATOR => 'AND' );
    }
    diag($users->BuildSelectQuery);
    is($users->Count,0);
}

# check that we do import
ok($importer->import_users( import => 1 ));
for my $entry (@ldap_entries) {
    my $user = RT::User->new($RT::SystemUser);
    $user->LoadByCols( EmailAddress => $entry->get_value('mail'),
                       Realname => $entry->get_value('cn'),
                       Name => $entry->get_value('uid') );
    ok($user->Id, "Found ".$entry->get_value('cn')." as ".$user->Id);
}
