use Test::More;
eval { require Net::LDAP::Server::Test; 1; } or do {
    plan skip_all => 'Unable to test without Net::Server::LDAP::Test';
};
plan tests => 1;
