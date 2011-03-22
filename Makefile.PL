use inc::Module::Install;

RTx('RT-Extension-LDAPImport');
author ('Kevin Falcone <falcone@bestpractical.com>');
license('perl');
abstract('Import RT Users from an LDAP store');
all_from('lib/RT/Extension/LDAPImport.pm');

requires('Test::More');
requires('Net::LDAP');
requires_rt('3.6.3');
requires('Class::Accessor');

feature "Proper Testing" =>
    -default => 0,
    recommends('Net::LDAP::Server::Test')
    ;

my ($lp) = ($INC{'RT.pm'} =~ /^(.*)[\\\/]/);
my $lib_path = join( ' ', "$RT::LocalPath/lib", $lp );
substitute(
    {
        RT_LIB_PATH  => $lib_path,
    },
    {
        sufix => '.in'
    },
    qw(bin/rtldapimport),
);
substitute(
    {
        RT_LIB_PATH  => $lib_path,
    },
    {
        sufix => '.in'
    },
    q(t/lib/RT/Extension/LDAPImport/Test.pm),
);

sign;
&auto_install();
&WriteAll;
