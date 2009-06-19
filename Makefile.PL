use inc::Module::Install;

RTx('RT-Extension-LDAPImport');
author ('Kevin Falcone <falcone@bestpractical.com>');
license('perl');
abstract('Import RT Users from an LDAP store');
all_from('lib/RT/Extension/LDAPImport.pm');

requires('Test::More');
requires('Net::LDAP');
requires('RT' => '3.6.3');
requires('Class::Accessor');

my ($lp) = ($INC{'RT.pm'} =~ /^(.*)[\\\/]/);
my $lib_path = join( ' ', "$RT::LocalPath/lib", $lp );
substitute(
    {
        RT_LIB_PATH  => $lib_path,
    },
    qw(bin/rtldapimport),
);

&WriteAll;
