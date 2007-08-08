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

&WriteAll;
