package RT::Extension::LDAPImport;

our $VERSION = '0.02';

use warnings;
use strict;
use base qw(Class::Accessor);
__PACKAGE__->mk_accessors(qw(_ldap screendebug));
use Carp;
use Net::LDAP;
use Data::Dumper;

=head1 NAME

RT::Extension::LDAPImport - Import Users from an LDAP store


=head1 SYNOPSIS

    use RT::Extension::LDAPImport;

=head1 METHODS

=head2 connect_ldap

Relies on the config variables $RT::LDAPHost,
$RT::LDAPUser and $RT::LDAPPassword being set
in your RT Config files.

 Set(LDAPHost,'my.ldap.host')
 Set(LDAPUSER,'me');
 Set(LDAPPassword,'mypass');

LDAPUser and LDAPPassword can be blank,
which will cause an anonymous bind.

LDAPHost can be a hostname or an ldap:// ldaps:// uri

=cut

sub connect_ldap {
    my $self = shift;

    my $ldap = Net::LDAP->new($RT::LDAPHost);
    $self->_debug("connecting to $RT::LDAPHost");
    unless ($ldap) {
        $self->_error("Can't connect to $RT::LDAPHost");
        return;
    }

    my $msg;
    if ($RT::LDAPUser) {
        $self->_debug("binding as $RT::LDAPUser");
        $msg = $ldap->bind($RT::LDAPUser, password => $RT::LDAPPassword);
    } else {
        $self->_debug("binding anonymously");
        $msg = $ldap->bind;
    }

    if ($msg->code) {
        $self->_error("LDAP bind failed " . $msg->error);
        return;
    }

    $self->_ldap($ldap);
    return $ldap;

}

=head2 run_search

Executes a search using the RT::LDAPFilter and RT::LDAPBase
options.

LDAPBase is the DN to look under
LDAPFilter is how you want to restrict the users coming back

Will connect to LDAP server using connect_ldap

=cut

sub run_search {
    my $self = shift;
    my $ldap = $self->_ldap||$self->connect_ldap;

    unless ($ldap) {
        $self->_error("fetching an LDAP connection failed");
        return;
    }

    $self->_debug("searching with base => '$RT::LDAPBase' filter => '$RT::LDAPFilter'");

    my $result = $ldap->search( base => $RT::LDAPBase, 
                                filter => $RT::LDAPFilter );

    if ($result->code) {
        $self->_error("LDAP search failed " . $result->error);
        return;
    }

    $self->_debug("search found ".$result->count." users");
    return $result;

}

=head2 import_users

Takes the results of the search from run_search
and maps attributes from LDAP into RT::User attributes
using $RT::LDAPMapping.
Creates RT users if they don't already exist.

RT::LDAPMapping should be set in your RT_SiteConfig
file and looks like this.

 Set($LDAPMapping, { RTUserField => LDAPField, RTUserField => LDAPField });

RTUserField is the name of a field on an RT::User object
LDAPField can be a simple scalar and that attribute
will be looked up in LDAP.  

It can also be an arrayref, in which case each of the 
elements will be evaluated in turn.  Scalars will be
looked up in LDAP and concatenated together with a single
space.

If the value is a sub reference, it will be executed.
The sub should return a scalar, which will be examined.
If it is a scalar, the value will be looked up in LDAP.
If it is an arrayref, the values will be concatenated 
together with a single space.

=cut

sub import_users {
    my $self = shift;

    my $results = $self->run_search;
    unless ( $results && $results->count ) {
        $self->_debug("No results found, no import");
        $self->disconnect_ldap;
        return;
    }

    my @rtfields = keys %{$RT::LDAPMapping||{}};
    unless ( @rtfields ) {
        $self->_debug("No mapping found in RT::LDAPMapping, can't import");
        $self->disconnect_ldap;
        return;
    }

    while (my $entry = $results->shift_entry) {
        my $newuser = {};
        foreach my $rtfield ( @rtfields ) {
            my $ldap_attribute = $RT::LDAPMapping->{$rtfield};

            my @attributes = $self->_parse_ldap_map($ldap_attribute);
            unless (@attributes) {
                $self->_error("Invalid LDAP mapping for $rtfield ".Dumper($ldap_attribute));
                next;
            }
            my @values;
            foreach my $attribute (@attributes) {
                $self->_debug("fetching value for $attribute and storing it in $rtfield");
                push @values, $entry->get_value($attribute);
            }
            $newuser->{$rtfield} = join(' ',@values); 
        }
        $newuser->{Name} ||= $newuser->{EmailAddress};
        unless ( $newuser->{Name} ) {
            $self->_warn("No Name or Emailaddress for user, skipping ".Dumper $newuser);
            next;
        }
        $self->_debug("Checking user $newuser->{Name}");
        #$self->_debug(Dumper $newuser);
        $self->create_rt_user( user => $newuser );
    }

}

=head3 _parse_ldap_map

Internal helper function for import_user
If we're passed an arrayref, it will recurse 
over each of the elements in case one of them is
another arrayref or subroutine.

If we're passed a subref, it executes the code
and recurses over each of the returned values
so that a returned array or arrayref will work.

If we're passed a scalar, returns that.

Returns a list of values that need to be concatenated
together.

=cut

sub _parse_ldap_mapping {
    my ($self,$mapping) = @_;

    if (ref $mapping eq 'ARRAY') {
        return map { $self->_parse_ldap_map($_) } @$mapping;
    } elsif (ref $mapping eq 'CODE') {
        return map { $self->_parse_ldap_map($_) } $mapping->()
    } elsif (ref $map) {
        $self->_error("Invalid type of LDAPMapping [$map]");
        return;
    } else {
        return $map;
    }
}

=head2 create_rt_user

Takes a hashref of args to pass to RT::User::Create
Will try loading the user and will only create a new
user if it can't find an existing user with the Name
or EmailAddress arg passed in.

=cut

sub create_rt_user {
    my $self = shift;
    my %args = @_;
    my $user = $args{user};

    my $user_obj = RT::User->new($RT::SystemUser);

    $user_obj->Load( $user->{Name} );
    unless ($user_obj->Id) {
        $user_obj->LoadByEmail( $user->{EmailAddress} );
    }

    if ($user_obj->Id) {
        $self->_debug("User $user->{Name} already exists as ".$user_obj->Id);
    } else {
        my ($val, $msg) = $user_obj->Create( %$user, Privileged => 0 );

        unless ($val) {
            $self->_error("couldn't create user_obj for $user->{Name}: $msg");
            return;
        }
        $self->_debug("Created user for $user->{Name} with id ".$user_obj->Id);
    }

    unless ($user_obj->Id) {
        $self->_error("We couldn't find or create $user->{Name}. This should never happen");
    }
    return;

}

=head3 disconnect_ldap

Disconnects from the LDAP server

Takes no arguments, returns nothing

=cut

sub disconnect_ldap {
    my $self = shift;
    my $ldap = $self->_ldap;
    return unless $ldap;

    $ldap->unbind;
    $ldap->disconnect;
    return;
}

=head3 screendebug

We always log to the RT log file with level debug 

This duplicates the messages to the screen

=cut

sub _debug {
    my $self = shift;
    my $msg  = shift;

    $RT::Logger->debug($msg);

    return unless $self->screendebug;
    print $msg, "\n";

}

sub _error {
    my $self = shift;
    my $msg  = shift;

    $RT::Logger->error($msg);
    print STDERR $msg, "\n";
}

sub _warn {
    my $self = shift;
    my $msg  = shift;

    $RT::Logger->warn($msg);
    print STDERR $msg, "\n";
}

=head1 BUGS AND LIMITATIONS

No bugs have been reported.

Please report any bugs or feature requests to
C<bug-rt-extension-ldapimport@rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org>.


=head1 AUTHOR

Kevin Falcone  C<< <falcone@bestpractical.com> >>


=head1 LICENCE AND COPYRIGHT

Copyright (c) 2007, Best Practical Solutions, LLC.  All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.


=head1 DISCLAIMER OF WARRANTY

BECAUSE THIS SOFTWARE IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
FOR THE SOFTWARE, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN
OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
PROVIDE THE SOFTWARE "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE
ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE SOFTWARE IS WITH
YOU. SHOULD THE SOFTWARE PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL
NECESSARY SERVICING, REPAIR, OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
REDISTRIBUTE THE SOFTWARE AS PERMITTED BY THE ABOVE LICENCE, BE
LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL,
OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE
THE SOFTWARE (INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING
RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A
FAILURE OF THE SOFTWARE TO OPERATE WITH ANY OTHER SOFTWARE), EVEN IF
SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.

=cut

1;