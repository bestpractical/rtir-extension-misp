use strict;
use warnings;
package RTIR::Extension::MISP;

use LWP::UserAgent;
use JSON;
use UUID::Tiny ':std';

our $VERSION = '0.01';

=head1 NAME

RTIR-Extension-MISP - Integrate RTIR with MISP

=head1 DESCRIPTION

L<MISP|https://www.misp-project.org/> is a platform for sharing threat intelligence among
security teams, and this extension provides integration from L<RTIR/https://bestpractical.com/rtir>.

=head1 RTIR VERSION

Works with RTIR 5.0

=head1 INSTALLATION

=over

=item C<perl Makefile.PL>

=item C<make>

=item C<make install>

May need root permissions

=item Edit your F</opt/rt4/etc/RT_SiteConfig.pm>

Add this line:

    Plugin('RTIR::Extension::MISP');

=item C<make initdb>

Only run this the first time you install this module.

If you run this twice, you will end up with duplicate data
in your database.

If you are upgrading this module, check for upgrading instructions
in case changes need to be made to your database.

=item Clear your mason cache

    rm -rf /opt/rt4/var/mason_data/obj

=item Restart your webserver

=back

=head1 CONFIGURATION

Set the following in your C<RT_SiteConfig.pm> with details for the MISP
instance you want RTIR to integrate with.

    Set(%ExternalFeeds,
        'MISP' => [
            {   Name        => 'MISP',
                URI         => 'https://mymisp.example.com',  # Change to your MISP
                Description => 'My MISP Feed',
                DaysToFetch => 5,  # For the feed page, how many days back to fetch
                ApiKeyAuth  => 'API SECRET KEY',  # Change to your real key
            },
        ],
    );

=head1 DETAILS

This integration adds several different ways to work between the MISP and
RTIR systems as described below.

=head2 Consume Feed from MISP

After adding the MISP configuration described above, the Feeds page in RTIR at
RTIR > Tools > External Feeds will have a new MISP option listed. This feed
pulls in events for the past X number of days based on the DaysToFetch
configuration. From the feed display page, you can click the "Create new ticket"
button to create a ticket with information from the MISP event.

=head2 MISP Portlet on Incident Display

On the Incident Display page, if the custom field MISP Event ID has a value,
a portlet MISP Event Details will be displayed, showing details pulled in
from the event via the MISP REST API.

=head2 Update MISP Event

On an incident with a MISP Event ID, the Actions menu will have an option
"Update MISP Event". If you select this action, RTIR will update the existing
MISP event with an RTIR object, including data from the incident ticket.

=head2 Create MISP Event

If MISP Event ID has no value, the Actions menu on incidents shows an option to
"Create MISP Event". Select this to create an event in MISP with details from
the incident ticket.

=head2 

=head1 AUTHOR

Best Practical Solutions, LLC E<lt>modules@bestpractical.comE<gt>

=for html <p>All bugs should be reported via email to <a
href="mailto:bug-RTIR-Extension-MISP@rt.cpan.org">bug-RTIR-Extension-MISP@rt.cpan.org</a>
or via the web at <a
href="http://rt.cpan.org/Public/Dist/Display.html?Name=RTIR-Extension-MISP">rt.cpan.org</a>.</p>

=for text
    All bugs should be reported via email to
        bug-RTIR-Extension-MISP@rt.cpan.org
    or via the web at
        http://rt.cpan.org/Public/Dist/Display.html?Name=RTIR-Extension-MISP

=head1 LICENSE AND COPYRIGHT

This software is Copyright (c) 2021 by Best Practical Solutions, LLC

This is free software, licensed under:

  The GNU General Public License, Version 2, June 1991

=cut

sub GetUserAgent {
    my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
    my $misp_config = RT->Config->Get('ExternalFeeds')->{MISP};
    RT->Logger->error("Unable to load MISP configuration") unless $misp_config;

    my $default_headers = HTTP::Headers->new(
        'Authorization' => $misp_config->[0]{ApiKeyAuth},
        'Accept'        => 'application/json',
        'Content-Type'  => 'application/json',
    );
    $ua->default_headers( $default_headers );
    return $ua;
}

sub GetMISPBaseURL {
    my $misp_config = RT->Config->Get('ExternalFeeds')->{MISP};
    RT->Logger->error("Unable to load MISP configuration") unless $misp_config;

    my $url = $misp_config->[0]{URI};
    return $url;
}

sub FetchEventDetails {
    my $event_id = shift;

    my $url = GetMISPBaseURL();
    return unless $url;

    my $ua = GetUserAgent();

    my $response = $ua->get($url . "/events/$event_id");

    unless ( $response->is_success ) {
        RT->Logger->error('Unable to fetch event data: ' . $response->status_line());
        return 0;
    }

    my $json;
    eval { $json = JSON->new->decode($response->content); };
    return $json;
}

sub AddRTIRObjectToMISP {
    my $ticket = shift;

    my $ua = GetUserAgent();
    my $url = GetMISPBaseURL();

    # This is base object information defined in MISP
    # See: https://github.com/MISP/misp-objects/blob/main/objects/rtir/definition.json
    my %misp_data = (
        "name" => "rtir",
        "meta-category" => "misc",
        "template_uuid" => "7534ee19-0a1f-4f46-a197-e6e73e457943",
        "description" => "RTIR - Request Tracker for Incident Response",
        "template_version" => "2",
        "uuid" => create_uuid_as_string(UUID_V4),
        "distribution" => "5",
        "sharing_group_id" => "0"
    );

    my %attribute_fields = (
        classification => $ticket->FirstCustomFieldValue('Classification'),
        ip             => $ticket->FirstCustomFieldValue('IP'),
        queue => $ticket->QueueObj->Name,
        status => $ticket->Status,
        subject => $ticket->Subject,
        'ticket-number' => $ticket->Id,
    );

    my @attributes;
    foreach my $attribute ( keys %attribute_fields ) {
        warn "for $attribute: " . $attribute_fields{$attribute};
        next unless $attribute_fields{$attribute};
        push @attributes, {
            'uuid' => create_uuid_as_string(UUID_V4),
            'object_relation' => $attribute,
            'value' => $attribute_fields{$attribute},
            'type' => $attribute eq 'ip' ? 'ip-dst' : 'text',
            'disable_correlation' => JSON::false,
            'to_ids' => $attribute eq 'ip' ? JSON::true : JSON::false,
            'category' => $attribute eq 'ip' ? 'Network activity' : 'Other'
        }
    }

    $misp_data{'Attribute'} = \@attributes;
    my $json = encode_json( \%misp_data );

    my $response = $ua->post($url . "/objects/add/" . $ticket->FirstCustomFieldValue("MISP Event UUID"), Content => $json);

    unless ( $response->is_success ) {
        RT->Logger->error('Unable to add object to event: ' . $response->status_line() . $response->decoded_content());
        return (0, 'MISP event update failed');
    }

    return (1, 'MISP event updated');
}

1;
