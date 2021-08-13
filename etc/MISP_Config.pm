=pod

This is an example configuration for a MISP feed. Replace the
URI with the MISP instance you want to query.

Set(%ExternalFeeds,
    'MISP' => [
        {   Name        => 'MISP',
            URI         => 'https://mymisp.example.com',
            Description => 'My MISP Feed',
            DaysToFetch => 5,
        },
    ],
);

=cut
