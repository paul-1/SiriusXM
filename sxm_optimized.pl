#!/usr/bin/env perl

use strict;
use warnings;
use Getopt::Long;
use HTTP::Daemon;
use HTTP::Status;
use HTTP::Response;
use LWP::UserAgent;
use JSON;
use MIME::Base64;
use URI::Escape;
use DateTime;
use Data::Dumper;
use HTTP::Cookies;
use Time::HiRes qw(time);

# Parse command line arguments
my ($list, $port, $canada, $env, $debug);
my $username = "";
my $password = "";

GetOptions(
    "list|l" => \$list,
    "port|p=i" => \$port,
    "canada|ca" => \$canada,
    "env|e" => \$env,
    "debug|d" => \$debug,
) or die "Error in command line arguments\n";

# Default port if not provided
$port //= 9999;

# Get credentials from command line or environment
if (@ARGV >= 2 && !$env) {
    $username = $ARGV[0];
    $password = $ARGV[1];
} elsif ($env) {
    $username = $ENV{SXM_USER} if exists $ENV{SXM_USER};
    $password = $ENV{SXM_PASS} if exists $ENV{SXM_PASS};
}

# SiriusXM class implementation
package SiriusXM;

use strict;
use warnings;
use HTTP::Request;
use URI;

sub new {
    my ($class, $username, $password, $region, $debug) = @_;
    
    my $ua = LWP::UserAgent->new;
    $ua->cookie_jar(HTTP::Cookies->new(file => "$ENV{HOME}/.sxm_cookies.txt", autosave => 1));
    $ua->agent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36');
    $ua->timeout(10);  # 10 second timeout
    
    my $self = {
        ua => $ua,
        username => $username,
        password => $password,
        region => $region || 'US',
        debug => $debug || 0,
        channels => undef,
        current_channel_id => undef,
        current_channel_subdir => {},
        current_base_path => {},
        rest_format => 'https://player.siriusxm.com/rest/v2/experience/modules/%s',
        live_primary_hls => 'https://siriusxm-priprodlive.akamaized.net',
        fallback_gupid => "35eb99d100800000",
        extracted_gupid => undef,
        tokens => {},
        last_auth_time => 0,
        auth_lifetime => 600,  # 10 minutes
        auth_count => 0,       # Count authentications
        segment_errors => 0,   # Count segment errors
        max_segment_errors => 5,  # Max segment errors before re-auth
    };
    
    return bless $self, $class;
}

sub log {
    my ($self, $msg) = @_;
    my $dt = DateTime->now();
    printf "%s <SiriusXM>: %s\n", $dt->strftime('%d.%b %Y %H:%M:%S'), $msg;
}

sub debug {
    my ($self, $msg) = @_;
    return unless $self->{debug};
    my $dt = DateTime->now();
    printf "%s <SiriusXM DEBUG>: %s\n", $dt->strftime('%d.%b %Y %H:%M:%S'), $msg;
}

sub should_authenticate {
    my $self = shift;
    
    # Check if we've authenticated recently
    my $now = time();
    my $auth_age = $now - $self->{last_auth_time};
    
    # Check for token in cookies
    my $cookies = $self->{ua}->cookie_jar->as_string;
    my $has_token = ($cookies =~ /SXMAKTOKEN=/);
    
    # Re-authenticate if:
    # 1. No authentication has been done yet
    # 2. Last auth was too long ago
    # 3. No token in cookies
    # 4. Too many segment errors
    if ($self->{last_auth_time} == 0 || 
        $auth_age > $self->{auth_lifetime} || 
        !$has_token ||
        $self->{segment_errors} >= $self->{max_segment_errors}) {
        
        my $reason = "";
        $reason .= "Initial auth. " if $self->{last_auth_time} == 0;
        $reason .= "Auth expired (age: ${auth_age}s). " if $auth_age > $self->{auth_lifetime};
        $reason .= "No token. " if !$has_token;
        $reason .= "Too many segment errors. " if $self->{segment_errors} >= $self->{max_segment_errors};
        
        $self->debug("Need authentication: $reason");
        return 1;
    }
    
    return 0;
}

sub login {
    my $self = shift;
    
    $self->log("Login attempt with username: " . $self->{username});
    
    my $postdata = {
        moduleList => {
            modules => [{
                moduleRequest => {
                    resultTemplate => 'web',
                    deviceInfo => {
                        osVersion => 'Windows',
                        platform => 'Web',
                        sxmAppVersion => '4.3.0',
                        browser => 'Chrome',
                        browserVersion => '91.0.4472.124',
                        appRegion => $self->{region},
                        deviceModel => 'K2WebClient',
                        clientDeviceId => 'null',
                        player => 'html5',
                        clientDeviceType => 'web',
                    },
                    standardAuth => {
                        username => $self->{username},
                        password => $self->{password},
                    },
                },
            }],
        },
    };
    
    my $url = sprintf($self->{rest_format}, 'modify/authentication');
    my $req = HTTP::Request->new('POST', $url);
    $req->header('Content-Type' => 'application/json');
    $req->content(JSON::encode_json($postdata));
    
    $self->debug("POST $url");
    my $response = $self->{ua}->request($req);
    
    if ($response->code != 200) {
        $self->log("Login failed with status code: " . $response->code);
        return 0;
    }
    
    my $data;
    eval {
        $data = JSON::decode_json($response->decoded_content);
    };
    if ($@) {
        $self->log("Failed to decode JSON response: $@");
        return 0;
    }
    
    eval {
        my $status = $data->{ModuleListResponse}{status};
        if ($status != 1) {
            $self->log("Login failed with status: $status");
            return 0;
        }
        
        # Save auth time
        $self->{last_auth_time} = time();
        
        # Extract and save tokens
        my $cookies = $self->{ua}->cookie_jar->as_string;
        if ($cookies =~ /SXMAKTOKEN=([^;]+)/) {
            my $token = $1;
            if ($token =~ /^([^=]+)=([^,]+)/) {
                $self->{tokens}{time()} = $2;
                $self->debug("Stored token");
            }
        }
        
        if ($cookies =~ /SXMDATA=([^;]+)/) {
            my $data = uri_unescape($1);
            eval {
                my $json = JSON::decode_json($data);
                if ($json->{gupId}) {
                    $self->{extracted_gupid} = $json->{gupId};
                    $self->debug("Extracted gupId: " . $self->{extracted_gupid});
                }
            };
        }
    };
    if ($@) {
        $self->log("Error processing login response: $@");
        return 0;
    }
    
    $self->log("Login successful");
    return 1;
}

sub authenticate {
    my $self = shift;
    my $force = shift || 0;  # Force authentication even if not needed
    
    # Return early if authentication isn't needed
    if (!$force && !$self->should_authenticate()) {
        $self->debug("Authentication not needed");
        return 1;
    }
    
    # If not logged in, do login first
    my $cookies = $self->{ua}->cookie_jar->as_string;
    if ($cookies !~ /SXMDATA=/) {
        if (!$self->login) {
            return 0;
        }
    }
    
    $self->log("Authentication attempt");
    $self->{auth_count}++;
    
    my $postdata = {
        moduleList => {
            modules => [{
                moduleRequest => {
                    resultTemplate => 'web',
                    deviceInfo => {
                        osVersion => 'Windows',
                        platform => 'Web',
                        clientDeviceType => 'web',
                        sxmAppVersion => '4.3.0',
                        browser => 'Chrome',
                        browserVersion => '91.0.4472.124',
                        appRegion => $self->{region},
                        deviceModel => 'K2WebClient',
                        player => 'html5',
                        clientDeviceId => 'null'
                    }
                }
            }]
        }
    };
    
    my $url = sprintf($self->{rest_format}, 'resume?OAtrial=false');
    my $req = HTTP::Request->new('POST', $url);
    $req->header('Content-Type' => 'application/json');
    $req->content(JSON::encode_json($postdata));
    
    $self->debug("POST $url");
    my $response = $self->{ua}->request($req);
    
    if ($response->code != 200) {
        $self->log("Authentication failed with status code: " . $response->code);
        return 0;
    }
    
    my $data;
    eval {
        $data = JSON::decode_json($response->decoded_content);
    };
    if ($@) {
        $self->log("Failed to decode JSON response: $@");
        return 0;
    }
    
    eval {
        my $status = $data->{ModuleListResponse}{status};
        if ($status != 1) {
            $self->log("Authentication failed with status: $status");
            return 0;
        }
        
        # Save auth time
        $self->{last_auth_time} = time();
        
        # Reset segment error counter on successful auth
        $self->{segment_errors} = 0;
        
        # Extract and save tokens
        my $cookies = $self->{ua}->cookie_jar->as_string;
        if ($cookies =~ /SXMAKTOKEN=([^;]+)/) {
            my $token = $1;
            if ($token =~ /^([^=]+)=([^,]+)/) {
                $self->{tokens}{time()} = $2;
                $self->debug("Stored token");
            }
        }
    };
    if ($@) {
        $self->log("Error processing authentication response: $@");
        return 0;
    }
    
    $self->log("Authentication successful (count: $self->{auth_count})");
    return 1;
}

sub get_token {
    my $self = shift;
    
    # Get the most recent token
    my @times = sort { $b <=> $a } keys %{$self->{tokens}};
    if (@times) {
        return $self->{tokens}{$times[0]};
    }
    
    # Fall back to getting from cookie
    my $cookies = $self->{ua}->cookie_jar->as_string;
    if ($cookies =~ /SXMAKTOKEN=([^;]+)/) {
        my $token = $1;
        if ($token =~ /^([^=]+)=([^,]+)/) {
            return $2;
        }
    }
    return undef;
}

sub get_gup_id {
    my $self = shift;
    
    return $self->{extracted_gupid} if $self->{extracted_gupid};
    return $self->{fallback_gupid};
}

sub get_channel_list {
    my $self = shift;
    
    if ($self->{channels}) {
        return $self->{channels};
    }
    
    # Ensure we're authenticated
    if (!$self->authenticate()) {
        $self->log("Failed to authenticate for channel list");
        return [];
    }
    
    my $postdata = {
        moduleList => {
            modules => [{
                moduleArea => 'Discovery',
                moduleType => 'ChannelListing',
                moduleRequest => {
                    consumeRequests => [],
                    resultTemplate => 'responsive',
                    alerts => [],
                    profileInfos => []
                }
            }]
        }
    };
    
    my $url = sprintf($self->{rest_format}, 'get');
    my $req = HTTP::Request->new('POST', $url);
    $req->header('Content-Type' => 'application/json');
    $req->content(JSON::encode_json($postdata));
    
    $self->debug("POST $url");
    my $response = $self->{ua}->request($req);
    
    if ($response->code != 200) {
        $self->log("Failed to get channel list: " . $response->code);
        return [];
    }
    
    my $data;
    eval {
        $data = JSON::decode_json($response->decoded_content);
    };
    if ($@) {
        $self->log("Failed to decode JSON response: $@");
        return [];
    }
    
    eval {
        $self->{channels} = $data->{ModuleListResponse}{moduleList}{modules}[0]{moduleResponse}{contentData}{channelListing}{channels};
        $self->log("Retrieved " . scalar(@{$self->{channels}}) . " channels");
    };
    if ($@) {
        $self->log("Error processing channel list: $@");
        return [];
    }
    
    return $self->{channels};
}

sub find_channel {
    my ($self, $name) = @_;
    $name = lc($name);
    
    my $channels = $self->get_channel_list();
    
    foreach my $channel (@$channels) {
        if (lc($channel->{name} // '') eq $name || 
            lc($channel->{channelId} // '') eq $name || 
            ($channel->{siriusChannelNumber} // '') eq $name) {
            
            $self->log("Found channel: " . ($channel->{name} // 'Unknown'));
            return ($channel->{channelGuid}, $channel->{channelId});
        }
    }
    
    $self->log("Channel not found: $name");
    return (undef, undef);
}

sub get_direct_stream_url {
    my ($self, $channel_id) = @_;
    
    # Store current channel
    $self->{current_channel_id} = $channel_id;
    
    # Use a direct stream URL pattern that works well
    my $url = sprintf(
        "%s/AAC_Data/%s/HLS_%s_256k_v3/%s_256k_large_v3.m3u8",
        $self->{live_primary_hls},
        $channel_id, $channel_id, $channel_id
    );
    
    $self->log("Using direct URL: $url");
    
    # Set channel subdirectory
    $self->{current_channel_subdir}{$channel_id} = "HLS_${channel_id}_256k_v3";
    $self->{current_base_path}{$channel_id} = "/AAC_Data/$channel_id/HLS_${channel_id}_256k_v3";
    
    return $url;
}

sub get_playlist {
    my ($self, $name) = @_;
    
    $self->log("Getting playlist for channel: $name");
    
    # Find channel
    my ($guid, $channel_id) = $self->find_channel($name);
    if (!$guid || !$channel_id) {
        return undef;
    }
    
    # Ensure we're authenticated
    if (!$self->authenticate()) {
        $self->log("Failed to authenticate for playlist");
        return undef;
    }
    
    # Get a direct stream URL (simplest approach)
    my $url = $self->get_direct_stream_url($channel_id);
    if (!$url) {
        return undef;
    }
    
    # Set up parameters
    my $token = $self->get_token();
    my $gup_id = $self->get_gup_id();
    
    if (!$token) {
        $self->log("Missing token for playlist");
        return undef;
    }
    
    my $params = {
        token => $token,
        consumer => 'k2',
        gupId => $gup_id,
    };
    
    my $uri = URI->new($url);
    $uri->query_form($params);
    
    $self->log("Requesting playlist: $uri");
    my $response = $self->{ua}->get($uri);
    
    if ($response->code != 200) {
        # Try to re-authenticate if we get a 403
        if ($response->code == 403) {
            $self->log("Received 403, attempting to re-authenticate");
            if ($self->authenticate(1)) {  # Force authentication
                $token = $self->get_token();
                $params = {
                    token => $token,
                    consumer => 'k2',
                    gupId => $gup_id,
                };
                $uri->query_form($params);
                
                $self->debug("Retrying with new auth: $uri");
                $response = $self->{ua}->get($uri);
            }
        }
        
        if ($response->code != 200) {
            $self->log("Failed to get playlist: " . $response->code);
            return undef;
        }
    }
    
    my $content = $response->decoded_content;
    $self->debug("Got playlist: " . length($content) . " bytes");
    
    # Modify the playlist to include the base path
    my $base_path = $self->{current_base_path}{$channel_id} || '';
    $self->log("Base path for segments: $base_path");
    
    if ($base_path) {
        my @lines = split(/\n/, $content);
        my @modified_lines;
        
        foreach my $line (@lines) {
            if ($line =~ /\.aac$/ && $line !~ /^\//) {
                $line = "$base_path/$line";
            }
            push @modified_lines, $line;
        }
        
        $content = join("\n", @modified_lines);
    }
    
    return $content;
}

sub get_segment {
    my ($self, $path) = @_;
    
    $self->debug("Getting segment: $path");
    
    # If this is just a filename without path, try to construct path
    if ($path !~ m|/| && $self->{current_channel_id}) {
        my $channel_id = $self->{current_channel_id};
        my $base_path = $self->{current_base_path}{$channel_id} || '';
        
        if ($base_path) {
            $path = "$base_path/$path";
        }
    }
    
    # Construct full URL
    my $url;
    if ($path =~ /^\//) {
        $url = $self->{live_primary_hls} . $path;
    } else {
        $url = $self->{live_primary_hls} . '/' . $path;
    }
    
    # Set up parameters
    my $token = $self->get_token();
    my $gup_id = $self->get_gup_id();
    
    if (!$token) {
        $self->log("Missing token for segment");
        $self->{segment_errors}++;
        return undef;
    }
    
    my $params = {
        token => $token,
        consumer => 'k2',
        gupId => $gup_id,
    };
    
    my $uri = URI->new($url);
    $uri->query_form($params);
    
    $self->debug("Requesting segment: $uri");
    my $response = $self->{ua}->get($uri);
    
    if ($response->code == 200) {
        # Success - reset error counter
        $self->{segment_errors} = 0;
        $self->debug("Got segment: " . length($response->content) . " bytes");
        return $response->content;
    } 
    elsif ($response->code == 403) {
        # Increment error counter
        $self->{segment_errors}++;
        
        $self->log("Received 403 for segment (errors: $self->{segment_errors}/$self->{max_segment_errors})");
        
        # Re-authenticate if error threshold reached
        if ($self->{segment_errors} >= $self->{max_segment_errors}) {
            $self->log("Error threshold reached, re-authenticating");
            
            if ($self->authenticate(1)) {  # Force authentication
                $token = $self->get_token();
                $params = {
                    token => $token,
                    consumer => 'k2',
                    gupId => $gup_id,
                };
                $uri->query_form($params);
                
                $self->debug("Retrying segment with new auth: $uri");
                $response = $self->{ua}->get($uri);
                
                if ($response->code == 200) {
                    # Success after re-auth
                    $self->{segment_errors} = 0;
                    $self->debug("Got segment after re-auth: " . length($response->content) . " bytes");
                    return $response->content;
                }
            }
        }
    }
    else {
        # Other error
        $self->{segment_errors}++;
        $self->log("Failed to get segment: " . $response->code);
    }
    
    return undef;
}

package main;

# Check if credentials are provided
if (!$username || !$password) {
    print "Error: Username and password are required\n";
    print "Usage: $0 [options] username password\n";
    print "       $0 -e (to use environment variables SXM_USER and SXM_PASS)\n";
    exit 1;
}

# Create the SiriusXM object with debug flag if needed
my $sxm = SiriusXM->new($username, $password, $canada ? 'CA' : 'US', $debug);

if ($list) {
    my $channels = $sxm->get_channel_list();
    
    if (!$channels || @$channels == 0) {
        print "No channels found. Check your credentials and try again.\n";
        exit 1;
    }
    
    # Sort channels
    my @sorted_channels = sort {
        (int($a->{siriusChannelNumber} // 9999) <=> int($b->{siriusChannelNumber} // 9999))
    } @$channels;
    
    # Display channels
    printf "%-20s | %-5s | %-30s\n", "ID", "Num", "Name";
    print "-" x 20 . "-+-" . "-" x 5 . "-+-" . "-" x 30 . "\n";
    
    foreach my $channel (@sorted_channels) {
        printf "%-20s | %-5s | %-30s\n", 
            substr($channel->{channelId} // '', 0, 20),
            substr($channel->{siriusChannelNumber} // '', 0, 5),
            substr($channel->{name} // '', 0, 30);
    }
} else {
    # Create HTTP server
    my $HLS_AES_KEY = decode_base64('0Nsco7MAgxowGvkUT8aYag==');
    my $daemon = HTTP::Daemon->new(
        LocalAddr => '0.0.0.0',
        LocalPort => $port,
        ReuseAddr => 1,
    ) or die "Cannot create HTTP daemon: $!";
    
    print "Server started at http://localhost:$port/\n";
    print "Press Ctrl+C to exit\n";
    
    # Ignore SIGPIPE to prevent the server from crashing
    $SIG{PIPE} = 'IGNORE';
    
    # Main loop
    while (1) {
        my $connection = $daemon->accept;
        next unless $connection;
        
        # Simple approach: handle each request separately
        my $request = $connection->get_request;
        if (!$request) {
            $connection->close;
            next;
        }
        
        my $path = $request->uri->path;
        print "Request: $path\n";
        
        if ($path =~ /\.m3u8$/) {
            my ($channel_name) = $path =~ m|/([^/]+)\.m3u8$|;
            print "Channel request for: $channel_name\n";
            
            my $data = $sxm->get_playlist($channel_name);
            
            if ($data) {
                my $response = HTTP::Response->new(200);
                $response->header('Content-Type' => 'application/x-mpegURL');
                $response->content($data);
                $connection->send_response($response);
                print "Playlist sent successfully\n";
            } else {
                my $response = HTTP::Response->new(500);
                $response->header('Content-Type' => 'text/plain');
                $response->content("Error getting playlist");
                $connection->send_response($response);
                print "Failed to get playlist\n";
            }
        }
        elsif ($path =~ /\.aac$/) {
            my $segment_path = substr($path, 1); # Remove leading slash
            print "Segment request for: $segment_path\n";
            
            my $data = $sxm->get_segment($segment_path);
            
            if ($data) {
                my $response = HTTP::Response->new(200);
                $response->header('Content-Type' => 'audio/x-aac');
                $response->content($data);
                $connection->send_response($response);
                print "Segment sent: " . length($data) . " bytes\n";
            } else {
                my $response = HTTP::Response->new(500);
                $response->header('Content-Type' => 'text/plain');
                $response->content("Error getting segment");
                $connection->send_response($response);
                print "Failed to get segment\n";
            }
        }
        elsif ($path =~ /\/key\/1$/) {
            my $response = HTTP::Response->new(200);
            $response->header('Content-Type' => 'text/plain');
            $response->content($HLS_AES_KEY);
            $connection->send_response($response);
            print "Key sent\n";
        }
        elsif ($path eq "/stats") {
            my $now = time();
            my $auth_age = $now - $sxm->{last_auth_time};
            
            my $response = HTTP::Response->new(200);
            $response->header('Content-Type' => 'text/html');
            my $html = "<html><body><h1>SiriusXM Proxy Stats</h1>";
            $html .= "<p>Authentication count: " . $sxm->{auth_count} . "</p>";
            $html .= "<p>Last authentication: " . ($auth_age > 0 ? sprintf("%.1f minutes ago", $auth_age/60) : "Never") . "</p>";
            $html .= "<p>Segment errors: " . $sxm->{segment_errors} . " / " . $sxm->{max_segment_errors} . "</p>";
            $html .= "<p><a href='/auth'>Force Authentication</a></p>";
            $html .= "</body></html>";
            $response->content($html);
            $connection->send_response($response);
        }
        elsif ($path eq "/auth") {
            # Force authentication
            my $success = $sxm->authenticate(1);  # Force authentication
            
            my $response = HTTP::Response->new(200);
            $response->header('Content-Type' => 'text/html');
            my $html = "<html><body><h1>SiriusXM Authentication</h1>";
            $html .= "<p>Authentication " . ($success ? "successful" : "failed") . "</p>";
            $html .= "<p>Total auth count: " . $sxm->{auth_count} . "</p>";
            $html .= "<p><a href='/'>Back to Home</a></p>";
            $html .= "</body></html>";
            $response->content($html);
            $connection->send_response($response);
        }
        else {
            my $response = HTTP::Response->new(200);
            $response->header('Content-Type' => 'text/html');
            my $html = "<html><body><h1>SiriusXM Proxy</h1>";
            $html .= "<p>Use format: http://localhost:$port/CHANNEL_ID.m3u8</p>";
            $html .= "<p><a href='/stats'>View Stats</a></p>";
            $html .= "</body></html>";
            $response->content($html);
            $connection->send_response($response);
        }
        
        # Close connection after each request
        $connection->close;
        print "Connection closed, waiting for next request\n";
    }
}
