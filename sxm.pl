#!/usr/bin/env perl

use strict;
use warnings;
use Getopt::Long;
use HTTP::Daemon;
use HTTP::Status;
use HTTP::Response;
use LWP::UserAgent;
use JSON::XS;
use MIME::Base64;
use URI::Escape;
use DateTime;
use DateTime::TimeZone;
use Data::Dumper;
use HTTP::Cookies;
use Time::HiRes qw(time);

# Define HTTP status codes directly
use constant {
    HTTP_OK => 200,
    HTTP_FORBIDDEN => 403,
    HTTP_INTERNAL_SERVER_ERROR => 500
};

# Parse command line arguments
my ($list, $port, $canada, $env, $debug, $help);
my $username = "";
my $password = "";

GetOptions(
    "list|l" => \$list,
    "port|p=i" => \$port,
    "canada|ca" => \$canada,
    "env|e" => \$env,
    "debug|d+" => \$debug,  # Allow -d -d -d for increased debug levels
    "help|h" => \$help,
) or die "Error in command line arguments\n";

if ($help) {
    print "SiriusXM proxy\n\n";
    print "usage: sxm.pl [options] username password\n\n";
    print "positional arguments:\n";
    print "  username              SiriusXM username\n";
    print "  password              SiriusXM password\n\n";
    print "options:\n";
    print "  -h, --help            show this help message and exit\n";
    print "  -l, --list            list available channels\n";
    print "  -p PORT, --port PORT  set server port (default: 9999)\n";
    print "  -ca, --canada         use Canadian region\n";
    print "  -e, --env             use credentials from environment variables\n";
    print "  -d, --debug           enable debug output (repeat for more detail)\n";
    exit 0;
}

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
use URI::Escape qw(uri_escape uri_unescape);
use Time::HiRes qw(time);
use JSON::XS;
use Data::Dumper;

# Define HTTP status codes for the class
use constant {
    HTTP_OK => 200,
    HTTP_FORBIDDEN => 403,
    HTTP_NOT_FOUND => 404,
    HTTP_TIMEOUT => 408
};

sub new {
    my ($class, $username, $password, $region, $debug) = @_;
    
    my $ua = LWP::UserAgent->new;
    $ua->cookie_jar(HTTP::Cookies->new(file => "$ENV{HOME}/.sxm_cookies.txt", autosave => 1));
    $ua->agent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/604.5.6 (KHTML, like Gecko) Version/11.0.3 Safari/604.5.6');
    $ua->default_header('Accept' => '*/*');
    $ua->default_header('Accept-Language' => 'en-US,en;q=0.9');
    $ua->default_header('Origin' => 'https://player.siriusxm.com');
    $ua->default_header('Referer' => 'https://player.siriusxm.com/');
    
    # Set reasonable timeout values
    $ua->timeout(20);  # 20 seconds for overall timeout
    $ua->conn_cache(undef);  # Disable connection caching to avoid stale connections
    
    # Fallback hardcoded gupId in case we can't get it from cookies
    # This is used by the Python script and might still work
    my $fallback_gupid = "35eb99d100800000";
    
    my $self = {
        ua => $ua,
        username => $username,
        password => $password,
        region => $region || 'US',
        debug => $debug || 0,
        playlists => {},
        channels => undef,
        current_channel_id => undef, # Track the current channel being played
        current_channel_subdir => {}, # Store the current subdirectory for each channel
        current_base_path => {},      # Store the full base path for each channel
        rest_format => 'https://player.siriusxm.com/rest/v2/experience/modules/%s',
        live_primary_hls => 'https://siriusxm-priprodlive.akamaized.net',
        fallback_gupid => $fallback_gupid,
        extracted_gupid => undef,
        tokens => {}, # Store tokens keyed by timestamp to manage token rotation
        last_auth_time => 0, # Time of last authentication
        segment_errors => 0, # Counter for consecutive segment errors
        max_segment_errors => 5, # Max consecutive errors before re-authenticating
    };
    
    return bless $self, $class;
}

sub log {
    my ($self, $msg) = @_;
    my $dt = DateTime->now(time_zone => 'UTC');
    printf "%s <SiriusXM>: %s\n", $dt->strftime('%d.%b %Y %H:%M:%S'), $msg;
}

sub debug {
    my ($self, $msg, $level) = @_;
    $level //= 1;  # Default debug level is 1
    return unless $self->{debug} >= $level;
    my $dt = DateTime->now(time_zone => 'UTC');
    printf "%s <SiriusXM DEBUG L%d>: %s\n", $dt->strftime('%d.%b %Y %H:%M:%S'), $level, $msg;
}

sub is_logged_in {
    my $self = shift;
    my $cookies = $self->{ua}->cookie_jar->as_string;
    $self->debug("Cookie jar: $cookies", 3); # Changed to level 3
    return ($cookies =~ /SXMDATA=/);
}

sub is_session_authenticated {
    my $self = shift;
    my $cookies = $self->{ua}->cookie_jar->as_string;
    $self->debug("Cookie jar: $cookies", 3); # Changed to level 3
    return ($cookies =~ /AWSALB=/ && $cookies =~ /JSESSIONID=/);
}

sub should_refresh_authentication {
    my $self = shift;
    
    # Refresh auth if it's been more than 10 minutes since last auth
    # or if we've had too many consecutive segment errors
    my $now = time();
    my $auth_age = $now - $self->{last_auth_time};
    my $refresh_needed = ($auth_age > 600) || ($self->{segment_errors} >= $self->{max_segment_errors});
    
    if ($refresh_needed) {
        $self->debug(sprintf("Auth refresh needed - age: %.1f seconds, errors: %d/%d", 
                              $auth_age, $self->{segment_errors}, $self->{max_segment_errors}));
    }
    
    return $refresh_needed;
}

sub get {
    my ($self, $method, $params, $authenticate) = @_;
    $authenticate = defined $authenticate ? $authenticate : 1;
    
    if ($authenticate && 
        (!$self->is_session_authenticated || $self->should_refresh_authentication) && 
        !$self->authenticate) {
        $self->log('Unable to authenticate');
        return undef;
    }
    
    my $url = sprintf($self->{rest_format}, $method);
    my $uri = URI->new($url);
    $uri->query_form($params);
    
    $self->debug("GET $uri");
    
    my $start_time = time();
    my $response = $self->{ua}->get($uri);
    my $elapsed = time() - $start_time;
    
    $self->debug(sprintf("GET completed in %.2f seconds with status %d", $elapsed, $response->code));
    
    if ($response->code != HTTP_OK) {
        $self->log(sprintf('Received status code %d for method \'%s\'', $response->code, $method));
        $self->debug("Response: " . $response->as_string, 2);
        return undef;
    }
    
    my $json;
    eval {
        $json = decode_json($response->decoded_content);
    };
    if ($@) {
        $self->log(sprintf('Error decoding json for method \'%s\': %s', $method, $@));
        $self->debug("Response content: " . substr($response->decoded_content, 0, 200) . "...", 2);
        return undef;
    }
    
    $self->debug("Response JSON: " . Dumper($json), 3);
    return $json;
}

sub post {
    my ($self, $method, $postdata, $authenticate) = @_;
    $authenticate = defined $authenticate ? $authenticate : 1;
    
    if ($authenticate && 
        (!$self->is_session_authenticated || $self->should_refresh_authentication) && 
        !$self->authenticate) {
        $self->log('Unable to authenticate');
        return undef;
    }
    
    my $url = sprintf($self->{rest_format}, $method);
    my $req = HTTP::Request->new('POST', $url);
    $req->header('Content-Type' => 'application/json');
    $req->header('Accept' => '*/*');
    $req->header('Origin' => 'https://player.siriusxm.com');
    $req->header('Referer' => 'https://player.siriusxm.com/');
    
    my $json_content = encode_json($postdata);
    $req->content($json_content);
    
    $self->debug("POST $url");
    $self->debug("POST data: $json_content", 2);
    
    my $start_time = time();
    my $response = $self->{ua}->request($req);
    my $elapsed = time() - $start_time;
    
    $self->debug(sprintf("POST completed in %.2f seconds with status %d", $elapsed, $response->code));
    
    if ($response->code != HTTP_OK) {
        $self->log(sprintf('Received status code %d for method \'%s\'', $response->code, $method));
        $self->debug("Response: " . $response->as_string, 2);
        return undef;
    }
    
    my $json;
    eval {
        $json = decode_json($response->decoded_content);
    };
    if ($@) {
        $self->log(sprintf('Error decoding json for method \'%s\': %s', $method, $@));
        $self->debug("Response content: " . substr($response->decoded_content, 0, 200) . "...", 2);
        return undef;
    }
    
    $self->debug("Response JSON: " . Dumper($json), 3);
    return $json;
}

sub login {
    my $self = shift;
    
    $self->log("Attempting login with username: " . $self->{username});
    
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
    
    my $data = $self->post('modify/authentication', $postdata, 0);
    if (!$data) {
        $self->log('Login failed - no response data');
        return 0;
    }
    
    eval {
        my $status = $data->{ModuleListResponse}{status};
        my $messages = $data->{ModuleListResponse}{messages};
        
        if ($status != 1) {
            my $message = $messages->[0]{message} || "Unknown error";
            my $code = $messages->[0]{code} || "??";
            $self->log("Login failed - status: $status, message: $message, code: $code");
            return 0;
        }
        
        # Try to extract the gupId directly from the response
        my $consumer_info = $data->{ModuleListResponse}{moduleList}{modules}[0]{moduleResponse}{consumerInfo};
        if ($consumer_info && $consumer_info->{guPId}) {
            $self->{extracted_gupid} = $consumer_info->{guPId};
            $self->debug("Extracted gupId from login response: " . $self->{extracted_gupid});
        }
        
        # Also extract from SXMDATA cookie if available
        $self->extract_gupid_from_cookie();
        
        # Store the current SXMAK token
        $self->update_token();
        
        # Update authentication time
        $self->{last_auth_time} = time();
        
        if ($self->is_logged_in) {
            $self->log("Login successful");
            $self->{segment_errors} = 0;  # Reset segment error counter
            return 1;
        } else {
            $self->log("Login failed - not logged in after API success");
            return 0;
        }
    };
    if ($@) {
        $self->log("Error processing login response: $@");
        return 0;
    }
    
    return $self->is_logged_in;
}

sub authenticate {
    my $self = shift;
    
    if (!$self->is_logged_in && !$self->login) {
        $self->log('Unable to authenticate because login failed');
        return 0;
    }
    
    $self->log("Attempting authentication");
    
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
    
    my $data = $self->post('resume?OAtrial=false', $postdata, 0);
    if (!$data) {
        $self->log('Authentication failed - no response data');
        return 0;
    }
    
    eval {
        my $status = $data->{ModuleListResponse}{status};
        my $messages = $data->{ModuleListResponse}{messages};
        
        if ($status != 1) {
            my $message = $messages->[0]{message} || "Unknown error";
            my $code = $messages->[0]{code} || "??";
            $self->log("Authentication failed - status: $status, message: $message, code: $code");
            return 0;
        }
        
        # Try to extract the gupId directly from the response
        my $consumer_info = $data->{ModuleListResponse}{moduleList}{modules}[0]{moduleResponse}{consumerInfo};
        if ($consumer_info && $consumer_info->{guPId}) {
            $self->{extracted_gupid} = $consumer_info->{guPId};
            $self->debug("Extracted gupId from auth response: " . $self->{extracted_gupid});
        }
        
        # Also extract from SXMDATA cookie if available
        $self->extract_gupid_from_cookie();
        
        # Store the current SXMAK token
        $self->update_token();
        
        # Update authentication time and reset error counter
        $self->{last_auth_time} = time();
        $self->{segment_errors} = 0;
        
        if ($self->is_session_authenticated) {
            $self->log("Authentication successful");
            return 1;
        } else {
            $self->log("Authentication failed - session not authenticated after API success");
            return 0;
        }
    };
    if ($@) {
        $self->log("Error processing authentication response: $@");
        return 0;
    }
    
    return $self->is_session_authenticated;
}

sub extract_gupid_from_cookie {
    my $self = shift;
    
    my $cookies = $self->{ua}->cookie_jar->as_string;
    if ($cookies =~ /SXMDATA=([^;]+)/) {
        my $data = uri_unescape($1);
        eval {
            my $json = decode_json($data);
            if ($json->{gupId}) {
                $self->{extracted_gupid} = $json->{gupId};
                $self->debug("Extracted gupId from cookie: " . $self->{extracted_gupid});
            }
        };
        if ($@) {
            $self->debug("Error extracting gupId from cookie: $@");
        }
    }
}

sub update_token {
    my $self = shift;
    
    my $cookies = $self->{ua}->cookie_jar->as_string;
    if ($cookies =~ /SXMAKTOKEN=([^;]+)/) {
        my $token = $1;
        if ($token =~ /^([^=]+)=([^,]+)/) {
            my $time = time();
            $self->{tokens}{$time} = $2;
            $self->debug("Stored token at time $time: $2");
            
            # Clean up old tokens (keep only the last 5)
            my @times = sort { $b <=> $a } keys %{$self->{tokens}};
            if (@times > 5) {
                foreach my $t (@times[5..$#times]) {
                    delete $self->{tokens}{$t};
                }
            }
        }
    }
}

sub get_sxmak_token {
    my $self = shift;
    
    # Get the most recent token first
    my @times = sort { $b <=> $a } keys %{$self->{tokens}};
    if (@times) {
        $self->debug("Using most recent token from time $times[0]");
        return $self->{tokens}{$times[0]};
    }
    
    # Fall back to getting from cookie directly
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
    
    # First try to use the extracted gupId if available
    if ($self->{extracted_gupid}) {
        $self->debug("Using extracted gupId: " . $self->{extracted_gupid});
        return $self->{extracted_gupid};
    }
    
    # Try to extract it now if we haven't already
    $self->extract_gupid_from_cookie();
    if ($self->{extracted_gupid}) {
        $self->debug("Using newly extracted gupId: " . $self->{extracted_gupid});
        return $self->{extracted_gupid};
    }
    
    # Fall back to the hardcoded value
    $self->debug("Using fallback gupId: " . $self->{fallback_gupid});
    return $self->{fallback_gupid};
}

sub get_playlist_url {
    my ($self, $guid, $channel_id, $use_cache, $max_attempts) = @_;
    
    # Store current channel ID for context
    $self->{current_channel_id} = $channel_id;
    
    $use_cache = defined $use_cache ? $use_cache : 1;
    $max_attempts = defined $max_attempts ? $max_attempts : 5;
    
    if ($use_cache && exists $self->{playlists}{$channel_id}) {
        $self->debug("Using cached playlist URL for channel $channel_id", 2);
        return $self->{playlists}{$channel_id};
    }
    
    my $dt = DateTime->now(time_zone => 'UTC');
    my $params = {
        assetGUID => $guid,
        ccRequestType => 'AUDIO_VIDEO',
        channelId => $channel_id,
        hls_output_mode => 'custom',
        marker_mode => 'all_separate_cue_points',
        'result-template' => 'web',
        time => int(time() * 1000),
        timestamp => $dt->strftime('%Y-%m-%dT%H:%M:%S') . 'Z'
    };
    
    $self->debug("Getting playlist URL for channel $channel_id with GUID $guid");
    my $data = $self->get('tune/now-playing-live', $params);
    if (!$data) {
        $self->log("Failed to get playlist URL - no response data");
        return undef;
    }
    
    my ($status, $message, $message_code);
    eval {
        $status = $data->{ModuleListResponse}{status};
        $message = $data->{ModuleListResponse}{messages}[0]{message} // "Unknown message";
        $message_code = $data->{ModuleListResponse}{messages}[0]{code} // "Unknown code";
        $self->debug("API response status: $status, message: $message, code: $message_code");
    };
    if ($@) {
        $self->log("Error parsing JSON response for playlist: $@");
        return undef;
    }
    
    if ($message_code == 201 || $message_code == 208) {
        if ($max_attempts > 0) {
            $self->log('Session expired, logging in and authenticating');
            if ($self->authenticate) {
                $self->log('Successfully authenticated');
                return $self->get_playlist_url($guid, $channel_id, $use_cache, $max_attempts - 1);
            } else {
                $self->log('Failed to authenticate');
                return undef;
            }
        } else {
            $self->log('Reached max attempts for playlist');
            return undef;
        }
    } elsif ($message_code != 100) {
        $self->log("Received error $message_code $message");
        return undef;
    }
    
    my $playlists;
    eval {
        $playlists = $data->{ModuleListResponse}{moduleList}{modules}[0]{moduleResponse}{liveChannelData}{hlsAudioInfos};
        if (!$playlists) {
            $self->log("No hlsAudioInfos found in response");
            $self->debug("Module response structure: " . Dumper($data->{ModuleListResponse}{moduleList}{modules}[0]{moduleResponse}), 2);
            return undef;
        }
        $self->debug("Found " . scalar(@$playlists) . " playlist variants");
    };
    if ($@) {
        $self->log("Error parsing JSON response for playlist data: $@");
        return undef;
    }
    
    if (!$playlists || @$playlists == 0) {
        $self->log("No playlists found in response");
        $self->debug("Full response structure: " . Dumper($data), 2);
        return undef;
    }
    
    # Debug output of available playlists
    if ($self->{debug} >= 2) {
        foreach my $idx (0..$#$playlists) {
            my $p = $playlists->[$idx];
            $self->debug(sprintf("Playlist %d: size=%s url=%s", 
                $idx, $p->{size} // 'unknown', $p->{url} // 'unknown'), 2);
        }
    }
    
    # Try to find LARGE variant first, then any variant
    my $playlist_url;
    foreach my $playlist_info (@$playlists) {
        if (($playlist_info->{size} // '') eq 'LARGE') {
            $playlist_url = $playlist_info->{url};
            $self->debug("Found LARGE playlist URL: $playlist_url");
            last;
        }
    }
    
    # If no LARGE variant, use the first one
    if (!$playlist_url && @$playlists > 0) {
        $playlist_url = $playlists->[0]->{url};
        $self->debug("No LARGE variant found, using first available: $playlist_url");
    }
    
    if ($playlist_url) {
        $playlist_url =~ s/%Live_Primary_HLS%/$self->{live_primary_hls}/g;
        
        # First try normal variant URL retrieval
        my $variant_url = $self->get_playlist_variant_url($playlist_url, $channel_id);
        
        if (!$variant_url) {
            # If variant URL fails, try direct stream URLs
            $self->log("Failed to get playlist variant, trying direct stream URLs");
            $variant_url = $self->try_direct_stream_patterns($channel_id);
        }
        
        if ($variant_url) {
            $self->{playlists}{$channel_id} = $variant_url;
            return $variant_url;
        }
    }
    
    $self->log("No suitable playlist found");
    
    # As last resort, try direct stream patterns
    return $self->try_direct_stream_patterns($channel_id);
}

sub try_direct_stream_patterns {
    my ($self, $channel_id) = @_;
    
    # Common patterns for different channels
    my @formats = (
        # Format 1: Direct with channel name and bitrate
        "%s/AAC_Data/%s/HLS_%s_256k_v3/%s_256k_large_v3.m3u8",
        
        # Format 2: Numeric channel ID with bitrate
        "%s/AAC_Data/%s/%s_256k_large_v3.m3u8",
        
        # Format 3: Just channel ID and bitrate
        "%s/dhe/sxm-channel-%s/256k.m3u8",
        
        # Format 4: Channel ID with variant suffix
        "%s/dhe/sxm-channel-%s/%s_variant_large_v3.m3u8",
        
        # Format 5: Channel ID with subdirectory and variant
        "%s/dhe/sxm-channel-%s/HLS_%s_256k_v3/%s_256k_large_v3.m3u8",
    );
    
    foreach my $format (@formats) {
        my $url = sprintf(
            $format,
            $self->{live_primary_hls},
            $channel_id, $channel_id, $channel_id # Pass channel_id multiple times for the format
        );
        
        $self->debug("Trying direct URL pattern: $url");
        
        my $token = $self->get_sxmak_token;
        my $gup_id = $self->get_gup_id;
        
        my $params = {
            token => $token,
            consumer => 'k2',
            gupId => $gup_id,
        };
        
        my $uri = URI->new($url);
        $uri->query_form($params);
        
        my $response = $self->{ua}->head($uri);
        if ($response->is_success) {
            $self->log("Found working direct URL: $url");
            
            # Set subdirectory based on the pattern that worked
            if ($format =~ /HLS_.*?_256k_v3/) {
                $self->{current_channel_subdir}{$channel_id} = "HLS_${channel_id}_256k_v3";
                $self->{current_base_path}{$channel_id} = "/AAC_Data/$channel_id/HLS_${channel_id}_256k_v3";
            } else {
                # Extract the base path from the URL
                my $base_path = $url;
                $base_path =~ s|^$self->{live_primary_hls}||;
                $base_path =~ s|/[^/]+$||;
                $self->{current_base_path}{$channel_id} = $base_path;
                
                # Extract subdirectory if present
                if ($base_path =~ m|/([^/]+)$|) {
                    $self->{current_channel_subdir}{$channel_id} = $1;
                } else {
                    $self->{current_channel_subdir}{$channel_id} = '';
                }
            }
            
            return $url;
        }
    }
    
    $self->log("Could not find any working direct stream URL");
    return undef;
}

sub get_playlist_variant_url {
    my ($self, $url, $channel_id, $max_attempts) = @_;
    $max_attempts = defined $max_attempts ? $max_attempts : 3;
    
    my $token = $self->get_sxmak_token;
    my $gup_id = $self->get_gup_id;
    
    if (!$token) {
        $self->log("Missing token for playlist variant request");
        return undef;
    }
    
    # Always have a gup_id now because of fallback
    
    my $params = {
        token => $token,
        consumer => 'k2',
        gupId => $gup_id,
    };
    
    my $uri = URI->new($url);
    $uri->query_form($params);
    
    $self->debug("Getting playlist variant URL: $uri");
    
    my $start_time = time();
    my $response = $self->{ua}->get($uri);
    my $elapsed = time() - $start_time;
    
    $self->debug(sprintf("Got playlist variant in %.2f seconds with status %d", $elapsed, $response->code));
    
    if ($response->code == HTTP_FORBIDDEN) {
        if ($max_attempts > 0) {
            $self->log("Received 403 on variant URL, re-authenticating and trying again");
            $self->authenticate();
            return $self->get_playlist_variant_url($url, $channel_id, $max_attempts - 1);
        } else {
            $self->log("Max attempts reached for playlist variant URL");
            return undef;
        }
    }
    
    if ($response->code != HTTP_OK) {
        $self->log(sprintf('Received status code %d on playlist variant retrieval', $response->code));
        $self->debug("Response: " . $response->as_string, 2);
        return undef;
    }
    
    my $content = $response->decoded_content;
    $self->debug("Variant playlist content: " . substr($content, 0, 200) . "...", 3);
    
    my @lines = split(/\n/, $content);
    
    # This pattern matches m3u8 files INCLUDING those in subdirectories
    foreach my $line (@lines) {
        $self->debug("Variant line: $line", 3);
        if ($line =~ /\.m3u8/) {  # Changed to match any .m3u8 file, including in subdirectories
            my $base_url = $url;
            $base_url =~ s/\/[^\/]+$//;
            my $variant_url = "$base_url/$line";
            $self->debug("Found variant URL: $variant_url");
            
            # Extract the subdirectory path if there is one
            if ($line =~ m|^(.*)/|) {
                $self->{current_channel_subdir}{$channel_id} = $1;
                $self->log("Set channel $channel_id subdirectory to: " . $self->{current_channel_subdir}{$channel_id});
            } else {
                $self->{current_channel_subdir}{$channel_id} = "";
            }
            
            # Extract the base path from the URL for later segment requests
            my $base_path = $variant_url;
            $base_path =~ s|^$self->{live_primary_hls}||;  # Remove host
            $base_path =~ s|/[^/]+$||;  # Remove filename
            $self->{current_base_path}{$channel_id} = $base_path;
            $self->debug("Set base path for channel $channel_id to: " . $base_path);
            
            # Try if the URL works
            my $var_uri = URI->new($variant_url);
            $var_uri->query_form($params);
            my $var_response = $self->{ua}->head($var_uri);
            if ($var_response->is_success) {
                $self->debug("Verified variant URL works: $variant_url");
                return $variant_url;
            } else {
                $self->debug("Variant URL failed with status " . $var_response->status_line . ": $variant_url");
            }
        }
    }
    
    # If we didn't find a working variant, pick the first one anyway as last resort
    foreach my $line (@lines) {
        if ($line =~ /\.m3u8/) {
            my $base_url = $url;
            $base_url =~ s/\/[^\/]+$//;
            my $variant_url = "$base_url/$line";
            
            # Extract the subdirectory path if there is one
            if ($line =~ m|^(.*)/|) {
                $self->{current_channel_subdir}{$channel_id} = $1;
                $self->log("Set channel $channel_id subdirectory to: " . $self->{current_channel_subdir}{$channel_id});
            } else {
                $self->{current_channel_subdir}{$channel_id} = "";
            }
            
            # Extract the base path from the URL for later segment requests
            my $base_path = $variant_url;
            $base_path =~ s|^$self->{live_primary_hls}||;  # Remove host
            $base_path =~ s|/[^/]+$||;  # Remove filename
            $self->{current_base_path}{$channel_id} = $base_path;
            $self->debug("Set base path for channel $channel_id to: " . $base_path);
            
            $self->log("Using first variant as last resort: $variant_url");
            return $variant_url;
        }
    }
    
    $self->log("No suitable variant found in playlist");
    $self->debug("Full playlist content: $content", 2);
    return undef;
}

sub get_direct_stream_url {
    my ($self, $channel_id) = @_;
    
    # Store current channel ID for context
    $self->{current_channel_id} = $channel_id;
    
    # Try direct stream patterns first
    my $url = $self->try_direct_stream_patterns($channel_id);
    if ($url) {
        return $url;
    }
    
    # Otherwise try older formats
    my @formats = (
        # Format 1: Old style with channel ID
        "%s/ch%s/%s/master.m3u8",
        
        # Format 2: Even older format
        "%s/sxm%s/%s/master.m3u8"
    );
    
    my @bitrates = ('256k', '128k', '64k', 'high');
    
    for my $i (0..1) {
        foreach my $bitrate (@bitrates) {
            my $url = sprintf(
                $formats[$i],
                $self->{live_primary_hls},
                $channel_id,
                $bitrate
            );
            
            $self->debug("Trying direct stream URL format " . ($i+1) . ": $url");
            
            my $test_uri = URI->new($url);
            $test_uri->query_form({
                token => $self->get_sxmak_token,
                consumer => 'k2',
                gupId => $self->get_gup_id,
            });
            
            my $response = $self->{ua}->head($test_uri);
            if ($response->is_success) {
                $self->log("Found working direct stream URL format " . ($i+1) . ": $url");
                $self->{current_channel_subdir}{$channel_id} = "";
                return $url;
            }
        }
    }
    
    $self->log("Could not find working direct stream URL");
    return undef;
}

sub get_playlist {
    my ($self, $name, $use_cache) = @_;
    $use_cache = defined $use_cache ? $use_cache : 1;
    
    $self->debug("Getting playlist for channel: $name");
    my ($guid, $channel_id) = $self->get_channel($name);
    if (!$guid || !$channel_id) {
        $self->log("No channel found for $name");
        return undef;
    }
    
    # Store current channel ID for context
    $self->{current_channel_id} = $channel_id;
    
    $self->debug("Found channel: ID=$channel_id, GUID=$guid");
    
    # Make sure we're authenticated
    if (!$self->authenticate()) {
        $self->log("Authentication failed, can't get playlist");
        return undef;
    }
    
    # First try the API-based method to get the playlist URL
    my $url = $self->get_playlist_url($guid, $channel_id, $use_cache);
    
    # If that fails, try direct stream URLs
    if (!$url) {
        $self->log("Failed to get playlist URL using standard method, trying direct stream URL");
        $url = $self->get_direct_stream_url($channel_id);
        if (!$url) {
            $self->log("Failed to get direct stream URL");
            return undef;
        }
    }
    
    my $token = $self->get_sxmak_token;
    my $gup_id = $self->get_gup_id;
    
    if (!$token) {
        $self->log("Missing token for playlist request");
        return undef;
    }
    
    my $params = {
        token => $token,
        consumer => 'k2',
        gupId => $gup_id,
    };
    
    my $uri = URI->new($url);
    $uri->query_form($params);
    
    $self->debug("Requesting playlist: $uri");
    
    my $start_time = time();
    my $response = $self->{ua}->get($uri);
    my $elapsed = time() - $start_time;
    
    $self->debug(sprintf("Got playlist in %.2f seconds with status %d", $elapsed, $response->code));
    
    if ($response->code == HTTP_FORBIDDEN) {
        $self->log('Received status code 403 on playlist, renewing session');
        if ($self->authenticate) {
            # Update token
            $token = $self->get_sxmak_token;
            $gup_id = $self->get_gup_id;
            
            $params = {
                token => $token,
                consumer => 'k2',
                gupId => $gup_id,
            };
            
            $uri = URI->new($url);
            $uri->query_form($params);
            
            $self->debug("Retrying playlist with new auth: $uri");
            $response = $self->{ua}->get($uri);
            
            if ($response->code != HTTP_OK) {
                $self->log('Still failed after authentication renewal');
                return undef;
            }
        } else {
            $self->log('Failed to renew session');
            return undef;
        }
    }
    
    if ($response->code != HTTP_OK) {
        $self->log(sprintf('Received status code %d on playlist', $response->code));
        $self->debug("Response: " . $response->as_string, 2);
        return undef;
    }
    
    my $content = $response->decoded_content;
    $self->debug("Playlist content: " . substr($content, 0, 200) . "...", 3);
    
    # Add base path to segments
    my $base_url = $url;
    $base_url =~ s/\/[^\/]+$//;
    my $base_path = $base_url;
    $base_path =~ s/^https?:\/\/[^\/]+//;
    
    $self->debug("Base path for segments: $base_path");
    # Store the base path for this channel for later use
    $self->{current_base_path}{$channel_id} = $base_path;
    
    my @lines = split(/\n/, $content);
    
    # Determine the subdirectory to use
    my $subdir = $self->{current_channel_subdir}{$channel_id} || '';
    
    for my $i (0..$#lines) {
        if ($lines[$i] =~ /\.aac$/) {
            $self->debug("Original segment: $lines[$i]", 3);
            # Don't modify if it already has a path
            if ($lines[$i] !~ /^\//) {
                # Make sure we include the subdirectory if needed
                if ($subdir) {
                    $lines[$i] = "$base_path/$subdir/$lines[$i]";
                } else {
                    $lines[$i] = "$base_path/$lines[$i]";
                }
                $self->debug("Modified segment: $lines[$i]", 3);
            }
        }
    }
    
    return join("\n", @lines);
}

sub get_segment {
    my ($self, $path, $max_attempts) = @_;
    $max_attempts = defined $max_attempts ? $max_attempts : 5;
    
    $self->debug("Original segment path: $path", 2);
    
    # If this is just a filename without path, try to construct complete path
    if ($path !~ m|/| && $self->{current_channel_id}) {
        my $channel_id = $self->{current_channel_id};
        my $base_path = $self->{current_base_path}{$channel_id} || '';
        
        # From the debug output you shared, the path should be:
        # /AAC_Data/9450/HLS_9450_256k_v3/segment_filename.aac
        my $full_path;
        
        if ($base_path) {
            # Use the recorded base path
            $full_path = "$base_path/$path";
            $self->debug("Using base path from playlist: $full_path");
        } else {
            # Try to construct a path based on channel ID
            my $subdir = $self->{current_channel_subdir}{$channel_id} || '';
            if ($subdir) {
                # Use the full path structure seen in your debug
                $full_path = "/AAC_Data/$channel_id/$subdir/$path";
            } else {
                # Fall back to just the path
                $full_path = $path;
            }
            $self->debug("Constructed segment path: $full_path");
        }
        
        $path = $full_path;
    }
    
    my $url = "$self->{live_primary_hls}$path";
    if ($path =~ /^\//) {
        $url = "$self->{live_primary_hls}$path";
    } else {
        $url = "$self->{live_primary_hls}/$path";
    }
    
    my $token = $self->get_sxmak_token;
    my $gup_id = $self->get_gup_id;
    
    if (!$token) {
        $self->log("Missing token for segment request");
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
    
    $self->debug("Getting segment: $uri");
    
    my $start_time = time();
    my $response = $self->{ua}->get($uri);
    my $elapsed = time() - $start_time;
    
    $self->debug(sprintf("Got segment in %.2f seconds with status %d", $elapsed, $response->code));
    
    if ($response->code == HTTP_FORBIDDEN) {
        $self->{segment_errors}++;
        
        if ($max_attempts > 0) {
            $self->log(sprintf('Received status code 403 on segment, renewing session (errors: %d/%d)', 
                               $self->{segment_errors}, $self->{max_segment_errors}));
            
            if ($self->{segment_errors} >= $self->{max_segment_errors} && $self->authenticate) {
                # Reset error counter after successful authentication
                $self->{segment_errors} = 0;
                
                # Update token after authentication
                $token = $self->get_sxmak_token;
                $gup_id = $self->get_gup_id;
                
                $params = {
                    token => $token,
                    consumer => 'k2',
                    gupId => $gup_id,
                };
                
                $uri = URI->new($url);
                $uri->query_form($params);
                
                $self->debug("Retrying segment with new auth: $uri");
                $response = $self->{ua}->get($uri);
                
                if ($response->code == HTTP_OK) {
                    $self->debug("Successfully retrieved segment after auth renewal");
                    return $response->content;
                }
            }
            
            # Try a different URL pattern regardless of authentication
            return $self->get_segment($path, $max_attempts - 1);
        } else {
            $self->log('Received status code 403 on segment, max attempts exceeded');
            return undef;
        }
    } elsif ($response->code == HTTP_OK) {
        # Reset error counter on success
        $self->{segment_errors} = 0;
    } else {
        # Increment error counter for non-403 errors too
        $self->{segment_errors}++;
    }
    
    if ($response->code == HTTP_NOT_FOUND) {
        $self->log("Segment not found (404): $path");
        
        # Try alternate paths if we have a channel context
        if ($self->{current_channel_id} && $path =~ m|([^/]+)$|) {
            my $filename = $1;
            my $channel_id = $self->{current_channel_id};
            
            # Try these alternate path patterns:
            my @alt_paths = (
                "/AAC_Data/$channel_id/HLS_${channel_id}_256k_v3/$filename",
                "/$filename",
                "/HLS_${channel_id}_256k_v3/$filename",
            );
            
            foreach my $alt_path (@alt_paths) {
                if ($alt_path ne $path) {
                    $self->log("Trying alternative path: $alt_path");
                    my $result = $self->get_segment($alt_path, $max_attempts - 1);
                    return $result if $result;
                }
            }
        }
        
        return undef;
    }
    
    if ($response->code != HTTP_OK) {
        $self->log(sprintf('Received status code %d on segment', $response->code));
        $self->debug("Response: " . $response->as_string, 2);
        return undef;
    }
    
    $self->debug("Successfully retrieved segment: " . length($response->content) . " bytes");
    return $response->content;
}

sub get_channels {
    my $self = shift;
    
    # Download channel list if necessary
    if (!$self->{channels}) {
        $self->log("Fetching channel list");
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
        
        my $data = $self->post('get', $postdata);
        if (!$data) {
            $self->log('Unable to get channel list');
            return [];
        }
        
        eval {
            $self->{channels} = $data->{ModuleListResponse}{moduleList}{modules}[0]{moduleResponse}{contentData}{channelListing}{channels};
            $self->log(sprintf("Retrieved %d channels", scalar(@{$self->{channels}})));
        };
        if ($@) {
            $self->log("Error parsing JSON response for channels: $@");
            return [];
        }
    }
    
    return $self->{channels};
}

sub get_channel {
    my ($self, $name) = @_;
    $name = lc($name);
    
    $self->debug("Looking for channel: $name");
    my $channels = $self->get_channels();
    
    foreach my $channel (@$channels) {
        if (lc($channel->{name} // '') eq $name || 
            lc($channel->{channelId} // '') eq $name || 
            ($channel->{siriusChannelNumber} // '') eq $name) {
            $self->debug(sprintf("Found channel: %s (%s)", 
                $channel->{name} // 'Unknown', 
                $channel->{channelId} // 'Unknown'));
            return ($channel->{channelGuid}, $channel->{channelId});
        }
    }
    
    $self->log("Channel not found: $name");
    return (undef, undef);
}

package main;

# Check if credentials are provided
if (!$username || !$password) {
    print "Error: Username and password are required\n";
    print "Usage: $0 [options] username password\n";
    print "       $0 -e (to use environment variables SXM_USER and SXM_PASS)\n";
    print "Options:\n";
    print "  -l, --list          List available channels\n";
    print "  -p, --port PORT     Set server port (default: 9999)\n";
    print "  -ca, --canada       Use Canadian region\n";
    print "  -e, --env           Use credentials from environment variables\n";
    print "  -d, --debug         Enable debug output (repeat for more detail, e.g., -d -d -d)\n";
    exit 1;
}

# Create the SiriusXM object with debug flag if needed
my $sxm = SiriusXM->new($username, $password, $canada ? 'CA' : 'US', $debug);

if ($list) {
    my $channels = $sxm->get_channels();
    
    if (!$channels || @$channels == 0) {
        print "No channels found. Check your credentials and try again.\n";
        exit 1;
    }
    
    # Sort channels by favorites and channel number
    my @sorted_channels = sort {
        (!$a->{isFavorite} <=> !$b->{isFavorite}) || 
        (int($a->{siriusChannelNumber} // 9999) <=> int($b->{siriusChannelNumber} // 9999))
    } @$channels;
    
    # Find column widths
    my $l1 = 2; # ID
    my $l2 = 3; # Num
    my $l3 = 4; # Name
    
    foreach my $channel (@sorted_channels) {
        my $id_len = length($channel->{channelId} // '');
        my $num_len = length($channel->{siriusChannelNumber} // '');
        my $name_len = length($channel->{name} // '');
        
        $l1 = $id_len if $id_len > $l1;
        $l2 = $num_len if $num_len > $l2;
        $l3 = $name_len if $name_len > $l3;
    }
    
    printf "%-${l1}s | %-${l2}s | %-${l3}s\n", "ID", "Num", "Name";
    print "-" x $l1 . "-+-" . "-" x $l2 . "-+-" . "-" x $l3 . "\n";
    
    foreach my $channel (@sorted_channels) {
        my $cid = substr(sprintf("%-${l1}s", $channel->{channelId} // ''), 0, $l1);
        my $cnum = substr(sprintf("%-${l2}s", $channel->{siriusChannelNumber} // '??'), 0, $l2);
        my $cname = substr(sprintf("%-${l3}s", $channel->{name} // '??'), 0, $l3);
        
        printf "%s | %s | %s\n", $cid, $cnum, $cname;
    }
} else {
    # Create HTTP server
    my $HLS_AES_KEY = decode_base64('0Nsco7MAgxowGvkUT8aYag==');
    my $daemon = HTTP::Daemon->new(
        LocalAddr => '0.0.0.0',
        LocalPort => $port,
        ReuseAddr => 1,
        Timeout => 10,  # 10 second timeout for connections
    ) or die "Cannot create HTTP daemon: $!";
    
    print "Server started at http://localhost:$port/\n";
    print "Press Ctrl+C to exit\n";
    
    while (my $connection = $daemon->accept) {
        while (my $request = $connection->get_request) {
            my $path = $request->uri->path;
            my $referer = $request->header('Referer') || "Unknown";
            my $user_agent = $request->header('User-Agent') || "Unknown";
            
            # Print full request info including URL requested by the player
            printf "Received request: %s %s\nReferer: %s\nUser-Agent: %s\n", 
                $request->method, $path, $referer, $user_agent if $debug;
            
            my $start_time = time();
            
            if ($path =~ /\.m3u8$/) {
                my ($channel_name) = $path =~ m|/([^/]+)\.m3u8$|;
                print "Channel request for: $channel_name\n" if $debug;
                
                my $data = $sxm->get_playlist($channel_name);
                
                if ($data) {
                    my $response = HTTP::Response->new(HTTP_OK);
                    $response->header('Content-Type' => 'application/x-mpegURL');
                    $response->content($data);
                    $connection->send_response($response);
                } else {
                    $connection->send_error(HTTP_INTERNAL_SERVER_ERROR);
                }
            } elsif ($path =~ /\.aac$/) {
                my $segment_path = substr($path, 1); # Remove leading slash
                my $data = $sxm->get_segment($segment_path);
                
                if ($data) {
                    my $response = HTTP::Response->new(HTTP_OK);
                    $response->header('Content-Type' => 'audio/x-aac');
                    $response->content($data);
                    $connection->send_response($response);
                } else {
                    $connection->send_error(HTTP_INTERNAL_SERVER_ERROR);
                }
            } elsif ($path =~ /\/key\/1$/) {
                my $response = HTTP::Response->new(HTTP_OK);
                $response->header('Content-Type' => 'text/plain');
                $response->content($HLS_AES_KEY);
                $connection->send_response($response);
            } else {
                # Send a simple HTML page with instructions
                my $response = HTTP::Response->new(HTTP_OK);
                $response->header('Content-Type' => 'text/html');
                my $html = <<EOT;
<!DOCTYPE html>
<html>
<head>
    <title>SiriusXM Proxy</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        h1 { color: #0066cc; }
        pre { background-color: #f0f0f0; padding: 10px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
    <h1>SiriusXM Proxy</h1>
    <p>Server is running. Use the following URL format to access a channel:</p>
    <pre>http://localhost:$port/CHANNEL_ID.m3u8</pre>
    <p>For example, to listen to channel "hits1":</p>
    <pre>http://localhost:$port/hits1.m3u8</pre>
    <p>You can use this URL in media players that support HLS streaming (VLC, mpv, etc.)</p>
</body>
</html>
EOT
                $response->content($html);
                $connection->send_response($response);
            }
            
            my $elapsed = time() - $start_time;
            if ($debug && $elapsed > 1.0) {
                printf "Request for %s took %.2f seconds\n", $path, $elapsed;
            }
        }
        $connection->close;
    }
}
