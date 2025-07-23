import argparse
import requests
import base64
import urllib.parse
import json
import time, datetime
import sys
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

class SiriusXM:
    USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/604.5.6 (KHTML, like Gecko) Version/11.0.3 Safari/604.5.6'
    REST_FORMAT = 'https://player.siriusxm.com/rest/v2/experience/modules/{}'
    LIVE_PRIMARY_HLS = 'https://siriusxm-priprodlive.akamaized.net'
    AUTH_FILE_PATH = os.path.expanduser('~/.sxm_auth.json')
    AUTH_TIMEOUT_MINUTES = 10

    def __init__(self, username, password, region):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.USER_AGENT})
        self.username = username
        self.password = password
        self.playlists = {}
        self.channels = None
        self.region = region
        self.last_auth_time = None
        
        # Load persisted authentication state
        self.load_auth_state()
        
        self.log('SiriusXM client initialized for region: {}'.format(region))

    @staticmethod
    def log(x):
        print('{} <SiriusXM>: {}'.format(datetime.datetime.now(datetime.UTC).strftime('%d.%b %Y %H:%M:%S'), x))
    
    def load_auth_state(self):
        """Load persisted authentication state from JSON file"""
        try:
            if os.path.exists(self.AUTH_FILE_PATH):
                with open(self.AUTH_FILE_PATH, 'r') as f:
                    auth_data = json.load(f)
                
                self.last_auth_time = auth_data.get('last_auth_time')
                cookies_data = auth_data.get('cookies', {})
                
                # Restore cookies to session
                for name, value in cookies_data.items():
                    self.session.cookies.set(name, value)
                
                if self.last_auth_time:
                    self.log('Loaded authentication state from {}, last auth: {}'.format(
                        self.AUTH_FILE_PATH, 
                        datetime.datetime.fromtimestamp(self.last_auth_time, datetime.UTC).strftime('%Y-%m-%d %H:%M:%S UTC')
                    ))
                else:
                    self.log('Loaded authentication state from {} (no previous auth time)'.format(self.AUTH_FILE_PATH))
            else:
                self.log('No existing authentication state found at {}'.format(self.AUTH_FILE_PATH))
        except Exception as e:
            self.log('Error loading authentication state: {}'.format(e))
            self.last_auth_time = None
    
    def save_auth_state(self):
        """Save current authentication state to JSON file"""
        try:
            auth_data = {
                'last_auth_time': self.last_auth_time,
                'cookies': dict(self.session.cookies)
            }
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.AUTH_FILE_PATH), exist_ok=True)
            
            # Write to temporary file first, then rename for atomicity
            temp_path = self.AUTH_FILE_PATH + '.tmp'
            with open(temp_path, 'w') as f:
                json.dump(auth_data, f, indent=2)
            os.rename(temp_path, self.AUTH_FILE_PATH)
            
            # Set restrictive file permissions
            os.chmod(self.AUTH_FILE_PATH, 0o600)
            
            self.log('Saved authentication state to {}'.format(self.AUTH_FILE_PATH))
        except Exception as e:
            self.log('Error saving authentication state: {}'.format(e))
    
    def should_refresh_authentication(self):
        """Check if authentication should be refreshed based on time elapsed"""
        if self.last_auth_time is None:
            self.log('No previous authentication time, refresh needed')
            return True
        
        elapsed_minutes = (time.time() - self.last_auth_time) / 60.0
        should_refresh = elapsed_minutes >= self.AUTH_TIMEOUT_MINUTES
        
        if should_refresh:
            self.log('Authentication timeout reached ({:.1f} minutes >= {} minutes), refresh needed'.format(
                elapsed_minutes, self.AUTH_TIMEOUT_MINUTES))
        else:
            self.log('Authentication still valid ({:.1f} minutes < {} minutes)'.format(
                elapsed_minutes, self.AUTH_TIMEOUT_MINUTES))
        
        return should_refresh

    def is_logged_in(self):
        return 'SXMDATA' in self.session.cookies

    def is_session_authenticated(self):
        return 'AWSALB' in self.session.cookies and 'JSESSIONID' in self.session.cookies

    def get(self, method, params, authenticate=True):
        if authenticate and (not self.is_session_authenticated() or self.should_refresh_authentication()):
            if not self.authenticate():
                self.log('Unable to authenticate')
                return None

        res = self.session.get(self.REST_FORMAT.format(method), params=params)
        if res.status_code != 200:
            self.log('Received status code {} for method \'{}\''.format(res.status_code, method))
            return None

        try:
            return res.json()
        except ValueError:
            self.log('Error decoding json for method \'{}\''.format(method))
            return None

    def post(self, method, postdata, authenticate=True):
        if authenticate and (not self.is_session_authenticated() or self.should_refresh_authentication()):
            if not self.authenticate():
                self.log('Unable to authenticate')
                return None

        res = self.session.post(self.REST_FORMAT.format(method), data=json.dumps(postdata))
        if res.status_code != 200:
            self.log('Received status code {} for method \'{}\''.format(res.status_code, method))
            return None

        try:
            return res.json()
        except ValueError:
            self.log('Error decoding json for method \'{}\''.format(method))
            return None

    def login(self):
        postdata = {
            'moduleList': {
                'modules': [{
                    'moduleRequest': {
                        'resultTemplate': 'web',
                        'deviceInfo': {
                            'osVersion': 'Mac',
                            'platform': 'Web',
                            'sxmAppVersion': '3.1802.10011.0',
                            'browser': 'Safari',
                            'browserVersion': '11.0.3',
                            'appRegion': self.region,
                            'deviceModel': 'K2WebClient',
                            'clientDeviceId': 'null',
                            'player': 'html5',
                            'clientDeviceType': 'web',
                        },
                        'standardAuth': {
                            'username': self.username,
                            'password': self.password,
                        },
                    },
                }],
            },
        }
        data = self.post('modify/authentication', postdata, authenticate=False)
        if not data:
            return False

        try:
            return data['ModuleListResponse']['status'] == 1 and self.is_logged_in()
        except KeyError:
            self.log('Error decoding json response for login')
            return False

    def authenticate(self):
        if not self.is_logged_in() and not self.login():
            self.log('Unable to authenticate because login failed')
            return False

        postdata = {
            'moduleList': {
                'modules': [{
                    'moduleRequest': {
                        'resultTemplate': 'web',
                        'deviceInfo': {
                            'osVersion': 'Mac',
                            'platform': 'Web',
                            'clientDeviceType': 'web',
                            'sxmAppVersion': '3.1802.10011.0',
                            'browser': 'Safari',
                            'browserVersion': '11.0.3',
                            'appRegion': self.region,
                            'deviceModel': 'K2WebClient',
                            'player': 'html5',
                            'clientDeviceId': 'null'
                        }
                    }
                }]
            }
        }
        data = self.post('resume?OAtrial=false', postdata, authenticate=False)
        if not data:
            return False

        try:
            success = data['ModuleListResponse']['status'] == 1 and self.is_session_authenticated()
            if success:
                self.last_auth_time = time.time()
                self.save_auth_state()
                self.log('Authentication successful, state saved')
            return success
        except KeyError:
            self.log('Error parsing json response for authentication')
            return False

    def get_sxmak_token(self):
        try:
            return self.session.cookies['SXMAKTOKEN'].split('=', 1)[1].split(',', 1)[0]
        except (KeyError, IndexError):
            return None

    def get_gup_id(self):
        try:
            return json.loads(urllib.parse.unquote(self.session.cookies['SXMDATA']))['gupId']
        except (KeyError, ValueError):
            return None

    def get_playlist_url(self, guid, channel_id, use_cache=True, max_attempts=5):
        if use_cache and channel_id in self.playlists:
             return self.playlists[channel_id]

        params = {
            'assetGUID': guid,
            'ccRequestType': 'AUDIO_VIDEO',
            'channelId': channel_id,
            'hls_output_mode': 'custom',
            'marker_mode': 'all_separate_cue_points',
            'result-template': 'web',
            'time': int(round(time.time() * 1000.0)),
            'timestamp': datetime.datetime.now(datetime.UTC).isoformat('T') + 'Z'
        }
        data = self.get('tune/now-playing-live', params)
        if not data:
            return None

        # get status
        try:
            status = data['ModuleListResponse']['status']
            message = data['ModuleListResponse']['messages'][0]['message']
            message_code = data['ModuleListResponse']['messages'][0]['code']
        except (KeyError, IndexError):
            self.log('Error parsing json response for playlist')
            return None

        # login if session expired
        if message_code == 201 or message_code == 208:
            if max_attempts > 0:
                self.log('Session expired (code {}), forcing re-authentication'.format(message_code))
                # Force re-authentication by clearing last_auth_time
                self.last_auth_time = None
                if self.authenticate():
                    self.log('Successfully re-authenticated after session expiry')
                    return self.get_playlist_url(guid, channel_id, use_cache, max_attempts - 1)
                else:
                    self.log('Failed to re-authenticate after session expiry')
                    return None
            else:
                self.log('Reached max attempts for playlist')
                return None
        elif message_code != 100:
            self.log('Received error {} {}'.format(message_code, message))
            return None

        # get m3u8 url
        try:
            playlists = data['ModuleListResponse']['moduleList']['modules'][0]['moduleResponse']['liveChannelData']['hlsAudioInfos']
        except (KeyError, IndexError):
            self.log('Error parsing json response for playlist')
            return None
        for playlist_info in playlists:
            if playlist_info['size'] == 'LARGE':
                playlist_url = playlist_info['url'].replace('%Live_Primary_HLS%', self.LIVE_PRIMARY_HLS)
                self.playlists[channel_id] = self.get_playlist_variant_url(playlist_url)
                return self.playlists[channel_id]

        return None

    def get_playlist_variant_url(self, url):
        params = {
            'token': self.get_sxmak_token(),
            'consumer': 'k2',
            'gupId': self.get_gup_id(),
        }
        res = self.session.get(url, params=params)

        if res.status_code != 200:
            self.log('Received status code {} on playlist variant retrieval'.format(res.status_code))
            return None
        
        for x in res.text.split('\n'):
            if x.rstrip().endswith('.m3u8'):
                # first variant should be 256k one
                return '{}/{}'.format(url.rsplit('/', 1)[0], x.rstrip())
        
        return None

    def get_playlist(self, name, use_cache=True):
        guid, channel_id = self.get_channel(name)
        if not guid or not channel_id:
            self.log('No channel for {}'.format(name))
            return None

        url = self.get_playlist_url(guid, channel_id, use_cache)
        params = {
            'token': self.get_sxmak_token(),
            'consumer': 'k2',
            'gupId': self.get_gup_id(),
        }
        res = self.session.get(url, params=params)

        if res.status_code == 403:
            self.log('Received status code 403 on playlist, forcing re-authentication')
            # Force re-authentication by clearing last_auth_time
            self.last_auth_time = None
            return self.get_playlist(name, False)

        if res.status_code != 200:
            self.log('Received status code {} on playlist variant'.format(res.status_code))
            return None

        # add base path to segments
        base_url = url.rsplit('/', 1)[0]
        base_path = base_url[8:].split('/', 1)[1]
        lines = res.text.split('\n')
        for x in range(len(lines)):
            if lines[x].rstrip().endswith('.aac'):
                lines[x] = '{}/{}'.format(base_path, lines[x])
        return '\n'.join(lines)

    def get_segment(self, path, max_attempts=5):
        url = '{}/{}'.format(self.LIVE_PRIMARY_HLS, path)
        params = {
            'token': self.get_sxmak_token(),
            'consumer': 'k2',
            'gupId': self.get_gup_id(),
        }
        res = self.session.get(url, params=params)

        if res.status_code == 403:
            if max_attempts > 0:
                self.log('Received status code 403 on segment, forcing re-authentication')
                # Force re-authentication by clearing last_auth_time
                self.last_auth_time = None
                self.get_playlist(path.split('/', 2)[1], False)
                return self.get_segment(path, max_attempts - 1)
            else:
                self.log('Received status code 403 on segment, max attempts exceeded')
                return None

        if res.status_code != 200:
            self.log('Received status code {} on segment'.format(res.status_code))
            return None

        return res.content
    
    def get_channels(self):
        # download channel list if necessary
        if not self.channels:
            postdata = {
                'moduleList': {
                    'modules': [{
                        'moduleArea': 'Discovery',
                        'moduleType': 'ChannelListing',
                        'moduleRequest': {
                            'consumeRequests': [],
                            'resultTemplate': 'responsive',
                            'alerts': [],
                            'profileInfos': []
                        }
                    }]
                }
            }
            data = self.post('get', postdata)
            if not data:
                self.log('Unable to get channel list')
                return (None, None)

            try:
                self.channels = data['ModuleListResponse']['moduleList']['modules'][0]['moduleResponse']['contentData']['channelListing']['channels']
            except (KeyError, IndexError):
                self.log('Error parsing json response for channels')
                return []
        return self.channels

    def get_channel(self, name):
        name = name.lower()
        for x in self.get_channels():
            if x.get('name', '').lower() == name or x.get('channelId', '').lower() == name or x.get('siriusChannelNumber') == name:
                return (x['channelGuid'], x['channelId'])
        return (None, None)

def make_sirius_handler(sxm):
    class SiriusHandler(BaseHTTPRequestHandler):
        HLS_AES_KEY = base64.b64decode('0Nsco7MAgxowGvkUT8aYag==')

        def do_GET(self):
            if self.path.endswith('.m3u8'):
                data = sxm.get_playlist(self.path.rsplit('/', 1)[1][:-5])
                if data:
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/x-mpegURL')
                    self.end_headers()
                    self.wfile.write(bytes(data, 'utf-8'))
                else:
                    self.send_response(500)
                    self.end_headers()
            elif self.path.endswith('.aac'):
                data = sxm.get_segment(self.path[1:])
                if data:
                    self.send_response(200)
                    self.send_header('Content-Type', 'audio/x-aac')
                    self.end_headers()
                    self.wfile.write(data)
                else:
                    self.send_response(500)
                    self.end_headers()
            elif self.path.endswith('/key/1'):
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(self.HLS_AES_KEY)
            else:
                self.send_response(500)
                self.end_headers()
    return SiriusHandler

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SiriusXM proxy')
    parser.add_argument('username')
    parser.add_argument('password')
    parser.add_argument('-l', '--list', required=False, action='store_true', default=False)
    parser.add_argument('-p', '--port', required=False, default=9999, type=int)
    parser.add_argument('-ca', '--canada', required=False, action='store_true', default=False)
    parser.add_argument('-e', '--env',  required=False, action='store_true', default=False)
    args = vars(parser.parse_args())
    if args['env']:
        if "SXM_USER" in os.environ:
            args['username'] = os.environ.get('SXM_USER')
        if "SXM_PASS" in os.environ:
            args['password'] = os.environ.get('SXM_PASS')

    sxm = SiriusXM(args['username'], args['password'], 'CA' if args['canada'] else 'US')
    if args['list']:
        channels = list(sorted(sxm.get_channels(), key=lambda x: (not x.get('isFavorite', False), int(x.get('siriusChannelNumber', 9999)))))
        
        l1 = max(len(x.get('channelId', '')) for x in channels)
        l2 = max(len(str(x.get('siriusChannelNumber', 0))) for x in channels)
        l3 = max(len(x.get('name', '')) for x in channels)
        print('{} | {} | {}'.format('ID'.ljust(l1), 'Num'.ljust(l2), 'Name'.ljust(l3)))
        for channel in channels:
            cid = channel.get('channelId', '').ljust(l1)[:l1]
            cnum = str(channel.get('siriusChannelNumber', '??')).ljust(l2)[:l2]
            cname = channel.get('name', '??').ljust(l3)[:l3]
            print('{} | {} | {}'.format(cid, cnum, cname))
    else:
        httpd = HTTPServer(('', args['port']), make_sirius_handler(sxm))
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        httpd.server_close()
