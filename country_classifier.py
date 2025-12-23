import os
import re
import json
import base64
import hashlib
import socket
import threading
import pickle
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from collections import defaultdict
import logging

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DNSResolver:
    def __init__(self, cache_file='dns_cache.pkl'):
        self.cache_file = cache_file
        self.cache = self.load_cache()
        self.lock = threading.Lock()
        self.cdn_domains = {
            'cloudflare': ['cloudflare.com', 'cloudflare.net', 'cloudflaressl.com'],
            'akamai': ['akamai.net', 'akamaiedge.net', 'akamaihd.net'],
            'fastly': ['fastly.net', 'fastlylb.net'],
            'aws': ['amazonaws.com', 'cloudfront.net'],
            'azure': ['azureedge.net', 'azurefd.net'],
            'google': ['googleusercontent.com', 'gstatic.com', 'googleapis.com']
        }
    
    def load_cache(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'rb') as f:
                    return pickle.load(f)
        except:
            pass
        return {}
    
    def save_cache(self):
        try:
            with open(self.cache_file, 'wb') as f:
                pickle.dump(self.cache, f)
        except:
            pass
    
    def is_cdn_domain(self, domain):
        for cdn, patterns in self.cdn_domains.items():
            for pattern in patterns:
                if domain.endswith(pattern):
                    return cdn
        return None
    
    def resolve_host(self, host, max_retries=2):
        with self.lock:
            if host in self.cache:
                if self.cache[host]['expiry'] > time.time():
                    return self.cache[host]['result']
        
        for attempt in range(max_retries):
            try:
                info = socket.getaddrinfo(
                    host, None,
                    socket.AF_UNSPEC,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                    socket.AI_ADDRCONFIG
                )
                
                ips = set()
                for res in info:
                    addr = res[4][0]
                    if ':' in addr:
                        continue
                    ips.add(addr)
                
                result = {
                    'ips': list(ips),
                    'cdn': self.is_cdn_domain(host),
                    'timestamp': time.time(),
                    'expiry': time.time() + 3600
                }
                
                with self.lock:
                    self.cache[host] = result
                
                return result
                
            except (socket.gaierror, socket.timeout, OSError) as e:
                if attempt == max_retries - 1:
                    logger.warning(f"Failed to resolve {host}: {e}")
                    result = {
                        'ips': [],
                        'cdn': None,
                        'error': str(e),
                        'timestamp': time.time(),
                        'expiry': time.time() + 300
                    }
                    with self.lock:
                        self.cache[host] = result
                    return result
                time.sleep(1)
        
        return {'ips': [], 'cdn': None, 'error': 'Unknown error'}

class GeoIPClassifier:
    def __init__(self, db_path='GeoLite2-Country.mmdb', cache_file='geoip_cache.pkl'):
        self.db_path = db_path
        self.cache_file = cache_file
        self.cache = self.load_cache()
        self.lock = threading.Lock()
        self.reader = None
        self.initialized = False
        
        if os.path.exists(db_path) and GEOIP_AVAILABLE:
            try:
                self.reader = geoip2.database.Reader(db_path)
                self.initialized = True
                logger.info(f"GeoIP database loaded: {db_path}")
            except Exception as e:
                logger.error(f"Failed to load GeoIP database: {e}")
                self.initialized = False
        else:
            logger.warning(f"GeoIP database not found or library not available: {db_path}")
            self.initialized = False
    
    def load_cache(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'rb') as f:
                    return pickle.load(f)
        except:
            pass
        return {}
    
    def save_cache(self):
        try:
            with open(self.cache_file, 'wb') as f:
                pickle.dump(self.cache, f)
        except:
            pass
    
    def get_country(self, ip):
        if not self.initialized:
            return {'country_code': 'UNKNOWN', 'country_name': 'Unknown'}
        
        cache_key = hashlib.md5(ip.encode()).hexdigest()
        
        with self.lock:
            if cache_key in self.cache:
                if self.cache[cache_key]['expiry'] > time.time():
                    return self.cache[cache_key]['result']
        
        try:
            response = self.reader.country(ip)
            result = {
                'country_code': response.country.iso_code or 'XX',
                'country_name': response.country.name or 'Unknown',
                'continent_code': response.continent.code or 'XX',
                'continent_name': response.continent.name or 'Unknown'
            }
        except geoip2.errors.AddressNotFoundError:
            result = {'country_code': 'XX', 'country_name': 'Unknown'}
        except Exception as e:
            logger.warning(f"GeoIP lookup failed for {ip}: {e}")
            result = {'country_code': 'ERROR', 'country_name': f'Error: {str(e)[:50]}'}
        
        with self.lock:
            self.cache[cache_key] = {
                'result': result,
                'expiry': time.time() + 86400
            }
        
        return result
    
    def close(self):
        if self.reader:
            self.reader.close()
        self.save_cache()

class ConfigParser:
    @staticmethod
    def decode_vmess(config_str):
        try:
            base64_part = config_str[8:]
            if len(base64_part) % 4 != 0:
                base64_part += '=' * (4 - len(base64_part) % 4)
            return json.loads(base64.b64decode(base64_part).decode('utf-8'))
        except:
            return None
    
    @staticmethod
    def parse_vless(config_str):
        try:
            parts = config_str.split('#', 1)
            base = parts[0][8:]
            if '?' in base:
                server_part, query_part = base.split('?', 1)
            else:
                server_part, query_part = base, ''
            
            if '@' in server_part:
                uuid_part, server_port = server_part.split('@', 1)
            else:
                return {}
            
            server, port = server_port.split(':', 1) if ':' in server_port else (server_port, '443')
            
            result = {
                'protocol': 'vless',
                'server': server,
                'port': int(port) if port.isdigit() else 443,
                'uuid': uuid_part
            }
            
            if query_part:
                params = parse_qs(query_part)
                if 'sni' in params:
                    result['sni'] = params['sni'][0]
                if 'host' in params:
                    result['host'] = params['host'][0]
            
            if len(parts) > 1:
                result['remarks'] = parts[1]
            
            return result
        except:
            return {}
    
    @staticmethod
    def parse_trojan(config_str):
        try:
            parts = config_str.split('#', 1)
            base = parts[0][9:]
            
            if '@' in base:
                password_part, server_port = base.split('@', 1)
            else:
                return {}
            
            server, port = server_port.split(':', 1) if ':' in server_port else (server_port, '443')
            
            result = {
                'protocol': 'trojan',
                'server': server,
                'port': int(port) if port.isdigit() else 443,
                'password': password_part
            }
            
            if '?' in server_port:
                server_part, query_part = server_port.split('?', 1)
                server, port = server_part.split(':', 1) if ':' in server_part else (server_part, '443')
                result['server'] = server
                result['port'] = int(port) if port.isdigit() else 443
                
                params = parse_qs(query_part)
                if 'sni' in params:
                    result['sni'] = params['sni'][0]
                if 'peer' in params:
                    result['sni'] = params['peer'][0]
            
            if len(parts) > 1:
                result['remarks'] = parts[1]
            
            return result
        except:
            return {}
    
    @staticmethod
    def parse_ss(config_str):
        try:
            parts = config_str.split('#', 1)
            base = parts[0][5:]
            
            if '@' in base:
                encoded_mp, server_port = base.split('@', 1)
            else:
                if len(base) % 4 != 0:
                    base += '=' * (4 - len(base) % 4)
                try:
                    decoded = base64.b64decode(base).decode('utf-8')
                    if '@' in decoded:
                        method_pass, server_port = decoded.split('@', 1)
                        encoded_mp = base64.b64encode(method_pass.encode()).decode()
                    else:
                        return {}
                except:
                    return {}
            
            server, port = server_port.split(':', 1) if ':' in server_port else (server_port, '443')
            
            if len(encoded_mp) % 4 != 0:
                encoded_mp += '=' * (4 - len(encoded_mp) % 4)
            
            try:
                method_pass = base64.b64decode(encoded_mp).decode('utf-8')
                method, password = method_pass.split(':', 1) if ':' in method_pass else (method_pass, '')
            except:
                method, password = 'unknown', ''
            
            result = {
                'protocol': 'ss',
                'server': server,
                'port': int(port) if port.isdigit() else 443,
                'method': method,
                'password': password
            }
            
            if len(parts) > 1:
                result['remarks'] = parts[1]
            
            return result
        except:
            return {}
    
    @staticmethod
    def parse_hysteria(config_str):
        try:
            if config_str.startswith('hysteria2://'):
                base = config_str[12:]
            elif config_str.startswith('hy2://'):
                base = config_str[6:]
            elif config_str.startswith('hysteria://'):
                base = config_str[11:]
            else:
                return {}
            
            parts = base.split('#', 1)
            base_part = parts[0]
            
            if '@' in base_part:
                auth_part, server_port = base_part.split('@', 1)
            else:
                server_port = base_part
                auth_part = ''
            
            server, port = server_port.split(':', 1) if ':' in server_port else (server_port, '443')
            
            result = {
                'protocol': 'hysteria' if 'hysteria://' in config_str else 'hysteria2',
                'server': server,
                'port': int(port) if port.isdigit() else 443,
                'auth': auth_part
            }
            
            if len(parts) > 1:
                result['remarks'] = parts[1]
            
            return result
        except:
            return {}
    
    @staticmethod
    def parse_tuic(config_str):
        try:
            base = config_str[6:]
            parts = base.split('#', 1)
            base_part = parts[0]
            
            if '@' in base_part:
                uuid_part, server_port = base_part.split('@', 1)
            else:
                return {}
            
            server, port = server_port.split(':', 1) if ':' in server_port else (server_port, '443')
            
            result = {
                'protocol': 'tuic',
                'server': server,
                'port': int(port) if port.isdigit() else 443,
                'uuid': uuid_part
            }
            
            if len(parts) > 1:
                result['remarks'] = parts[1]
            
            return result
        except:
            return {}
    
    @staticmethod
    def parse_wireguard(config_str):
        try:
            base = config_str[12:]
            params = parse_qs(base)
            
            result = {
                'protocol': 'wireguard',
                'public_key': params.get('public_key', [''])[0],
                'endpoint': params.get('endpoint', [''])[0]
            }
            
            if result['endpoint']:
                if ':' in result['endpoint']:
                    server, port = result['endpoint'].split(':', 1)
                    result['server'] = server
                    result['port'] = int(port) if port.isdigit() else 51820
                else:
                    result['server'] = result['endpoint']
                    result['port'] = 51820
            
            return result
        except:
            return {}
    
    @staticmethod
    def parse_config(config_str):
        config_str = config_str.strip()
        
        if config_str.startswith('vmess://'):
            decoded = ConfigParser.decode_vmess(config_str)
            if decoded and isinstance(decoded, dict):
                return {
                    'protocol': 'vmess',
                    'server': decoded.get('add', ''),
                    'port': int(decoded.get('port', 443)),
                    'uuid': decoded.get('id', ''),
                    'sni': decoded.get('sni', ''),
                    'host': decoded.get('host', ''),
                    'remarks': decoded.get('ps', '')
                }
        
        elif config_str.startswith('vless://'):
            return ConfigParser.parse_vless(config_str)
        
        elif config_str.startswith('trojan://'):
            return ConfigParser.parse_trojan(config_str)
        
        elif config_str.startswith('ss://'):
            return ConfigParser.parse_ss(config_str)
        
        elif config_str.startswith('hysteria2://') or config_str.startswith('hy2://') or config_str.startswith('hysteria://'):
            return ConfigParser.parse_hysteria(config_str)
        
        elif config_str.startswith('tuic://'):
            return ConfigParser.parse_tuic(config_str)
        
        elif config_str.startswith('wireguard://'):
            return ConfigParser.parse_wireguard(config_str)
        
        return {}

class CountryClassifier:
    def __init__(self, max_workers=50, skip_countries=None):
        self.max_workers = max_workers
        self.skip_countries = set(skip_countries or [])
        self.dns_resolver = DNSResolver()
        self.geoip_classifier = GeoIPClassifier()
        self.config_parser = ConfigParser()
        
        self.results = defaultdict(lambda: defaultdict(list))
        self.stats = {
            'total': 0,
            'processed': 0,
            'failed': 0,
            'by_country': defaultdict(int),
            'by_protocol': defaultdict(int)
        }
    
    def read_config_files(self, input_dirs=None):
        if input_dirs is None:
            input_dirs = ['configs/combined', 'configs/telegram', 'configs/github']
        
        configs = []
        seen_hashes = set()
        
        for input_dir in input_dirs:
            if not os.path.exists(input_dir):
                continue
            
            for root, dirs, files in os.walk(input_dir):
                for file in files:
                    if file.endswith('.txt') and file != 'all.txt':
                        filepath = os.path.join(root, file)
                        try:
                            with open(filepath, 'r', encoding='utf-8') as f:
                                for line in f:
                                    line = line.strip()
                                    if line and not line.startswith('#'):
                                        config_hash = hashlib.md5(line.encode()).hexdigest()
                                        if config_hash not in seen_hashes:
                                            seen_hashes.add(config_hash)
                                            configs.append(line)
                        except Exception as e:
                            logger.error(f"Error reading {filepath}: {e}")
        
        self.stats['total'] = len(configs)
        logger.info(f"Loaded {len(configs)} unique configurations")
        return configs
    
    def process_config(self, config_str):
        try:
            parsed = self.config_parser.parse_config(config_str)
            if not parsed or 'server' not in parsed or not parsed['server']:
                return None
            
            server = parsed['server']
            
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', server):
                ips = [server]
                cdn_info = None
            else:
                dns_result = self.dns_resolver.resolve_host(server)
                ips = dns_result.get('ips', [])
                cdn_info = dns_result.get('cdn')
            
            if not ips:
                return {
                    'config': config_str,
                    'parsed': parsed,
                    'country': {'country_code': 'UNRESOLVED', 'country_name': 'Unresolved'},
                    'ip': None,
                    'cdn': cdn_info,
                    'error': 'DNS resolution failed'
                }
            
            ip = ips[0]
            country_info = self.geoip_classifier.get_country(ip)
            
            if country_info['country_code'] in self.skip_countries:
                return None
            
            return {
                'config': config_str,
                'parsed': parsed,
                'country': country_info,
                'ip': ip,
                'cdn': cdn_info,
                'all_ips': ips
            }
            
        except Exception as e:
            logger.warning(f"Error processing config: {e}")
            return {
                'config': config_str,
                'error': str(e),
                'country': {'country_code': 'ERROR', 'country_name': 'Processing Error'}
            }
    
    def classify_configs(self, configs):
        logger.info(f"Processing {len(configs)} configurations with {self.max_workers} workers...")
        
        show_progress = len(configs) <= 10000
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.process_config, config): config for config in configs}
            
            for i, future in enumerate(as_completed(futures), 1):
                try:
                    result = future.result()
                    
                    if result is None:
                        self.stats['failed'] += 1
                        continue
                    
                    if 'error' in result and 'Processing Error' not in result['error']:
                        self.stats['failed'] += 1
                        continue
                    
                    country_code = result['country']['country_code']
                    protocol = result['parsed'].get('protocol', 'unknown')
                    
                    if country_code not in ['ERROR', 'UNRESOLVED', 'UNKNOWN']:
                        self.results[country_code][protocol].append(result)
                        self.stats['by_country'][country_code] += 1
                        self.stats['by_protocol'][protocol] += 1
                        self.stats['processed'] += 1
                    
                    if show_progress and i % 100 == 0:
                        logger.info(f"Processed {i}/{len(configs)} configurations")
                        
                except Exception as e:
                    logger.error(f"Future error: {e}")
                    self.stats['failed'] += 1
        
        return self.results
    
    def save_results(self):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        output_dir = 'configs/country'
        os.makedirs(output_dir, exist_ok=True)
        
        for country_code, protocols in self.results.items():
            country_dir = os.path.join(output_dir, country_code)
            os.makedirs(country_dir, exist_ok=True)
            
            all_country_configs = []
            
            for protocol, configs in protocols.items():
                if len(configs) >= 10:
                    protocol_file = os.path.join(country_dir, f"{protocol}.txt")
                    with open(protocol_file, 'w', encoding='utf-8') as f:
                        f.write(f"# {protocol.upper()} configurations for {country_code}\n")
                        f.write(f"# Updated: {timestamp}\n")
                        f.write(f"# Count: {len(configs)}\n")
                        f.write(f"# Generated by ARISTA Country Classifier\n\n")
                        for config_info in configs:
                            f.write(f"{config_info['config']}\n")
                
                all_country_configs.extend([c['config'] for c in configs])
            
            if all_country_configs:
                all_file = os.path.join(country_dir, "all.txt")
                with open(all_file, 'w', encoding='utf-8') as f:
                    f.write(f"# All configurations for {country_code}\n")
                    f.write(f"# Updated: {timestamp}\n")
                    f.write(f"# Count: {len(all_country_configs)}\n")
                    f.write(f"# Generated by ARISTA Country Classifier\n\n")
                    for config in all_country_configs:
                        f.write(f"{config}\n")
        
        summary_file = os.path.join(output_dir, "summary.txt")
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write(f"# Country Classification Summary\n")
            f.write(f"# Updated: {timestamp}\n")
            f.write(f"# Total configs: {self.stats['total']}\n")
            f.write(f"# Processed successfully: {self.stats['processed']}\n")
            f.write(f"# Failed: {self.stats['failed']}\n\n")
            
            f.write("Countries by config count:\n")
            sorted_countries = sorted(self.stats['by_country'].items(), key=lambda x: x[1], reverse=True)
            for country_code, count in sorted_countries:
                f.write(f"  {country_code}: {count}\n")
            
            f.write("\nProtocols by config count:\n")
            for protocol, count in sorted(self.stats['by_protocol'].items(), key=lambda x: x[1], reverse=True):
                f.write(f"  {protocol}: {count}\n")
        
        self.dns_resolver.save_cache()
        self.geoip_classifier.save_cache()
        self.geoip_classifier.close()
        
        return len(self.results)
    
    def print_stats(self):
        print("=" * 60)
        print("COUNTRY CLASSIFICATION RESULTS")
        print("=" * 60)
        print(f"Total configurations: {self.stats['total']}")
        print(f"Successfully processed: {self.stats['processed']}")
        print(f"Failed: {self.stats['failed']}")
        
        if self.stats['by_country']:
            print("\nTop 10 countries by config count:")
            sorted_countries = sorted(self.stats['by_country'].items(), key=lambda x: x[1], reverse=True)[:10]
            for country_code, count in sorted_countries:
                print(f"  {country_code}: {count}")
        
        if self.stats['by_protocol']:
            print("\nProtocol distribution:")
            for protocol, count in sorted(self.stats['by_protocol'].items(), key=lambda x: x[1], reverse=True):
                print(f"  {protocol}: {count}")
        
        print(f"\nResults saved to: configs/country/")
        print("=" * 60)

def main():
    logger.info("Starting Country Classifier...")
    
    try:
        classifier = CountryClassifier(
            max_workers=50,
            skip_countries=['CN', 'IR', 'RU', 'KP']  # Skip these countries
        )
        
        configs = classifier.read_config_files()
        
        if not configs:
            logger.error("No configurations found to process")
            return
        
        results = classifier.classify_configs(configs)
        num_countries = classifier.save_results()
        classifier.print_stats()
        
        logger.info(f"Classification complete. Found {num_countries} countries.")
        
    except Exception as e:
        logger.error(f"Fatal error in main: {e}")
        raise

if __name__ == "__main__":
    main()
