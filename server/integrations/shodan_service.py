# backend/integrations/shodan_service.py

import requests
import logging
import os
import re
import socket
from urllib.parse import urlparse
from django.conf import settings
from django.core.cache import cache

logger = logging.getLogger(__name__)

class ShodanService:
    """
    Service for integrating with Shodan API to retrieve host information
    and enhance security scanning capabilities
    """
    
    def __init__(self):
        # Get API key from settings or environment variables
        self.api_key = getattr(settings, 'SHODAN_API_KEY', os.environ.get('SHODAN_API_KEY'))
        self.api_base_url = "https://api.shodan.io"
        self.cache_timeout = 86400  # 24 hours
        self.mock_enabled = getattr(settings, 'SHODAN_MOCK_ENABLED', True)
        
        if not self.api_key and not self.mock_enabled:
            logger.warning("No Shodan API key found. Set SHODAN_API_KEY in settings or environment.")
    
    def get_host_information(self, target_url):
        """
        Get Shodan information for a host
        
        Args:
            target_url (str): URL of the target to scan
            
        Returns:
            dict: Host information from Shodan
        """
        # Extract hostname/IP from URL
        hostname = self._extract_hostname(target_url)
        if not hostname:
            logger.error(f"Could not extract valid hostname from {target_url}")
            return {"error": "Invalid URL", "data": None}
        
        # Try to resolve hostname to IP if it's not already an IP
        ip_address = self._resolve_to_ip(hostname)
        if not ip_address:
            logger.error(f"Could not resolve hostname to IP: {hostname}")
            return {"error": "Could not resolve hostname", "data": None}
            
        # Check cache first
        cache_key = f"shodan_host_{ip_address}"
        cached_data = cache.get(cache_key)
        if cached_data:
            logger.info(f"Using cached Shodan data for {ip_address}")
            return cached_data
        
        # If mock mode is enabled, return mock data
        if self.mock_enabled:
            logger.info(f"Using mock Shodan data for {ip_address}")
            data = self._get_mock_host_data(ip_address, hostname)
            cache.set(cache_key, data, self.cache_timeout)
            return data
            
        # Otherwise, query the Shodan API
        if not self.api_key:
            return {"error": "No Shodan API key configured", "data": None}
            
        try:
            # Make API request to Shodan
            url = f"{self.api_base_url}/shodan/host/{ip_address}?key={self.api_key}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                # Cache the successful response
                cache.set(cache_key, {"error": None, "data": data}, self.cache_timeout)
                return {"error": None, "data": data}
            elif response.status_code == 404:
                logger.info(f"No Shodan data found for {ip_address}")
                return {"error": "No data found", "data": None}
            else:
                logger.error(f"Shodan API error: {response.status_code} - {response.text}")
                return {"error": f"API error: {response.status_code}", "data": None}
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error requesting Shodan data: {str(e)}")
            return {"error": str(e), "data": None}
    
    def search_vulnerabilities(self, query):
        """
        Search for vulnerabilities in Shodan
        
        Args:
            query (str): Shodan search query
            
        Returns:
            dict: Search results from Shodan
        """
        # Check cache first
        cache_key = f"shodan_search_{hash(query)}"
        cached_data = cache.get(cache_key)
        if cached_data:
            logger.info(f"Using cached Shodan search results for query: {query}")
            return cached_data
            
        # If mock mode is enabled, return mock data
        if self.mock_enabled:
            logger.info(f"Using mock Shodan search results for query: {query}")
            data = self._get_mock_search_data(query)
            cache.set(cache_key, data, self.cache_timeout)
            return data
            
        # Otherwise, query the Shodan API
        if not self.api_key:
            return {"error": "No Shodan API key configured", "data": None}
            
        try:
            # Make API request to Shodan
            url = f"{self.api_base_url}/shodan/host/search?key={self.api_key}&query={query}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                # Cache the successful response
                cache.set(cache_key, {"error": None, "data": data}, self.cache_timeout)
                return {"error": None, "data": data}
            else:
                logger.error(f"Shodan API error: {response.status_code} - {response.text}")
                return {"error": f"API error: {response.status_code}", "data": None}
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error searching Shodan: {str(e)}")
            return {"error": str(e), "data": None}
    
    def get_ports(self, target_url):
        """
        Get open ports for a target from Shodan
        
        Args:
            target_url (str): URL of the target
            
        Returns:
            dict: Port information from Shodan
        """
        host_info = self.get_host_information(target_url)
        
        if host_info["error"] or not host_info["data"]:
            return {"error": host_info["error"], "ports": []}
            
        try:
            # Extract ports from host information
            ports = []
            for service in host_info["data"].get("data", []):
                if "port" in service:
                    port_info = {
                        "port": service["port"],
                        "protocol": service.get("transport", "unknown"),
                        "service": service.get("_shodan", {}).get("module", "unknown"),
                        "product": service.get("product", ""),
                        "version": service.get("version", "")
                    }
                    ports.append(port_info)
            
            return {"error": None, "ports": ports}
            
        except Exception as e:
            logger.error(f"Error extracting port information: {str(e)}")
            return {"error": str(e), "ports": []}
    
    def _extract_hostname(self, url):
        """Extract hostname from URL"""
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc
            
            # If no hostname was found, the URL might be missing the scheme
            if not hostname and parsed.path:
                # Try adding https:// and parse again
                parsed = urlparse(f"https://{url}")
                hostname = parsed.netloc
            
            # Remove port if present
            if ":" in hostname:
                hostname = hostname.split(":")[0]
                
            return hostname
        except Exception as e:
            logger.error(f"Error extracting hostname from URL {url}: {str(e)}")
            return None
    
    def _resolve_to_ip(self, hostname):
        """Resolve hostname to IP address"""
        # Check if it's already an IP address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
            return hostname
            
        try:
            ip_address = socket.gethostbyname(hostname)
            return ip_address
        except socket.gaierror as e:
            logger.error(f"Error resolving hostname {hostname}: {str(e)}")
            return None
    
    def _get_mock_host_data(self, ip_address, hostname):
        """Generate mock Shodan host data for development/testing"""
        # Create a deterministic but varied response based on IP/hostname
        ip_hash = sum(ord(c) for c in ip_address) % 100
        
        # Common ports to include in mock data
        common_ports = [
            (80, "http", "HTTP"),
            (443, "https", "HTTPS"),
            (22, "ssh", "SSH"),
            (21, "ftp", "FTP"),
            (25, "smtp", "SMTP"),
            (110, "pop3", "POP3"),
            (143, "imap", "IMAP"),
            (3306, "mysql", "MySQL"),
            (5432, "postgresql", "PostgreSQL"),
            (27017, "mongodb", "MongoDB"),
            (6379, "redis", "Redis"),
            (9200, "elasticsearch", "Elasticsearch"),
            (8080, "http-alt", "HTTP Alternate")
        ]
        
        # Select a varied number of ports based on the IP hash
        num_ports = 3 + (ip_hash % 8)  # 3 to 10 ports
        
        # Shuffle and select ports
        import random
        random.seed(ip_hash)  # Use deterministic randomness
        selected_ports = random.sample(common_ports, min(num_ports, len(common_ports)))
        
        # Generate mock services data
        services = []
        for port, protocol, service_name in selected_ports:
            service = {
                "port": port,
                "transport": protocol,
                "_shodan": {
                    "module": service_name,
                    "id": f"mock_{service_name.lower()}_{port}"
                },
                "product": f"Mock {service_name}",
                "version": f"{(ip_hash % 10)}.{(ip_hash % 5)}.{ip_hash % 20}"
            }
            services.append(service)
        
        # Build full mock response
        mock_response = {
            "ip_str": ip_address,
            "hostnames": [hostname],
            "country_name": "United States",
            "org": "Mock Organization",
            "isp": "Mock ISP",
            "os": "Linux" if ip_hash % 2 == 0 else "Windows",
            "ports": [s["port"] for s in services],
            "data": services,
            "last_update": "2025-01-01T00:00:00.000000",
            "tags": ["mock", "development"],
            "_shodan": {
                "crawler": "Mock Shodan Crawler",
                "id": f"mock_{ip_hash:08x}"
            }
        }
        
        return {"error": None, "data": mock_response}
    
    def _get_mock_search_data(self, query):
        """Generate mock Shodan search results for development/testing"""
        # Create deterministic but varied response based on the query
        query_hash = sum(ord(c) for c in query) % 100
        
        # Generate mock matches
        matches = []
        num_matches = 3 + (query_hash % 8)  # 3 to 10 matches
        
        for i in range(num_matches):
            ip_last_octet = (query_hash + i) % 255
            match = {
                "ip_str": f"192.168.1.{ip_last_octet}",
                "hostnames": [f"mock-host-{i}.example.com"],
                "country_name": "United States",
                "org": f"Mock Organization {i}",
                "port": 80 + (i * 1000) % 65535,
                "data": f"Mock data for search query '{query}'",
                "_shodan": {
                    "crawler": "Mock Shodan Crawler",
                    "id": f"mock_search_{query_hash:04x}_{i:04x}"
                }
            }
            matches.append(match)
            
        # Build full mock response
        mock_response = {
            "matches": matches,
            "total": num_matches
        }
        
        return {"error": None, "data": mock_response}