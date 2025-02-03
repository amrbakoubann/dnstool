import dns.resolver
import time
import matplotlib.pyplot as plt

def dns_lookup(domain, record_type='A', dns_server='8.8.8.8'):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [dns_server]
    try:
        answers = resolver.resolve(domain, record_type)
        return [answer.to_text() for answer in answers]
    except Exception as e:
        return f"Error: {e}"

def visualize_response_time(domain):
    servers = {
        'Google DNS': '8.8.8.8',
        'Cloudflare': '1.1.1.1',
        'OpenDNS': '208.67.222.222'
    }
    times = {}
    
    for name, server in servers.items():
        start = time.time()
        dns_lookup(domain, 'A', server)
        times[name] = time.time() - start
    
    plt.bar(times.keys(), times.values())
    plt.title(f'DNS Response Times for {domain}')
    plt.ylabel('Time (seconds)')

def dns_health_check(domain):
    checks = {
        'MX': 'Mail servers configured?',
        'TXT': 'SPF/DMARC records?',
        'A': 'IPv4 address?'
    }
    results = {}
    
    for record, question in checks.items():
        try:
            dns_lookup(domain, record)
            results[question] = "✅ Passed"
        except:
            results[question] = "❌ Failed"
    
    return results