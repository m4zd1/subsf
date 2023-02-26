#!/usr/bin/env python
import requests



def search_crt(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    response = requests.get(url)
    if response.status_code == 200:
        json_response = response.json()
        subdomains = set()
        for entry in json_response:
            name_value = entry.get('name_value')
            subdomains.add(name_value)
        return list(subdomains)
    else:
        return None

def search_dnsdumpster(domain):
    url = f"https://dnsdumpster.com/"
    session = requests.Session()
    response = session.get(url)
    csrf_token = response.cookies['csrftoken']
    headers = {
        'Referer': 'https://dnsdumpster.com/',
        'X-CSRFToken': csrf_token
    }
    data = {
        'csrfmiddlewaretoken': csrf_token,
        'targetip': domain
    }
    response = session.post(url, headers=headers, data=data)
    if response.status_code == 200:
        subdomains = set()
        for line in response.text.split('\n'):
            if 'dns-resolver' in line:
                subdomain = line.split(',')[0].strip()
                subdomains.add(subdomain)
        return list(subdomains)
    else:
        return None

def search_hackertarget(domain):
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    response = requests.get(url)
    if response.status_code == 200:
        subdomains = response.text.strip().split('\n')
        return subdomains
    else:
        return None


        
if __name__ == "__main__":
    domain = input("Please enter a domain: ")
    sources = [
        {'name': 'crt.sh', 'function': search_crt},
        {'name': 'DNSDumpster', 'function': search_dnsdumpster},
        {'name': 'HackerTarget', 'function': search_hackertarget},
    ]
    subdomains = set()
    for source in sources:
        print(f"Searching {source['name']}...")
        results = source['function'](domain)
        if results:
            subdomains.update(results)
    if subdomains:
        output_file = f"{domain}_subdomains.txt"
        with open(output_file, "w") as f:
            for subdomain in subdomains:
                print(subdomain)
                f.write(subdomain + "\n")
        print(f"Results saved to {output_file}")
    else:
        print("No subdomains found")
