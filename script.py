import re, requests, json, random, argparse


#class for storing all the variables of the IP address
class FailedSSH:
    def __init__(self, ip_address):
        self.usernames = set()
        self.ip_address = ip_address
        self.count = 1
        self.confidence_level = -1
    #function used to set confidence level of any given IP address
    def set_confidence_level(self, confidence_level): self.confidence_level = confidence_level

    def __str__(self):
        fmt = f"addr: {self.ip_address}\ncount: {self.count}\n usernames:\n{self.usernames.__str__()}\n"
        if self.confidence_level > -1: 
            fmt += f"confidence level: {self.confidence_level}"
        return fmt

#function that finds failed SSH connections 
def find_failed_ssh(path):
    pattern = re.compile(r'(?:Failed password for|Invalid user) ([^\s]+) from ([^\s]+) port [0-9]+ ssh2', re.IGNORECASE)
    failed_ssh = {}
  # Open the auth.log file
    with open(path, 'r', encoding='UTF-8') as f:
        for line in f:
            match = pattern.search(line)
            if match:
                username = match.group(1)
                ip_address = match.group(2)
                if ip_address in failed_ssh:
                    failed_ssh[ip_address].count += 1
                    failed_ssh[ip_address].usernames.add(username) 
                else:
                    failed_ssh[ip_address] = FailedSSH(ip_address)
                    failed_ssh[ip_address].usernames.add(username)
    return failed_ssh

#function that finds failed Telnet connections 
def find_failed_telnet(path):
    pattern = re.compile(r"(?<=telnet login failed for )([\w-]+)(?: from )(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)", re.IGNORECASE)
    failed_telnet = {}
  # Open the auth.log file
    with open(path, 'r', encoding='UTF-8') as f:
        for line in f:
            match = pattern.search(line)
            if match:
                username = match.group(1)
                ip_address = match.group(2)
                if ip_address in failed_telnet:
                    failed_telnet[ip_address].count += 1
                    failed_telnet[ip_address].usernames.add(username)
                else:
                    failed_telnet[ip_address] = FailedSSH(ip_address)
                    failed_telnet[ip_address].usernames.add(username)
    return failed_telnet

#this function uses abuseIPDB api to check for malicious IP addresses
def check_ip(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': '00f5859612f46869eddc404e144f56ab49045d1b2b3d3363495d762fef87e7c7889ffc8aa163f416	'
    }
    querystring = {
        'ipAddress': '',
        'maxAgeInDays': '90'
    }
    querystring.update({'ipAddress': str(ip)})
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    decoded = json.loads(response.text)
    try:
        conflvl = decoded['data']
    except AttributeError as error:
        print(f"data fetching gone bad {error}")
        exit(1)

    return conflvl['abuseConfidenceScore']

#print and save top 10 addresses based on confidence level
def top_10_conf(results):
    r2 = {}
    i = 0 
    for ip, fssh in results.items():
        r2[ip] = fssh
    results = r2
    ll = [(k, v) for k, v in sorted(results.items(), key=lambda item: item[1].confidence_level, reverse=True)][:10]

    with open(str(args.save), 'w') as f:
        f.write("Top IPs based on AbuseIPDB confidence level")
        f.writelines([f"{l[0]} {l[1]}\n" for l in ll])
        
    
#print and save top 10 addresses based on amount of failed connections
def top_10_count(results):
    r2 = {}
    i = 0 
    for ip, fssh in results.items():
        r2[ip] = fssh
    results = r2
    ll = [(k, v) for k, v in sorted(results.items(), key=lambda item: item[1].count, reverse=True)][:10]
    with open(str(args.save), 'w') as f:
        f.write("Top IPs based on amount of failed connections")
        f.writelines([f"{l[0]} {l[1]}\n" for l in ll])



if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="Simple brute-force detection script")
    arg_parser.add_argument('--all', dest="all", action='store_true', help="run all checks")
    arg_parser.add_argument('--ssh', dest="ssh", action='store_true', help="run checks on ssh")
    arg_parser.add_argument('--telnet', dest="telnet", action='store_true', help="run checks on telnet")
    arg_parser.add_argument('--save', dest="save", help="If provided with path saves outpus to the given path", default='output.txt')

    args = arg_parser.parse_args()
    

    if args.all:
        results = find_failed_ssh("./auth.log")
        [fssh.set_confidence_level(check_ip(ip)) for ip, fssh in results.items()]
        top_10_conf(results)
        top_10_count(results)
        results = find_failed_telnet("./auth.log")
        [fssh.set_confidence_level(check_ip(ip)) for ip, fssh in results.items()]
        top_10_conf(results)
        top_10_count(results)
    elif args.ssh:
        results = find_failed_ssh("./auth.log")
        [fssh.set_confidence_level(check_ip(ip)) for ip, fssh in results.items()]
        top_10_conf(results)
        top_10_count(results)
    elif args.telnet:
        results = find_failed_telnet("./auth.log")
        [fssh.set_confidence_level(check_ip(ip)) for ip, fssh in results.items()]
        top_10_conf(results)
        top_10_count(results)
    else:
        exit(1)
