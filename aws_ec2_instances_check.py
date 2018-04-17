import boto3
import sys
import csv
import tqdm
import collections
import codecs
from netaddr import IPNetwork, IPAddress

def parse_blacklist():
	blacklist = collections.defaultdict(lambda: set())
	with codecs.open("dump.csv", encoding="cp1251") as dump:
		for line in dump:
			if line.startswith("Updated:"):
				continue
			tokens = line.split(';')
			ips = tokens[0]
			for ip in ips.split(" | "):
				blacklist[ip].add("%s: %s" % (tokens[4], tokens[5]))
	return blacklist

if __name__ == "__main__":
	blacklist = parse_blacklist()
	print("Inited blacklist size: %d" % len(blacklist))
	ec2 = boto3.resource('ec2')
	running_instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
	blacklisted = 0
	for instance in tqdm.tqdm(running_instances, desc="Instances"):
		name = "Unknown"
		for tag in instance.tags:
			if 'Name'in tag['Key']:
				name = tag['Value']
		ip = instance.public_ip_address
		matches = []
		for ip_range, reasons in tqdm.tqdm(blacklist.items(), desc="%s: %s" % (name, ip)):
			if IPAddress(ip) in IPNetwork(ip_range):
				matches.append("%s (%s)" % (", ".join(reasons), ip_range))
		if len(matches) > 0:
			print("[!] Alert, seems instance is blacklisted: %s" % matches)
			blacklisted += 1
	print("\nTotal blacklisted: %d ips" % blacklisted)


