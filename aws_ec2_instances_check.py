import boto3
import sys
import csv
import tqdm
import collections
import codecs
import json
import os
import requests
from netaddr import IPNetwork, IPAddress

"""
Jenkins run instuction:
1. Create Freestyle project
2. Add git repo https://github.com/shuva10v/z-i.git (origin) and https://github.com/zapret-info/z-i.git (upstream)
3. Add execute shell build step with the code:
	git fetch upstream
	git checkout origin/master
	git config --global user.email "user@example.com"
	git config --global user.name "user"
	git rebase upstream/master
	pip install -r requirements.txt
	python aws_ec2_instances_check.py
4. Pass SLACK_URL env with Credentials Binding Plugin
"""

def parse_blacklist():
	blacklist = collections.defaultdict(lambda: set())
	with codecs.open("dump.csv", encoding="cp1251") as dump:
		for line in dump:
			if line.startswith("Updated:"):
				continue
			tokens = line.split(';')
			ips = tokens[0]
			for ip in ips.split(" | "):
				try:
					blacklist[IPNetwork(ip)].add("%s: %s" % (tokens[4], tokens[5]))
				except:
					print("Unable to process ip %s" % ip)
	return blacklist

if __name__ == "__main__":
	blacklist = parse_blacklist()
	print("Inited blacklist size: %d" % len(blacklist))
	blacklisted = {}
	running = set()

	regions = boto3.client('ec2').describe_regions()['Regions']
	for region in regions:
		region = region['RegionName']
		print("Processing %s" % region)
		ec2 = boto3.resource('ec2', region_name=region)
		running_instances = ec2.instances.filter(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
		for instance in tqdm.tqdm(running_instances, desc="Instances"):
			name = "Unknown"
			running.add(instance.id)
			if instance.tags is not None:
				for tag in instance.tags:
					if 'Name'in tag['Key']:
						name = tag['Value']
			ip = instance.public_ip_address
			matches = []
			for ip_range, reasons in tqdm.tqdm(blacklist.items(), desc="%s: %s" % (name, ip)):
				if IPAddress(ip) in ip_range:
					matches.append("%s (%s)" % (", ".join(reasons), ip_range))
			if len(matches) > 0:
				print("\n[!] Alert, seems instance %s (%s) is blacklisted: %s\n" % (name, ip, matches))
				blacklisted[instance.id]  = {"name": name, "ip": ip}
	try:
		with open("last_state.json") as last_file:
			last_state = json.load(last_file)
	except:
		last_state = {}
	slack_url = os.environ.get("SLACK_URL", None)
	def send_slack(message, color):
		payload = { "username": "Zharov A.A.", "attachments": [ { "text": message, "color": color } ] }
		requests.post(slack_url, data=json.dumps(payload)).text
		
	if slack_url is not None:
		for id, value in blacklisted.items():
			if id not in last_state and value['name'] != "Unknown":
				print("New instance banned!")
				send_slack("New instance banned :face_with_symbols_on_mouth: %s %s (%s)" % (id, value['name'], value['ip']), "danger")
		for id, value in last_state.items():
			if id not in blacklisted and id in running:
				print("Instance unbanned!")
				send_slack("Instance unbanned :beers: %s %s (%s)" % (id, value['name'], value['ip']), "good")

	try:
		with open("last_state.json", "w") as out:
			out.write(json.dumps(blacklisted))
	except:
		pass
	print("\nTotal blacklisted: %d ips" % len(blacklisted))


