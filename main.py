import sys
import os
import subprocess
import json


flags = ""
modes = ["static", "hybrid", "active"]
name = []
version = []
count = 0
notv20 = 0
notv30 = 0
notv31 = 0
notv40 = 0
cves = []
severities = []
details = ["CVE_ID", "Severity Rating", "Severity Score"]


def verboseFlag(verbose):
	if verbose:
		print("Verbose Mode Engaged")

def activeFlag(active):
	if active:
		print("Active Mode Engaged")

def passiveFlag(passive):
	if passive:
		print("Passive Mode Engaged")

def createSBOM(container):
	##Command to extract the SBOM from the container
	command = "docker run -v ./output:/output aquasec/trivy:canary image -q --scanners vuln --format cyclonedx --output /output/result.json " + container
	##Runs the command as a subprocess, stores nothing into the variable
	check = subprocess.run(command, shell=True) 

def readJSON():
	##Opens the SBOM file which was created
	with open("./output/result.json") as jsonfile:
		d = json.load(jsonfile)
	##Filters the dictionary to look for the components section
	components = d["components"]
	##count = 0
	##Loops through the components section extracting the name of the packages
	for component in components:
		name = component["name"]
		versions = component["version"]
		software.append(name)
		version.append(version)
		##count = count + 1
	##print(count)
	##print(software)
	##print(version)
	return name, version

def createCPE(name, version):
	for name in names:
    url = baseURL + name
    response = requests.get(url)
    response_json = response.json()
    count = count + 1
    vulnerabilities = response_json["vulnerabilities"]
    print(name + " Vulnerabilities")
    print(response_json["totalResults"])
    for vulnerability in vulnerabilities:
        print(details)
        cve = vulnerability["cve"]
        cves.append(cve["id"])
        details[0] = cve["id"]
        metrics = cve["metrics"]
        try:
            metricsV2 = metrics["cvssMetricV2"]
            metricsV2 = metricsV2[0]
            severities.append(metricsV2["baseSeverity"])
            details[1] = metricsV2["baseSeverity"]
            details[2] = metricsV2["cvssData"]["baseScore"]
        except:
            try:
                notv2 = notv2 + 1
                metricsV30 = metrics["cvssMetricV30"]
                metricsV30 = metricsV30[0]
                severities.append(metricsV30["cvssData"]["baseSeverity"])
                details[1] = metricsV30["cvssData"]["baseSeverity"]
                details[2] = metricsV30["cvssData"]["baseScore"]
            except:
                try:
                    notv30 = notv30 + 1
                    metricsV31 = metrics["cvssMetricV31"]
                    metricsV31 = metricsV31[0]
                    severities.append(metricsV31["cvssData"]["baseSeverity"])
                    details[1] = metricsV31["cvssData"]["baseSeverity"]
                    details[2] = metricsV31["cvssData"]["baseScore"]
                except:
                    try:
                        notv31 = notv31 + 1
                        metricsV40 = metrics["cvssMetricV40"]
                        metricsV40 = metricsV40[0]
                        severities.append(metricsV40["cvssData"]["baseSeverity"])
                        details[1] = metricsV40["cvssData"]["baseSeverity"]
                        details[2] = metricsV40["cvssData"]["baseScore"]
                    except:
                        count = count + 1
                        print(cve["id"])
                        print("OFDJKAPFJPOASDFJKOIPWEJFAODPJKFKLADJFPOEAKROPAEJF")
                
    print(cves)
    print(severities)

def static(container):
	createSBOM(container)
	name, version = readJSON()
	createCPE(name, version)


def main(mode, container):
	##print(active)
	##print(passive)
	##print(verbose)
	print(mode)
	print(container)
	##Runs command to check for container among running containers
	output = subprocess.check_output("sudo docker ps", shell=True)
	output = output.decode("UTF-8")
	if container in output:
		print("This container exists")
	else:
		print("This container does not exist")
	print(output[2])

##Detects if the script is being run or the user wants to access the help manual.
if sys.argv[1] in ["help", "-h"]:
	##Prints the help manual with all modes and flags which can be used.
	print('''Input should be structured python3 [mode] [container] [flags]
	         Where \n
		 [mode] == What mode you want to run the program in \n
		 [container] == The image name of the container \n
	         [flags] == The flags you want to run the program with \n
		 Modes \n
 		 \t Scan \n
		 \t DockerFile \n
		 Flags \n
		 \t -a Active \n
		 \t -p Passive \n
	         \t -v Verbose''')
	##Quits the program after printing the help manual
	os._exit(1)
else:
	##Checks to see if the mode entered is a valid mode.
	try:
		for m in modes:
			if sys.argv[1] == m:
				mode = sys.argv[1]
		if mode != sys.argv[1]:
			print("Invalid Mode Selected")
			os._exit(1)
	##Stores the mode into the variable mode
	except:
		print("Invalid Mode Selected")
		os._exit(1)
	##Checks to see if a valid running container has been selected
	try:
		containerInfo = subprocess.check_output("docker ps", shell=True)
		containerInfo = containerInfo.decode()
		containerInfo = containerInfo.split("   ")
		containerInfo = containerInfo[17:]
		if sys.argv[2] == containerInfo[1]:
			container = containerInfo[1]
		else:
			print("Container Either Invalid or Not Running")
			os._exit(1)
	except:
		print("Container Either Invalid or Not Running")
		os._exit(1)
	##Tries to store the flags if any are present
	try:
		flags = sys.argv[3]
	except:
		print("No Flags Selected, Script Will Run in Default Mode")


##for x in flags:
##	print(x)

##Checks to see if the user has submitted any flags
if flags != " ":
	flags = flags[1:]
	if "a" in flags:
		active = True
	if "p" in flags:
		passive = True
	if "v" in flags:
		verbose = True

print(container)
print(mode)

##activeFlag(active)
##passiveFlag(passive)
##verboseFlag(verbose)
##if mode == "static":
##	static(container)

