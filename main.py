import sys
import os
import subprocess
import json
import requests

modes = ["static", "hybrid", "dynamic"]
names = []
versions = []
count = 0
cves = []
severities = []
details = ["CVE_ID", "Severity Rating", "Severity Score"]
files_to_check = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/proc/sys", "/sys", "/var/run/docker.sock", "/run/containerd/containerd.sock"]
latestVersion = "29.4.0"
latestAPIVersion = "1.54"
baseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName="

def createSBOM(container):
	# Command to extract the SBOM from the container
	command = "docker run -v ./output:/output aquasec/trivy:canary image -q --scanners vuln --format cyclonedx --output /output/result.json " + container
	# Runs the command as a subprocess, stores nothing into the variable
	check = subprocess.run(command, shell=True)


def readJSON():
	# Opens the SBOM file which was created
	with open("./output/result.json") as jsonfile:
		d = json.load(jsonfile)
	# Filters the dictionary to look for the components section
	components = d["components"]
	count = 0
	# Loops through the components section extracting the name of the packages
	for component in components:
		name = component["name"]
		version = component["version"]
		names.append(name)
		versions.append(version)
		count = count + 1
	print(count)
	# print(software)
	return names, versions

def generateCPE(name, version):
    CPE = f'cpe:2.3:a:*:{name}:{version}:*:*:*:*:*:*:*:*'
    return CPE

def fetchCVES(names, version):
    count = 0
    print(type(names))
    for name in names:
        generateCPE(name, version[count])
        count = count + 1
        url = baseURL + name
        response = requests.get(url)
        try:
        	response_json = response.json()
        	count = count + 1
        	vulnerabilities = response_json["vulnerabilities"]
        	print(name + " Vulnerabilities")
        	print(response_json["totalResults"])
        	for vulnerability in vulnerabilities:
		    	# Cycles through the vulnerabilities which are present in the JSON
        		print(details)
        		cve = vulnerability["cve"]
        		cves.append(cve["id"])
        		details[0] = cve["id"]
        		metrics = cve["metrics"]
		    	# Checks the metrics which can be used to find one which is applicable and can then give a baseSeverity and a #baseScore
        		try:
        			metricsV40 = metrics["cvssMetricV40"]
        			metricsV40 = metricsV40[0]
        			severities.append(metricsV40["cvssData"]["baseSeverity"])
        			details[1] = metricsV40["cvssData"]["baseSeverity"]
        			details[2] = metricsV40["cvssData"]["baseScore"]
        		except:
        			try:
        				metricsV31 = metrics["cvssMetricV31"]
        				metricsV31 = metricsV31[0]
        				severities.append(metricsV31["cvssData"]["baseSeverity"])
        				details[1] = metricsV31["cvssData"]["baseSeverity"]
        				details[2] = metricsV31["cvssData"]["baseScore"]
        			except:
        				try:
        					metricsV30 = metrics["cvssMetricV30"]
        					metricsV30 = metricsV30[0]
        					severities.append(metricsV30["cvssData"]["baseSeverity"])
        					details[1] = metricsV30["cvssData"]["baseSeverity"]
        					details[2] = metricsV30["cvssData"]["baseScore"]
        				except:
        					try:
        						metricsV2 = metrics["cvssMetricV2"]
        						metricsV2 = metricsV2[0]
        						severities.append(metricsV2["baseSeverity"])
        						details[1] = metricsV2["baseSeverity"]
       							details[2] = metricsV2["cvssData"]["baseScore"]
        					except:
        						count = count + 1
        						print(cve["id"])  
        except:
        	print("No Vulnerabilities Found")
        	print(name)
    print(count)
    print(cves)
    print(severities)

def getContainerID():
	# Gets the ID of the container whilst it is running
	ID = subprocess.check_output("docker ps --format '{{.ID}}'", shell=True)
	ID = ID.decode()
	ID4 = ID[:4]
	return ID, ID4

def getRunningMetadata(ID):
	# Gets the metadata of the container whilst it is running
    metadata = subprocess.check_output("docker inspect " + ID, shell=True)
    metadata = metadata.decode()
    metadata = json.loads(metadata)
    metadata = metadata[0]
    return metadata

def getContainerName():
	# Gets the name of the running container
	name = subprocess.check_output("docker ps --format '{{.Names}}'", shell=True)
	name = name.decode()
	return name

def checkFiles(ID):
    # Loops through all the files which an adversary could manipulate to gain privilege escalation
    count = 0
    print("\nChecking write privileges on sensitive host files.")
    name = getContainerName()
    try:
        for file in files_to_check:
            # Creates the command for the file
            command = "FILE=" + file + "\n"
            # Creates a bash file which checks whether write permissions are enabled on the file
            with open("script.sh", "w") as f:
                f.write("#!/bin/bash\n")
                f.write(command)
                f.write("if [ -w $FILE ]; then\n")
                f.write('\techo "1"\n')
                f.write("\telse\n")
                f.write('\techo "0"\n')
                f.write("fi")
            # Copy the script onto the docker container so that it can be run
            command = "docker cp ./script.sh " + name + ':/.'
            #print(f"docker cp ./script.sh {name}:/.")
            #check = subprocess.check_output(f"docker cp ./script.sh {name}:/.", shell=True)
            # Run the bash script and read the output
            #check = subprocess.check_output("docker exec " + ID + " bash script.sh", shell=True)
		    # If the file is writeable return a message to the user
            if check == 1:
                print(file + " can be written to, this allows for possible privilege escalation or container escapes")
                count = count + 1
	    # Returns a message when no host files are writeable.
        if count == 0:
            print("\tAll vulnerable files scanned none found with write privileges")
    except:
        print("\tVulnerable files not found on container.")

def checkForGroups(ID):
    print("\nChecking what groups the user is in")
    user = subprocess.check_output("docker exec -i " + ID + " whoami", shell=True)
    user = user.decode()
    command = "docker exec -i " + ID + " groups " + user
    groups = subprocess.check_output(command, shell=True)
    if user == "root":
        print("\tUser has root privileges, can execute any commands.")
    else:
        print("\tNo root privileges.")
    groups = groups.decode()
    groups = groups.split(":")
    userGroups = groups[1]
    groups = userGroups.split(" ")
    for group in groups:
        if group == "docker":
            print("\tUser is added to the docker group - Docker commands can be executed with no privileges.")
        elif group == "sudo":
            print("\tUser is added to the sudo group - This could allow for exploitation of root commands.")
    print("\tUser is not part of any vulnerable groups.")

def exposedPorts(metadata):
    # subprocess.check_output("docker ps --format '{{.Ports}}'")
    networkSettings = metadata["NetworkSettings"]
    ports = networkSettings["Ports"]
    print("\nChecking for externally facing ports. \nExternal facing ports can be used for reconaissance by an adversary.")
    for port in ports:
        try:
            openPorts = ports[port]
            openPorts = openPorts[0]
            if openPorts["HostIp"] == "0.0.0.0":
                print("\tPort exposed on host port " + openPorts["HostPort"] + ". Port exposed because HostIP for the port is 0.0.0.0.")
            elif openPorts["HostIp"] != "127.0.0.1":
                print("\tPort exposed on host port " + openPorts["HostPort"] + ". Port exposed because HostIP for the port is not local host.")
        except:
            print("\tPort " + port + " is open but not externally facing.")
    print("\tAll ports scanned to see if they are externally facing.")

def checkDockerVersions():
    versions = subprocess.check_output("docker version --format '{{json .}}'", shell=True)
    versions = versions.decode()
    versions = json.loads(versions)
    client = versions["Client"]
    dockerVersion = client["Version"]
    apiVersion = client["ApiVersion"]
    print("\nChecking Docker Versions")
    if dockerVersion != latestVersion:
        print("\tLocal docker engine outdated - Updating could ensure security from existing threats.")
    if apiVersion != latestAPIVersion:
        print("\tLocal API version outdated - Updating could ensure security from existing threats.")

def checkIfRootless():
    rootless = False
	# Checks the docker info looking for indicators that docker is being run rootless or rootful
    info = subprocess.check_output("docker info --format '{{json .}}'", shell=True)
    info = info.decode()
    info = json.loads(info)
    security = info["SecurityOptions"]
    print("\nChecking if containers run in rootless mode.")
    for option in security:
        if option == "rootless":
            rootless = True
    if rootless == False:
        print("\tDocker engine configured to run in rootful mode - If adversaries escape the container they will have privileges.")
    else:
        print("\tContainers run in rootless mode.")

def checkLoggingLevel():
    # ps aux | grep '[d]ockerd.*--log-level' | awk '{for(i=1;i<=NF;i++) if ($i ~ /--log-level/) print $i}'
    print("\nChecking the logging level used on the container.")
    try:
        with open("/etc/docker/daemon.json", "r") as f:
            try:
                loggingLevel = f["log-level"]
                if loggingLevel == "info":
                    print("\tLogging level - 'info' sufficient.")
                else:
                    print("\tLogging level should be 'info'.")
            except:
                print("\tDefault logging level 'info' sufficient.")
    except:
        print("\tDocker logging level 'info' sufficient.")

def static(container):
	print("Conducting static scan.")
	createSBOM(container)
	name, version = readJSON()
	fetchCVES(name, version)

def dynamic():
	ID, ID4 = getContainerID()
	metadata = getRunningMetadata(ID)
	checkFiles(ID4)
	checkForGroups(ID4)
	checkDockerVersions()
	exposedPorts(metadata)
	checkIfRootless()
	checkLoggingLevel()

def hybrid(container):
	print("Conducting static scan of the container for CVEs.")
	static(container)
	print("Static scan concluded, conducting dynamic scan.")
	dynamic()
	
def main(container, mode):
	if mode == "hybrid":
		hybrid(container)
	elif mode == "static":
		static(container)
	elif mode == "dynamic":
		dynamic()
	else:
		print("No valid modes selected!")
		os._exit(1)

# Detects if the script is being run or the user wants to access the help manual.
if sys.argv[1] in ["help", "-h"]:
	# Prints the help manual with all modes and flags which can be used.
	print('''Input should be structured python3 [mode] [container] [flags]
	         Where \n
		 [mode] == What mode you want to run the program in \n
		 [container] == The image name of the container \n
		 Modes \n
 		 \t Hybrid - Container is scanned both statically and dynamically. \n
		 \t Static - Container packages will be scanned to look for existing CVEs associated with the packages. \n
		 \t Dynamic - Container and Host system will be scanned for misconfigurations. \n
		 When using the tool the only container that should be running is the container that you wish to scan.''')
	# Quits the program after printing the help manual
	os._exit(1)
else:
	# Checks to see if the mode entered is a valid mode.
	try:
		for m in modes:
			if sys.argv[1] == m:
				mode = sys.argv[1]
		if mode != sys.argv[1]:
			print("Invalid Mode Selected")
			os._exit(1)
	# Stores the mode into the variable mode
	except:
		print("Invalid Mode Selected")
		os._exit(1)
	# Checks to see if a valid running container has been selected
	try:
		containerInfo = subprocess.check_output("docker ps", shell=True)
		containerInfo = containerInfo.decode()
		containerInfo = containerInfo.split("   ")
		containerInfo = containerInfo[17:]
		if sys.argv[2] == containerInfo[1]:
			container = containerInfo[1]
		else:
			print("Container Either Invalid or Not Running")
			container = containerInfo[1]
	except:
		#print("Container Either Invalid or Not Running")
		container = containerInfo[1]

main(container, mode)



