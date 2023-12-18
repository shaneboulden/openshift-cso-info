#!/usr/bin/python
import requests
import sys
import openshift as oc
from collections import defaultdict
import re
import subprocess
import json
import time

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def get_security_data(rhsa, endpoint, params):
    PROXIES = {}
    API_HOST = 'https://access.redhat.com/hydra/rest/securitydata'
    full_query = API_HOST + endpoint + '?' + params + rhsa
    r = requests.get(full_query, proxies=PROXIES)

    if r.status_code != 200:
        print('ERROR: Invalid request; returned {} for the following '
            'query:\n{}'.format(r.status_code, full_query))
        sys.exit(1)

    return r.json()

def cisa_search(cve):
    # perform a search of CISA KEV to see if this CVE is exploitable
    exploits = {}
    CISA_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    cisa_json = requests.get(CISA_URL).json()
    for cisa_cve in cisa_json["vulnerabilities"]:
        if cve == cisa_cve["cveID"]:
            exploits[cve] = cisa_cve

    return exploits

def map_image(image_manifest):
    cmd = subprocess.run(['crane','config',image_manifest], stdout=subprocess.PIPE)
    json_out = json.loads(cmd.stdout.decode('utf-8'))
    return json_out['config']['Labels']['name'] + ":" + json_out['config']['Labels']['release']

def progress_bar(current, total, bar_length=20):
    fraction = current / total

    arrow = int(fraction * bar_length - 1) * '=' + '>'
    padding = int(bar_length - len(arrow)) * ' '

    ending = '\n' if current == total else '\r'

    print(f'[{arrow}{padding}] {int(fraction*100)}%', end=ending)

def main():
    print(f"{bcolors.HEADER}Cluster info:{bcolors.ENDC}")
    print('Current user: {}'.format(oc.whoami()))
    cluster_info=oc.selector("clusterVersion.config.openshift.io/version").objects()[0].model
    print('Cluster version: {}'.format(cluster_info.spec.desiredUpdate.version))
    print('Current channel: {}'.format(cluster_info.spec.channel))
    print('Available updates:')
    for update in cluster_info.status.availableUpdates:
        print('\t'+update['version'])
    

    # Get all vulnerabilities
    vuln_selector = oc.selector("vuln",all_namespaces="True")
    vulns = vuln_selector.objects()


    namespace_map = defaultdict(list)
    image_map = defaultdict(list)
    i = 1
    print("Mapping images")
    for vuln in vulns:
        progress_bar(current=i,total=len(vulns))
        i += 1
        for feature in vuln.model.spec.features:
            image_map[feature.vulnerabilities[0].name].append(map_image(vuln.model.spec.image.strip("sha256") + vuln.model.spec.manifest))
            namespace_map[feature.vulnerabilities[0].name].append(vuln.namespace())
  
    print(f"{bcolors.HEADER}Security advisories:{bcolors.ENDC}")
    # Print some data about the CVEs found so far
    print("Security advisories found: %d\n" % len(namespace_map.keys()))

    # iterate over the CVEs and display info
    for key,items in namespace_map.items():
        print("Security advisory: " + key)
        print("Impacted namespaces: ")
        for namespace in items:
            print("\t" + namespace)

        # key also matches image_map
        print("Impacted images: ")
        for image in image_map[key]:
            print("\t" + image)

        match = re.search("^RHSA-.*$",key)

        if(match):
            # Get the severity from the CSAF
            csaf = get_security_data(rhsa=match.string,endpoint="/csaf.json", params="rhsa_ids=")
            severity = csaf[0]['severity']
            match severity:
                case "critical":
                    print(f"Severity: {bcolors.HEADER}%s {bcolors.ENDC}" % severity)
                case "important":
                    print(f"Severity: {bcolors.FAIL}%s {bcolors.ENDC}" % severity)
                case "moderate":
                    print(f"Severity: {bcolors.WARNING}%s {bcolors.ENDC}" % severity)
                case "low":
                    print(f"Severity: {bcolors.OKGREEN}%s {bcolors.ENDC}" % severity)
                case _:
                    print(f"Severity: {bcolors.WARNING}%s {bcolors.ENDC}" % "unknown")

            # if this looks like a RHSA, get the associated CVEs
            cves = get_security_data(rhsa=match.string, endpoint="/cve.json",params="advisory=")
            print("CVEs:")
            for cve in cves:
                print("\t"+cve['CVE'] + " \t[ https://access.redhat.com/security/cve/"+cve['CVE'] + " ]")
            exploits = cisa_search(cve)
            if(len(exploits.keys()) > 0):
                print("Known exploited:"+ f"{bcolors.FAIL} yes [CVEs appear in CISA KEV] {bcolors.ENDC}")
                print("Exploited CVEs:")
                for cve,cisa_entry in exploits:
                    print("\tCVE: " + cve + ", Date added: " + cisa_entry["dateAdded"])
            else:
                print("Known exploited:" + f"{bcolors.OKGREEN} No [No CVEs appear in CISA KEV] {bcolors.ENDC}")

            # print the patch this is fixed in
            for update in cluster_info.status.availableUpdates:
                if key in update['url']:
                    print("Fixed in: " + update['version'])
        else:
            # If this doesn't look like a RHSA, we don't have a reliable way of getting CVEs
            print("CVEs:\tunknown")
            print("Known exploited:"+ f"{bcolors.WARNING} Unknown {bcolors.ENDC}")
        print('----------------')

if __name__ == "__main__":
    main()