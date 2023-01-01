import xml.etree.ElementTree as ET
from datetime import date


#Whenever you see variables.var_name these are environment variables you set yourself. 

#DONT CHANGE THE VALUES OR IT WILL CORRUPT YOUR .CKL!!!
validOutcomes = {
    'NA': 'Not_Applicable',
    'NF': 'NotAFinding',
    'OPEN': 'Open',
    'NR': 'Not_Reviewed'
}

today = date.today()

ckl_name = variables.CHECKLIST_NAME
path = variables.CHECKLIST_PATH 
loc = path + ckl_name

try:
    tree = ET.parse(loc)
    root = tree.getroot()
except:
    print('FATAL ERROR: ' + ckl_name + ' not found in: ' + path)


def get_vuln_ids():
    vulns = []
    for child in root.findall('.//VULN'):
        if child.find('.//VULN_ATTRIBUTE').text == 'Vuln_Num':
            vulns.append(child.find('.//ATTRIBUTE_DATA').text)
    return vulns


def set_vuln_status(key, value):
    for child in root.findall('.//VULN'):
        # print(child.find('.//VULN_ATTRIBUTE').text)
        if child.find('.//VULN_ATTRIBUTE').text == 'Vuln_Num':
            # print(child.find('.//ATTRIBUTE_DATA').text)
            if child.find('.//ATTRIBUTE_DATA').text == key:
                findingDetails = child.find('./FINDING_DETAILS')
                # print(findingDetails.text)
                findingDetails.text = ' Tool: Netmiko \n Completed on: ' + str(today) + ' \n Status: ' + value
                findingStatus = child.find('./STATUS')
                findingStatus.text = value


# Needed new method here as Python does not support method overloads 
# This method will will add what commands are missing to comments section.
def set_vuln_status_open(key, value, missing):
    for child in root.findall('.//VULN'):
        # print(child.find('.//VULN_ATTRIBUTE').text)
        if (child.find('.//VULN_ATTRIBUTE').text == 'Vuln_Num'):
            # print(child.find('.//ATTRIBUTE_DATA').text)
            if (child.find('.//ATTRIBUTE_DATA').text == key):
                findingDetails = child.find('./FINDING_DETAILS')
                # print(findingDetails.text)
                findingDetails.text = ' Tool: Netmiko \n Completed on: ' + str(today) + ' \n Status: ' + value
                findingStatus = child.find('./STATUS')
                findingStatus.text = value
                findingComments = child.find('./COMMENTS')
                missing_items = ' '.join([str(item) for item in missing])  # convert list to string
                findingComments.text = 'The following commands did not take properly: \n' + missing_items


def get_vuln_status(key):
    for child in root.findall('.//VULN'):
        # print(child.find('.//VULN_ATTRIBUTE').text)
        if child.find('.//VULN_ATTRIBUTE').text == 'Vuln_Num':
            # print(child.find('.//ATTRIBUTE_DATA').text)
            if child.find('.//ATTRIBUTE_DATA').text == key:
                findingStatus = child.find('./STATUS')
                return findingStatus.text


def set_hostname(hostname):
    for host in root.findall('.//HOST_NAME'):
        host.text = hostname


def set_ip_address(ipaddress):
    for ip in root.findall('.//HOST_IP'):  
      ip.text = ipaddress


def get_hostname():
    for host in root.findall('.//HOST_NAME'):
        return host.text


def save(hostname):
    loc = path + hostname + '_' + ckl_name
    tree.write(loc)


