import sys
import os
import subprocess
import csv
import json
import requests
import pandas as pd
from fireREST import FMC
from getpass import getpass

currentFolder = os.path.abspath(os.path.dirname(__file__))
auth_folder = os.path.abspath(os.path.join(currentFolder, "auth"))
data_folder = os.path.abspath(os.path.join(currentFolder, "data"))
sys.path.insert(0, auth_folder)
sys.path.insert(1, data_folder)

def getMenu():
    menu = True
    while menu:
        print('''
        Multipolar Technology\n
        Cisco FMC Automation
        \nSelect:
        \n[1] Create Network Object
        \n[2] Create Port Object
        \n[3] Create Access Control Rules''')
        selectMenu = input('\nYour Choice: ')
        availableMenu = ('1', '2', '3')

        if selectMenu in availableMenu:
            menu = False
        else:
            os.system('cls')
            print('Invalid input found!\nRepeat...')
    
    return selectMenu

def getACPId(varACPname, varAddress, varUsername, varPasswd):

    fmc = FMC(hostname=varAddress, username=varUsername, password=varPasswd)
    acpid = fmc.policy.accesspolicy.get(name=varACPname)

    return(acpid['id'])

def getToken(varIP, varUser, varPass):
    
    from auth import basicAuth
    tokenList = basicAuth(varIP, varUser, varPass)

    fmcAccessToken = tokenList[0]
    fmcRefreshToken = tokenList[1]
    fmcDomainUUID = tokenList[2]
    
    return [fmcAccessToken,fmcRefreshToken,fmcDomainUUID]

def getObjectId(varObjType, varObjName, varAddress, varUsername, varPasswd):
    
    fmc = FMC(hostname=varAddress, username=varUsername, password=varPasswd)

    if "icmpv4" in varObjType:
        objId = fmc.object.icmpv4object.get(name=varObjName)
        return[objId['id'], objId['name']]
    else:
        return(False)

def createNetObject():

    csvFile = "data/net-object.csv"

    address = input("\nFMC IP Address / FQDN: ")
    username = input ("Username: ")
    password = getpass("Password: ")
    
    token = getToken(address, username, password)

    host_api_uri = "/api/fmc_config/v1/domain/" + token[2] + "/object/hosts"
    host_url = "https://" + address + host_api_uri
    range_api_uri = "/api/fmc_config/v1/domain/" + token[2] + "/object/ranges"
    range_url = "https://" + address + range_api_uri
    network_api_uri = "/api/fmc_config/v1/domain/" + token[2] + "/object/networks"
    network_url = "https://" + address + network_api_uri
    fqdn_api_uri = "/api/fmc_config/v1/domain/" + token[2] + "/object/fqdns"
    fqdn_url = "https://" + address + fqdn_api_uri
    headers = { 'Content-Type': 'application/json', 'x-auth-access-token': token[0] }

    errorLog = []

    with open(csvFile) as csvf:
        csvReader = csv.DictReader(csvf, delimiter=";")
        for rows in csvReader:
            if rows['type'] == "Host":
                rowsJson = json.dumps(rows)
                print('\nSedang Push Object Host', rows['name'])
                response = requests.request("POST", host_url, headers=headers, data = rowsJson, verify=False)
                if response.status_code == 201 or response.status_code == 202:
                    print('Push Object Host', rows['name'], 'sukses!')
                else:
                    print('Push Object Host', rows['name'], 'Gagal...')
                    errorLog.append(response.text)

            elif rows['type'] == "Range":
                rowsJson = json.dumps(rows)
                print('\nSedang Push Object Range', rows['name'])
                response = requests.request("POST", range_url, headers=headers, data = rowsJson, verify=False)
                if response.status_code == 201 or response.status_code == 202:
                    print('Push Object Range', rows['name'], 'sukses!')
                else:
                    print('Push Object Range', rows['name'], 'Gagal...')
                    errorLog.append(response.text)

            elif rows['type'] == "Network":
                rowsJson = json.dumps(rows)
                print('\nSedang Push Object Network', rows['name'])
                response = requests.request("POST", network_url, headers=headers, data = rowsJson, verify=False)
                if response.status_code == 201 or response.status_code == 202:
                    print('Push Object Network', rows['name'], 'sukses!')
                else:
                    print('Push Object Network', rows['name'], 'Gagal...')
                    errorLog.append(response.text)

            elif rows['type'] == "FQDN":
                rowsJson = json.dumps(rows)
                print('\nSedang Push Object FQDN', rows['name'])
                response = requests.request("POST", fqdn_url, headers=headers, data = rowsJson, verify=False)
                if response.status_code == 201 or response.status_code == 202:
                    print('Push Object FQDN', rows['name'], 'sukses!')
                else:
                    print('Push Object FQDN', rows['name'], 'Gagal...')
                    errorLog.append(response.text)
        
    dataLog = '[{}]'.format('\n'.join(errorLog))
    logFile = open("networkobject_error_log.txt", "w")
    logFile.write(dataLog)
    logFile.close()

def createPortObject():

    csvFile = "data/port-object.csv"
    
    address = input("\nFMC IP Address / FQDN: ")
    username = input ("Username: ")
    password = getpass("Password: ")
    
    token = getToken(address, username, password)
        
    port_api_uri = "/api/fmc_config/v1/domain/" + token[2] + "/object/protocolportobjects"
    port_url = "https://" + address + port_api_uri
    headers = { 'Content-Type': 'application/json', 'x-auth-access-token': token[0] }

    errorLog = []

    with open(csvFile) as csvf:
        csvReader = csv.DictReader(csvf, delimiter=";")
        for rows in csvReader:
            rowsJson = json.dumps(rows)
            print('\nSedang Push Object', rows['name'])
            response = requests.request("POST", port_url, headers=headers, data = rowsJson, verify=False)

            if response.status_code == 201 or response.status_code == 202:
                print('Push Object', rows['name'], 'sukses!')
            else:
                print('Push Object', rows['name'], 'Gagal...')
                errorLog.append(response.text)
    
    dataLog = '[{}]'.format('\n'.join(errorLog))
    logFile = open("portobject_error_log.txt", "w")
    logFile.write(dataLog)
    logFile.close()

def createAccessRule():
    
    csvFile = "data/acp-rules.csv"

    address = input("\nFMC IP Address / FQDN: ")
    username = input ("Username: ")
    password = getpass("Password: ")
    acpname = input("ACP name: ")

    acpid = getACPId(acpname, address, username, password)
    
    dfHead = pd.read_csv(csvFile, delimiter=';')
    dfHead.loc[dfHead['protocol'] == 'tcp', 'protocol'] = '6'
    dfHead.loc[dfHead['protocol'] == 'udp', 'protocol'] = '17'
    
    errorLog = []

    for index, row in dfHead.iterrows():
        policyData = {}
        
        nameTuple = (index, row['name'])
        nameList = list(nameTuple)
        nameList.pop(0)
        policyData["name"] = nameList[0]
        
        sendEventTuple = (index, row['sendEventsToFMC'])
        sendEventList = list(sendEventTuple)
        sendEventList.pop(0)
        policyData["sendEventsToFMC"] = str(sendEventList[0])
        
        actionTuple = (index, row['action'])
        actionList = list(actionTuple)
        actionList.pop(0)
        policyData["action"] = actionList[0]
        
        enabledTuple = (index, row['enabled'])
        enabledList = list(enabledTuple)
        enabledList.pop(0)
        policyData['enabled'] = str(enabledList[0])
        
        logTuple = (index, row['logEnd'])
        logList = list(logTuple)
        logList.pop(0)
        policyData['logEnd'] = str(logList[0])
        
        dstPortTuple = (index, row['destinationPorts'], row['protocol'])
        dstPortList = list(dstPortTuple)
        dstPortList.pop(0)
        
        if 'any' not in dstPortList[0] and dstPortList[1]:
            portDataList = []
            portDataDict = {}
            portDataDict["destinationPorts"] = {}
                
            if ',' in dstPortList[0]:
                newDstPortList = dstPortList[0].split(',')
                for index in range(len(newDstPortList)):
                    portSplitDict = {}
                    portSplitDict['type'] = 'PortLiteral'
                    portSplitDict['port'] = newDstPortList[index]
                    portSplitDict['protocol'] = dstPortList[1]
                    portDataList.append(portSplitDict)
                
                portDataDict["destinationPorts"]["literals"] = portDataList

            elif 'ICMP' in dstPortList[0] and dstPortList[1]:
                icmpRequest = getObjectId("icmpv4", "icmp-request", address, username, password)
                icmpReply = getObjectId("icmpv4", "icmp-reply", address, username, password)
                icmpRequestDict = {}
                icmpRequestDict['type'] = 'ICMPV4Object'
                icmpRequestDict['overridable'] = False
                icmpRequestDict['id'] = icmpRequest[0]
                icmpRequestDict['name'] = icmpRequest[1]
                portDataList.append(icmpRequestDict)
                
                icmpReplyDict = {}
                icmpReplyDict['type'] = 'ICMPV4Object'
                icmpReplyDict['overridable'] = False
                icmpReplyDict['id'] = icmpReply[0]
                icmpReplyDict['name'] = icmpReply[1]
                portDataList.append(icmpReplyDict)

                portDataDict["destinationPorts"]["objects"] = portDataList

            else:
                portSingleDict = {}
                portSingleDict['type'] = 'PortLiteral'
                portSingleDict['port'] = dstPortList[0]
                portSingleDict['protocol'] = dstPortList[1]
                portDataList.append(portSingleDict)

                portDataDict["destinationPorts"]["literals"] = portDataList
    
            policyData.update(portDataDict)
        
        srcNetworkTuple = (index, row['sourceNetworks'])
        srcNetworkList = list(srcNetworkTuple)
        srcNetworkList.pop(0)
        
        if 'any' not in srcNetworkList[0]:
            srcNetdataList = []
                
            if ',' in srcNetworkList[0]:
                newSrcNetList = srcNetworkList[0].split(',')
                for index in range(len(newSrcNetList)):
                    if '/32' in newSrcNetList[index]:
                        srcNetSplitDict = {}
                        srcNetSplitDict['type'] = 'Host'
                        srcNetSplitDict['value'] = newSrcNetList[index]
                        srcNetdataList.append(srcNetSplitDict)
                    else:
                        srcNetSplitDict = {}
                        srcNetSplitDict['type'] = 'Network'
                        srcNetSplitDict['value'] = newSrcNetList[index]
                        srcNetdataList.append(srcNetSplitDict)
            else:
                if '/32' in srcNetworkList[0]:
                    srcNetSingleDict = {}
                    srcNetSingleDict['type'] = 'Host'
                    srcNetSingleDict['value'] = srcNetworkList[0]
                    srcNetdataList.append(srcNetSingleDict)
                else:
                    srcNetSingleDict = {}
                    srcNetSingleDict['type'] = 'Network'
                    srcNetSingleDict['value'] = srcNetworkList[0]
                    srcNetdataList.append(srcNetSingleDict)

            srcNetDataDict = {}
            srcNetDataDict["sourceNetworks"] = {}
            srcNetDataDict["sourceNetworks"]["literals"] = srcNetdataList
                
            policyData.update(srcNetDataDict)
        
        dstNetworkTuple = (index, row['destinationNetworks'])
        dstNetworkList = list(dstNetworkTuple)
        dstNetworkList.pop(0)
        
        if 'any' not in dstNetworkList[0]:
            dstNetdataList = []
                
            if ',' in dstNetworkList[0]:
                newDstNetList = dstNetworkList[0].split(',')
                for index in range(len(newDstNetList)):
                    if '/32' in newDstNetList[index]:
                        dstNetSplitDict = {}
                        dstNetSplitDict['type'] = 'Host'
                        dstNetSplitDict['value'] = newDstNetList[index]
                        dstNetdataList.append(dstNetSplitDict)
                    else:
                        dstNetSplitDict = {}
                        dstNetSplitDict['type'] = 'Network'
                        dstNetSplitDict['value'] = newDstNetList[index]
                        dstNetdataList.append(dstNetSplitDict)
            else:
                if '/32' in dstNetworkList[0]:
                    dstNetSingleDict = {}
                    dstNetSingleDict['type'] = 'Host'
                    dstNetSingleDict['value'] = dstNetworkList[0]
                    dstNetdataList.append(dstNetSingleDict)
                else:
                    dstNetSingleDict = {}
                    dstNetSingleDict['type'] = 'Network'
                    dstNetSingleDict['value'] = dstNetworkList[0]
                    dstNetdataList.append(dstNetSingleDict)

            dstNetDataDict = {}
            dstNetDataDict["destinationNetworks"] = {}
            dstNetDataDict["destinationNetworks"]["literals"] = dstNetdataList
                
            policyData.update(dstNetDataDict)
        
        policyJson = json.dumps(policyData)
        
        token = getToken(address, username, password)

        #print(policyJson)
        print('\nSedang Push Rule', policyData['name'])
        api_uri = "/api/fmc_config/v1/domain/" + token[2] + "/policy/accesspolicies/" + acpid + "/accessrules"
        api_url = "https://" + address + api_uri
        headers = { 'Content-Type': 'application/json', 'x-auth-access-token': token[0] }
        response = requests.request("POST", api_url, headers=headers, data = policyJson, verify=False)

        if response.status_code == 201 or response.status_code == 202:
            print('Push Rule', policyData['name'], 'sukses!')
        else:
            print('Push Rule', policyData['name'], 'Gagal...')
            errorLog.append(response.text)
   
    dataLog = '[{}]'.format('\n'.join(errorLog))
    logFile = open("acl_error_log.txt", "w")
    logFile.write(dataLog)
    logFile.close()

if __name__ == "__main__":
    
    fmcFunction = getMenu()

    if fmcFunction == '1':
        createNetObject()
    elif fmcFunction == '2':
        createPortObject()
    elif fmcFunction == '3':
        createAccessRule()
    else:
        getMenu()