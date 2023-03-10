from netmiko import ConnectHandler, NetmikoAuthenticationException, NetMikoTimeoutException
from Devices import devices
import re,ipaddress
import logging
import datetime

now = datetime.datetime.now()
logFile = f"Log_{now.year}_{now.month}_{now.day}_{now.hour}_{now.minute}_{now.second}.txt"

# Set up the logger with a handler that writes to the console and a file
logger = logging.getLogger('my_logger')
logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
file_handler = logging.FileHandler(logFile)

logger.addHandler(console_handler)
logger.addHandler(file_handler)

def singleObject(obj):
    logger.info(f"Log generated at: {now} \n")
    new_script = open("Fortigate1.txt", "w")
    new_script = open("Fortigate2.txt", "w")
    new_script = open("Fortigate3.txt", "w")
    new_script = open("SRX.txt", "w")
    # Check for IPv4 Validity
    try:
        ip_object = ipaddress.ip_address(obj)
        logger.info(f"The IP address '{obj}' is valid.")
    except ValueError:
       logger.info(f"The IP address '{obj}' is not valid")
       exit()
    firewallNumber = 0
    logger.info('Trying to Connect to Devices . . .')
    logger.info('Please wait . . .')
    for device in range(len(devices)):
        realObj = obj
        try:
            net_connect = ConnectHandler(**devices[device])
            if firewallNumber == 0:
                logger.info("""
                ========================
                Checking Firewall Fortigate1
                ========================""")
            elif firewallNumber == 1:
                logger.info("""
                ========================
                Checking Firewall Fortigate2
                ========================""")
            elif firewallNumber == 2:
                logger.info("""
                =========================
                Checking Firewall Fortigate3
                =========================""")
            elif firewallNumber == 3:
                logger.info("""
                =========================
                Checking Firewall SRX
                =========================""")
            if firewallNumber < 3:
                object_is_alive = False
                # Determin if C_ or S_ is for object
                showResult = net_connect.send_command(f'show firewall address | grep {realObj}')
                extractObject = re.findall('(".*")', showResult)
                if extractObject :
                    # examining entered object string by user with object found from 'show firewall address | grep '
                    # to avoid mismatches. for example : 192.168.1.24 and 192.168.1.244 are two different IPs
                    # if show command from firewall and entered object by user are exactly the same, then it's ok
                    for eachObject in extractObject :
                        trimedObject = re.search("._(.*)\"",eachObject)
                        rawObject = trimedObject.group(1)
                        if rawObject == realObj:
                            object_is_alive = True
                            realObj = eachObject
                            break
                if object_is_alive == False :
                    logger.info(f'{realObj} does not exist in firewall !!!')
                    logger.info("==============================================\n")
                    firewallNumber +=1
                    continue
                # Check dependencies of the object
                output = net_connect.send_command('diagnose sys cmdb refcnt show firewall.address:name '+realObj)
                mylist = output.splitlines()
                groupList = []
                PolicyList = []
                PBRList = []
                # Spliting dependencies based on policy, group and PBR
                for line in range(len(mylist)):
                    if "policyid" in mylist[line]:
                        tempList = mylist[line].split(' ')
                        PolicyList.append(tempList[-1])
                        logger.info(f"{realObj} in policy: {tempList[-1]}")
                    elif "addrgrp" in mylist[line]:
                        tempList = re.search("'(.*)'.*('.*')", mylist[line])
                        groupList.append(tempList.group(2))
                        logger.info(f"{realObj} in group: {tempList.group(2)}")
                    elif "router" in mylist[line]:
                        tempList = mylist[line].split(' ')
                        PBRList.append(tempList[-1])
                        logger.info(f"{realObj} in PBR: {tempList[-1]}")
                total_dep = len(groupList) + len(PolicyList) + len(PBRList)
                if total_dep > 0:
                    # Building configuration for group dependencies
                    if len(groupList) > 0:
                        if firewallNumber == 0:
                            new_script = open("Fortigate1.txt", "a")
                        elif firewallNumber == 1:
                            new_script = open("Fortigate2.txt", "a")
                        elif firewallNumber == 2:
                            new_script = open("Fortigate3.txt", "a")
                        new_script.write("config firewall addrgrp\n")
                        for j in range(len(groupList)):
                            new_script.write("edit {group}\n".format(group=groupList[j]))
                            new_script.write("unselect member {object}\n".format(object=realObj))
                            new_script.write("next\n")
                        new_script.write("end\n\n")
                    # Building configuration for policy dependencies
                    if len(PolicyList) > 0:
                        if firewallNumber == 0:
                            new_script = open("Fortigate1.txt", "a")
                        elif firewallNumber == 1:
                            new_script = open("Fortigate2.txt", "a")
                        elif firewallNumber == 2:
                            new_script = open("Fortigate3.txt", "a")
                        new_script.write("config firewall policy\n")
                        for j in range(len(PolicyList)):
                            # Check if the object is the only object in the policy
                            myResult = net_connect.send_command(f'show firewall policy {PolicyList[j]}')
                            srcaddResult = re.findall('srcaddr ("[CcSsRr]_.*")', myResult)
                            dstaddrResult = re.findall('dstaddr ("[CcSsRr]_.*")', myResult)
                            if srcaddResult:
                                srcaddrList = srcaddResult[0].split(' ')
                            else:
                                srcaddrList = [str(0)]
                            if dstaddrResult:
                                dstaddrList = dstaddrResult[0].split(' ')
                            else:
                                dstaddrList = [str(0)]
                            if (len(srcaddrList) == 1) and (realObj in srcaddrList[0]):
                                    logger.info(f"{realObj} is the only src address in policy {PolicyList[j]}")
                                    new_script.write(f'delete {PolicyList[j]}\n')
                                    new_script.write("next\n")
                            elif (len(dstaddrList) == 1) and (realObj in dstaddrList[0]):
                                logger.info(f"{realObj} is the only dst address in policy {PolicyList[j]}")
                                new_script.write(f'delete {PolicyList[j]}\n')
                                new_script.write("next\n")
                            else :
                                new_script.write("edit {policy}\n".format(policy=PolicyList[j]))
                                new_script.write("unselect srcaddr {object}\n".format(object=realObj))
                                new_script.write("unselect dstaddr {object}\n".format(object=realObj))
                                new_script.write("next\n")
                        new_script.write("end\n\n")
                    # Building configuration for PBR dependencies
                    if len(PBRList) > 0:
                        if firewallNumber == 0:
                            new_script = open("Fortigate1.txt", "a")
                        elif firewallNumber == 1:
                            new_script = open("Fortigate2.txt", "a")
                        elif firewallNumber == 2:
                            new_script = open("Fortigate3.txt", "a")
                        new_script.write("config router policy\n")
                        for j in range(len(PBRList)):
                            new_script.write("edit {pbr}\n".format(pbr=PBRList[j]))
                            new_script.write("unselect srcaddr {object}\n".format(object=realObj))
                            new_script.write("unselect dstaddr {object}\n".format(object=realObj))
                            new_script.write("next\n")
                        new_script.write("end\n\n")
                    logger.info("There are " + str(total_dep) +" dependencies for " + realObj)
                    logger.info("==============================================\n")
                else:
                    logger.info(f"{realObj} exists but has 0 dependency")
                    logger.info("==============================================\n")
                if firewallNumber == 0:
                    new_script = open("Fortigate1.txt", "a")
                elif firewallNumber == 1:
                    new_script = open("Fortigate2.txt", "a")
                elif firewallNumber == 2:
                    new_script = open("Fortigate3.txt", "a")
                new_script.write("===========================================\n\n")
            elif firewallNumber == 3:
                prompt = net_connect.find_prompt()
                # Finding prompt in SRX
                if '>' in prompt:
                    net_connect.send_command('edit private', expect_string=r'#')
                    tempSrxList = []
                    # Find all dependencies of the object
                    theCommand = 'show logical-systems <YOUR LOGICAL SYSTEM> | match "{object} |{object}{dollar}" | display set'.format(object=realObj,dollar='$')
                    srxOutput = net_connect.send_command(theCommand, read_timeout=30)
                    tempSrxList = srxOutput.splitlines()
                    for line in tempSrxList:
                        new_script = open("SRX.txt", "a")
                        # Check if the object is the only object in the policy
                        if 'policy' in line:
                                policyNumber = re.findall('policy (.*) match', line)
                                logger.info(f"{str(realObj)} in policy: {policyNumber}")
                                srcAddrList = []
                                dstAddrList = []
                                srcTemp1 = ''
                                sliceCommand = re.findall('(set .*) match',line)
                                command = sliceCommand[0].replace('set', 'show',1)
                                policyOutput = net_connect.send_command(command)
                                srcTemp1 = re.findall('source-address (.*);', policyOutput)
                                for src in srcTemp1:
                                    srcTemp2 = src.replace('[','')
                                    srcTemp2 = srcTemp2.replace(']','')
                                    srcAddrList = srcTemp2.strip().split(' ')
                                dstTemp1 = re.findall('destination-address (.*);', policyOutput)
                                for dst in dstTemp1:
                                    dstTemp2 = dst.replace('[','')
                                    dstTemp2 = dstTemp2.replace(']','')
                                    dstAddrList = dstTemp2.strip().split(' ')
                                if (len(srcAddrList) == 1) or (len(dstAddrList) == 1):
                                    for address in srcAddrList :
                                        if len(srcAddrList) == 1 and realObj in address :
                                            logger.info(f"{realObj} is the only src address in policy {policyNumber}")
                                            new_script.write(sliceCommand[0].replace('set', 'delete',1))
                                            new_script.write("\n")
                                        elif len(srcAddrList) == 1 and realObj not in address :
                                            new_script.write(line.replace('set', 'delete',1))
                                            new_script.write('\n')
                                    for address in dstAddrList :
                                        if len(dstAddrList) == 1 and realObj in address :
                                            logger.info(f"{realObj} is the only dst address in policy {policyNumber}")
                                            new_script.write(sliceCommand[0].replace('set', 'delete',1))
                                            new_script.write("\n")
                                        elif len(dstAddrList) == 1 and realObj not in address:
                                            new_script.write(line.replace('set', 'delete',1))
                                            new_script.write('\n')
                                else :
                                    new_script.write(line.replace('set', 'delete',1))
                                    new_script.write('\n')
                        else:
                            # Replace set command with delete command in SRX configuration (only the first set)
                            new_script.write(line.replace('set', 'delete',1))
                            new_script.write("\n")
                    logger.info("There are " + str(len(tempSrxList)) +" dependencies for " + str(realObj))
                    logger.info("==============================================\n")
            if firewallNumber < 3:
                if firewallNumber == 0:
                    new_script = open("Fortigate1.txt", "a")
                elif firewallNumber == 1:
                    new_script = open("Fortigate2.txt", "a")
                elif firewallNumber == 2:
                    new_script = open("Fortigate3.txt", "a")
                # Building object remove configuration for fortigate firewalls
                new_script.write("config firewall address\n")
                new_script.write("delete {object}\n".format(object=realObj))
                new_script.write("end\n\n")
            firewallNumber += 1
        except NetmikoAuthenticationException:
            logger.info("Authentication Failed")
            firewallNumber += 1
        except NetMikoTimeoutException:
            logger.info("Connection Timeout")
            firewallNumber += 1
        # if net_connect.is_alive():
        #     net_connect.disconnect()
        
def listObject(list):
    logger.info(f"Log generated at: {now} \n")
    objectList = []
    firewallNumber = 0
    with open(list) as file:
        for line in file:
            objectList.append(line.rstrip('\n'))
    for i in objectList:
        try:
            ip_object = ipaddress.ip_address(i)
        except ValueError:
            logger.info(f"The IP address '{i}' is not valid in the list")
            # log.write(f"The IP address '{i}' is not valid in the list")
            exit()
    logger.info('Trying to Connect to Devices . . .')
    # log.write('Trying to Connect to Devices . . .')
    logger.info('Please wait . . .')
    # log.write('Please wait . . .')
    for device in range(len(devices)):
        try:
            net_connect = ConnectHandler(**devices[device])
            if firewallNumber == 0:
                logger.info("""
                ========================
                Checking Firewall Fortigate1
                ========================""")
            elif firewallNumber == 1:
                logger.info("""
                ========================
                Checking Firewall Fortigate2
                ========================""")
            elif firewallNumber == 2:
                logger.info("""
                =========================
                Checking Firewall Fortigate3
                =========================""")
            elif firewallNumber == 3:
                logger.info("""
                =========================
                Checking Firewall SRX
                =========================""")
            realObjList = []
            if firewallNumber < 3:
                for i in range(len(objectList)):
                    object_is_alive = False
                    realObj = objectList[i]
                    showResult = net_connect.send_command(f'show firewall address | grep {realObj}')
                    extractObject = re.findall('(".*")', showResult)
                    if extractObject :
                        # examining entered object string by user with object found from 'show firewall address | grep '
                        # to avoid mismatches. for example : 192.168.1.24 and 192.168.1.244 are two different IPs
                        # if show command from firewall and entered object by user are exactly the same, then it is ok
                        for eachObject in extractObject :
                            trimedObject = re.search("._(.*)\"",eachObject)
                            rawObject = trimedObject.group(1)
                            if rawObject == realObj:
                                object_is_alive = True
                                realObj = eachObject
                                realObjList.append(realObj)
                                break
                    if object_is_alive == False :
                        logger.info(f'{realObj} does not exist in firewall !!!')
                        logger.info("==============================================\n")
                        continue
                    output = net_connect.send_command('diagnose sys cmdb refcnt show firewall.address:name '+realObj)
                    mylist = output.splitlines()
                    groupList = []
                    PolicyList = []
                    PBRList = []
                    for line in range(len(mylist)):
                        if "policyid" in mylist[line]:
                            tempList = mylist[line].split(' ')
                            PolicyList.append(tempList[-1])
                            logger.info(f"{realObj} in policy: {tempList[-1]}")
                        elif "addrgrp" in mylist[line]:
                            tempList = re.search("'(.*)'.*('.*')", mylist[line])
                            groupList.append(tempList.group(2))
                            logger.info(f"{realObj} in group: {tempList.group(2)}")
                        elif "router" in mylist[line]:
                            tempList = mylist[line].split(' ')
                            PBRList.append(tempList[-1])
                            logger.info(f"{realObj} in PBR: {tempList[-1]}")
                    total_dep = len(groupList) + len(PolicyList) + len(PBRList)
                    if total_dep > 0:
                        if len(groupList) > 0:
                            if firewallNumber == 0:
                                new_script = open("Fortigate1.txt", "a")
                            elif firewallNumber == 1:
                                new_script = open("Fortigate2.txt", "a")
                            elif firewallNumber == 2:
                                new_script = open("Fortigate3.txt", "a")
                            new_script.write("config firewall addrgrp\n")
                            for j in range(len(groupList)):
                                new_script.write("edit {group}\n".format(group=groupList[j]))
                                new_script.write("unselect member {object}\n".format(object=realObj))
                                new_script.write("next\n")
                            new_script.write("end\n\n")
                        if len(PolicyList) > 0:
                            if firewallNumber == 0:
                                new_script = open("Fortigate1.txt", "a")
                            elif firewallNumber == 1:
                                new_script = open("Fortigate2.txt", "a")
                            elif firewallNumber == 2:
                                new_script = open("Fortigate3.txt", "a")
                            new_script.write("config firewall policy\n")
                            # Check if the object is the only object in the policy
                            for j in range(len(PolicyList)):
                                myResult = net_connect.send_command(f'show firewall policy {PolicyList[j]}')
                                srcaddResult = re.findall('srcaddr ("[CcSsRr]_.*")', myResult)
                                dstaddrResult = re.findall('dstaddr ("[CcSsRr]_.*")', myResult)
                                if srcaddResult:
                                    srcaddrList = srcaddResult[0].split(' ')
                                else:
                                    srcaddrList = [str(0)]
                                if dstaddrResult:
                                    dstaddrList = dstaddrResult[0].split(' ')
                                else:
                                    dstaddrList = [str(0)]
                                if (len(srcaddrList) == 1) and (realObj in srcaddrList[0]):
                                    logger.info(f"{realObj} is the only src address in policy {PolicyList[j]}")
                                    new_script.write(f'delete {PolicyList[j]}\n')
                                    new_script.write("next\n")
                                elif (len(dstaddrList) == 1) and (realObj in dstaddrList[0]):
                                    logger.info(f"{realObj} is the only dst address in policy {PolicyList[j]}")
                                    new_script.write(f'delete {PolicyList[j]}\n')
                                    new_script.write("next\n")
                                else :
                                    new_script.write("edit {policy}\n".format(policy=PolicyList[j]))
                                    new_script.write("unselect srcaddr {object}\n".format(object=realObj))
                                    new_script.write("unselect dstaddr {object}\n".format(object=realObj))
                                    new_script.write("next\n")
                            new_script.write("end\n\n")
                        if len(PBRList) > 0:
                            if firewallNumber == 0:
                                new_script = open("Fortigate1.txt", "a")
                            elif firewallNumber == 1:
                                new_script = open("Fortigate2.txt", "a")
                            elif firewallNumber == 2:
                                new_script = open("Fortigate3.txt", "a")
                            new_script.write("config router policy\n")
                            for j in range(len(PBRList)):
                                new_script.write("edit {pbr}\n".format(pbr=PBRList[j]))
                                new_script.write("unselect srcaddr {object}\n".format(object=realObj))
                                new_script.write("unselect dstaddr {object}\n".format(object=realObj))
                                new_script.write("next\n")
                            new_script.write("end\n\n")
                        logger.info("There are " + str(total_dep) +" dependencies for " + realObj)
                        logger.info("==============================================\n")
                    else:
                        logger.info(f"{realObj} exists but has 0 dependency")
                        logger.info("==============================================\n")
                    if firewallNumber == 0:
                        new_script = open("Fortigate1.txt", "a")
                    elif firewallNumber == 1:
                        new_script = open("Fortigate2.txt", "a")
                    elif firewallNumber == 2:
                        new_script = open("Fortigate3.txt", "a")
                    new_script.write("===========================================\n\n")
            elif firewallNumber == 3:
                prompt = net_connect.find_prompt()
                if '>' in prompt:
                    net_connect.send_command('edit private', expect_string=r'#')
                    for i in range(len(objectList)):
                        realObj = objectList[i]
                        tempSrxList = []
                        # Find all dependencies of the object
                        theCommand = 'show logical-systems <YOUR LOGICAL SYSTEM> | match "{object} |{object}{dollar}" | display set'.format(object=realObj, dollar='$')
                        srxOutput = net_connect.send_command(theCommand, read_timeout=30)
                        tempSrxList = srxOutput.splitlines()
                        for line in tempSrxList:
                            new_script = open("SRX.txt", "a")
                            # Check if the object is the only object in the policy
                            if 'policy' in line:
                                policyNumber = re.findall('policy (.*) match', line)
                                logger.info(f"{str(realObj)} in policy: {policyNumber}")
                                srcAddrList = []
                                dstAddrList = []
                                srcTemp1 = ''
                                sliceCommand = re.findall('(set .*) match',line)
                                command = sliceCommand[0].replace('set', 'show',1)
                                policyOutput = net_connect.send_command(command)
                                srcTemp1 = re.findall('source-address (.*);', policyOutput)
                                for src in srcTemp1:
                                    srcTemp2 = src.replace('[','')
                                    srcTemp2 = srcTemp2.replace(']','')
                                    srcAddrList = srcTemp2.strip().split(' ')
                                dstTemp1 = re.findall('destination-address (.*);', policyOutput)
                                for dst in dstTemp1:
                                    dstTemp2 = dst.replace('[','')
                                    dstTemp2 = dstTemp2.replace(']','')
                                    dstAddrList = dstTemp2.strip().split(' ')
                                if (len(srcAddrList) == 1) or (len(dstAddrList) == 1):
                                    for address in srcAddrList :
                                        if len(srcAddrList) == 1 and realObj in address :
                                            logger.info(f"{realObj} is the only src address in policy {policyNumber}")
                                            new_script.write(sliceCommand[0].replace('set', 'delete',1))
                                            new_script.write("\n")
                                        elif len(srcAddrList) == 1 and realObj not in address :
                                            new_script.write(line.replace('set', 'delete',1))
                                            new_script.write('\n')
                                    for address in dstAddrList :
                                        if len(dstAddrList) == 1 and realObj in address :
                                            logger.info(f"{realObj} is the only dst address in policy {policyNumber}")
                                            new_script.write(sliceCommand[0].replace('set', 'delete',1))
                                            new_script.write("\n")
                                        elif len(dstAddrList) == 1 and realObj not in address:
                                            new_script.write(line.replace('set', 'delete',1))
                                            new_script.write('\n')
                                else :
                                    new_script.write(line.replace('set', 'delete',1))
                                    new_script.write('\n')
                            # Replace set command with delete command in SRX configuration (only the first set)
                            else :
                                new_script.write(line.replace('set', 'delete',1))
                                new_script.write('\n')
                        logger.info("There are " + str(len(tempSrxList)) +" dependencies for " + str(realObj))
                        logger.info("==============================================\n")
            if firewallNumber < 3:
                if firewallNumber == 0:
                    new_script = open("Fortigate1.txt", "a")
                elif firewallNumber == 1:
                    new_script = open("Fortigate2.txt", "a")
                elif firewallNumber == 2:
                    new_script = open("Fortigate3.txt", "a")
                new_script.write("config firewall address\n")
                for j in range(len(realObjList)):
                    new_script.write("delete {object}\n".format(object=realObjList[j]))
                new_script.write("end\n\n")
            firewallNumber += 1
        except NetmikoAuthenticationException:
            logger.info("Authentication Failed")
            firewallNumber += 1
        except NetMikoTimeoutException:
            logger.info("Connection Timeout")
            firewallNumber += 1
        # if net_connect.is_alive():
        #     net_connect.disconnect()
