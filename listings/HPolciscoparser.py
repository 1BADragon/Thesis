#!/usr/bin/env python

# Cisco Parser for hpol project
# Author: Matthew Brown
# Adviser: Daniel Conte de Leon, PhD
# Center for Secure and Dependable Systems
# University of Idaho

"""
This script converts a cisco style router policy and 
converts it into an HPol style policy graph. As of 
Feb 10, 2016 this scipt can only handle a cisco 
router configuration file that is discribed in the
cisco VPN simulation as discribed at:
http://www.cisco.com/c/en/us/td/docs/security/vpn_modules/6342/vpn_cg/6342site3.html

useage:
    NewPolicyciscoparser.py [flags] [inputfile]

Inputs: 
    filename of cisco configuration 
Flags:
    --debug: prints debugging information
    --nograph: does not display the policy graph
    --nohermes: does not convert policy graph to hermes output
    --help: displays help information

Output:
    policy graph defined by input    
"""

# import nessesary libraries
import HPol
import ciscoconfparse as ccp
import argparse
import sys
import struct
import socket
from socket import inet_aton

# global variables used to define node types
ipaddressType = 'object'
interfaceType = 'object'
cryptoType = 'action'



def getCryptoPolicies(parse):
    """
    Parses out the encryption policies that are
    defined by a cisco configuration file.
    Inputs:
        parse
            cisco parse object of type ciscoconfparse
    Returns:
        cryptoPolicies
            a dictionary consisting of crypto policy 
            containing names and properties of the 
            crypto transform
    """
    # dictionary to be populated
    cryptoPolicies = {}
    # find the crypto policies
    cpParents = parse.find_objects('crypto isakmp policy')
    # loop on each policy
    for parent in cpParents:
        # get the name of the policy
        parentName = parent.text
        policyName = parentName.split()[-1]
        # collect a list of the children
        children = parse.find_children_w_parents(parentName,'')
        # attributes dictionary of crypto policies
        attributes = {}
        # parse the children
        for child in children:
            data = child.split()
            attributes[data[0]] = data[1]
        # add attributes dictionary to policy dictionary
        cryptoPolicies[policyName] = (policyName,attributes)
    # return policy dictionary
    return cryptoPolicies
    
    
    
def getTransformPolicies(parse):
    """
    Parses the Transform policies defined by the 
    cisco configuration file.
    Inputs:
        parse
            cisco parse object of type ciscoconfparse
    Returns:
        transformPolicies
            dictionary of transform Polices containing
            names and properties of each transform
    """
    # create the policy dictionary
    transformPolicies = {}
    # find the transforms in the config file
    transformParents = parse.find_objects('crypto ipsec transform-set')
    # loop over the objects found
    for transforms in transformParents:
        # parse the data
        data = transforms.text
        policyName = 'crypto ipsec transform-set'
        index = data.find(policyName)
        attributes = data[index+len(policyName)+1:].split()
        name = attributes[0]
        transformPolicies[name] = (name,attributes[1:])
    # return transform dictionary
    return transformPolicies
  
  
    
def getInterfaces(parse):
    """
    Parses out all interfaces that are defined in the 
    cisco configuration file. 
    Inputs:
        parse
            cisco parse object of type ciscoconfparse
    Returns:
        interfacePolicies
            dictionary of all interfaces found in the
            configuration file. contains names and 
            attributes relavent to policy creation.
    """
    # policy dictionary
    interfacePolicies = {}
    # gather all interfaces from config file
    interfaceParents = parse.find_objects('interface')
    # loop over interfaces found
    for interface in interfaceParents:
        # attributes dictionary
        attributes = {}
        # get interface name
        parentName = interface.text
        interfaceName = parentName.split()[-1]
        attributes['interfaceName'] = interfaceName
        # find the interface's IP address
        if len(parse.find_children_w_parents(parentName, 'ip address')) > 0:
            ipAddressAttribute = parse.find_children_w_parents(parentName, 'ip address')[0]
            if 'no ip address' not in ipAddressAttribute:
                ipAddress = (ipAddressAttribute.split()[-2],ipAddressAttribute.split()[-1])
            else:
                ipAddress = None
        else:
            ipAddress = None
        # and store the address
        attributes['address'] = ipAddress
        # determine if the interface is a tunnel
        tunnel = parse.find_children_w_parents(parentName, 'tunnel')
        if len(tunnel) != 0:
            # if it is parse the tunnel details
            if 'source' in tunnel[0]:
                ts = tunnel[0].split()[-1]
                td = tunnel[1].split()[-1]
            else:
                td = tunnel[0].split()[-1]
                ts = tunnel[1].split()[-1]
            # store the details in a tuple
            attributes['tunnel'] = (ts,td)
        else:
            attributes['tunnel'] = None
        # if the interface encrypts traffic, find it
        crypto = parse.find_children_w_parents(parentName, 'crypto map')
        if len(crypto) != 0:
            if len(crypto) == 1:
                # and store it
                attributes['crypto'] = crypto[0].split()[-1]
            else:
                cryptoList = []
                for entry in crpyto:
                    cryptoList.append(crypto[0].split()[-1])
                # ditto
                attributes['crypto'] = cryptoList
        else:
            attributes['crypto'] = None
        interfacePolicies[interfaceName] = (interfaceName,attributes)
    # return the dictionary
    return interfacePolicies
    
    

def getTransportModes(parse):
    """
    This Function collect useful information about a VPN
    connection for a given router. I collects information 
    like VPN mode, crypto maps, and VPN peers and stores 
    it in a dictionary.
    Input:
        parse 
            cisco parse object of type ciscoconfparse
    Returns:
        transportModes
            Dictionary of all relevant VPN information
    """
    # define the dictionary
    transportModes = {}
    # gather the mode entrys
    transportModeParent = parse.find_objects('mode transport')
    # loop over them
    for modeEntry in transportModeParent:
        # gather the name
        parentName = modeEntry.text
        attributes = {}
        cryptomaps = {}
        cryptomaps['entries'] = []
        # Because ther are many different fields relavent 
        # to this 'object' some fancy conditions have to 
        # be created for each type of entry.
        # loop over the children
        for child in modeEntry.children:
            # get the name of the child
            childText = child.text
            #  '!' represent comments in the config file
            if '!' in childText:
                #  split out the commented area
                childText = childText.split('!')[0]
            # these if statments test for the various
            # types of children in this parent field
            if 'crypto map' in childText:
                # crypto maps tie the crypto transform to the 
                # interface that is using the crypto
                
                # get the name of the crypto map
                childText = childText.replace('crypto map', '')
                childList = childText.split()
                # test to see if the crypto map has already been defined
                if childList[0] not in cryptomaps:
                    cryptomaps[childList[0]] = {}
                    cryptomaps['entries'].append(childList[0])
                # add relevant information to the dictionary
                if childList[1] == 'local-address':
                    cryptomaps[childList[0]]['interface'] = childList[2]
                if childList[1].isdigit():
                    cryptomaps[childList[0]]['crypto'] = childList[2]
            elif 'set peer' in childText:
                # the 'peer' is the ip address of the router on the 
                # other side of the VPN
                peer = childText.split()[-1]
            elif 'set transform-set' in childText:
                # the transform set ties to the transform to the crypto
                transform = childText.split()[-1]
            elif 'match address' in childText:
                # the match address child referse to an access list that
                # has yet to be defind in the config file. I store the 
                # ID of the access list for later use
                adress = childText.split()[-1]
        # once all relavent data has been collected, store it in an
        # attributes dictionary    
        attributes['cryptomaps'] = cryptomaps
        attributes['peer'] = peer
        attributes['transform-set'] = transform
        attributes['address'] = adress
        transportModes[parentName] = (parentName, attributes)
    return transportModes        
                    
def getAccessLists(parse):
    """
    This function parses out all access lists defined in a given
    cisco configuration file and stores them in a dictionary.
    Input:
        parse
            cisco parse object of type ciscoconfparse
    Returns:
        accessListPolicies
            dictionary of access lists and their attributes
    """
    # create the dictionary
    accessListPolicies = {}
    # find the access lists in the config file
    accessListList = parse.find_objects('access-list')
    # and loop over them
    for entry in accessListList:
        # get the ID of the access list
        temp = entry.text
        textlist = temp.split()
        name = textlist[1]
        # get the permission of the list permit, deny
        if 'permit' in temp:
            permit = True
        else:
            permit = False
        # get the packet type of the access list ip, gre, tcp, udp, etc.
        # i have only defined the gre packet type because it is the only
        # one used in this senario however for real world use all types 
        # would have to be used.
        if 'gre' in temp:
            ALtype = 'gre'
        # other types can be added here in elseifs
        sourceMode = True
        # this loop gathers the hosts defined by the access list
        for i in range(len(textlist)):
            if textlist[i] == 'host':
                if sourceMode:
                    source = textlist[i+1]
                    sourceMode = False
                else:
                    dest = textlist[i+1]
        # store the data in a dictionary
        accessListPolicies[name] = (name, ALtype, source, dest)
    # return
    return accessListPolicies
    
def getIPRoutes(parse):
    """
    This function gathers all predefined IP routes in the config file and stores them in a list. I chose a list for this data because there are no unique IDs for IP Routes. The Rule is just defined.
    Input:
        parse, cisco parse object of type ciscoconfparse
    Returns:
        iproutes, a list of defined IP routes
    """
    # make the list
    iproutes = []
    # find the ip route objects
    routes = parse.find_objects('ip route')
    # loop directly of the object since they have no children objects
    for entry in routes:
        # remove the 'ip route' part of the object
        temp = entry.text.replace('ip route ', '').split()
        # collect the ip of first object
        ip = getIPRange(temp[0], temp[1])
        # collect the name of the interface 
        interface = temp[-1]
        # store
        iproutes.append((ip.replace('/','_'), interface))
    # and return
    return iproutes
    
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# following code adapted from Erik Johnson at http://terminalmage.net
# URL: http://terminalmage.net/2012/06/10/how-to-find-out-the-cidr-notation-for-a-subnet-given-an-ip-and-netmask.html
# Content licensed under a Creative Commons Attribution 4.0 International License, except where indicated otherwise
# Feb 1, 2016
def get_net_size(netmask):
    binary_str = ''
    for octet in netmask:
        binary_str += bin(int(octet))[2:].zfill(8)
    return str(len(binary_str.rstrip('0')))

def getIPRange(ip, subnet):

    #  validate input
    try:
        inet_aton(ip)
        inet_aton(subnet)
    except:
        sys.stderr.write('IP address or netmask invalid\n')
        sys.stderr.write(USAGE)
        sys.exit(2)

    ipaddr = ip.split('.')
    netmask = subnet.split('.')

    #  calculate network start
    net_start = [str(int(ipaddr[x]) & int(netmask[x]))
             for x in range(0,4)]

    #  print CIDR notation
    return '.'.join(net_start) + '/' + get_net_size(netmask)
# end adaption
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# following code adapted from username Debanshu Kundu on stackoverflow.com
# URL:http://stackoverflow.com/questions/819355/how-can-i-check-if-an-ip-is-in-a-network-in-python/23230273# 23230273   
def addressInNetwork(ip, net_n_bits):
   net_n_bits = net_n_bits.replace('_','/')
   ipaddr = struct.unpack('<L', socket.inet_aton(ip))[0]
   net, bits = net_n_bits.split('/')
   netaddr = struct.unpack('<L', socket.inet_aton(net))[0]
   netmask = ((1L << int(bits)) - 1)
   return ipaddr & netmask == netaddr & netmask
# end adaption
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 

def isNotTunnelSubnet(subnet, tunnelPaths, interfaces):
    check = True
    for interfaceName in tunnelPaths:
        for devicePath in tunnelPaths[interfaceName]:
            device = devicePath.split('/')[-1]
            try:
                if addressInNetwork(device, subnet):
                    check = False
            except socket.error:
                device = device.replace('_','/')
                if device in interfaces:
                    deviceAddress = interfaces[device][1]['address'][0]
                    if addressInNetwork(deviceAddress, subnet):
                        check = False
    return check

def createNode(hpol, nodeName, nodePath, nodeType):
    return {'path' : hpol.addNode(type = nodeType, name = nodeName, path = nodePath)}
   
def populateGraph(hpol, deviceName, interfaces, 
                  crytpo, transforms, accessLists, transportModes, ipRoutes):
    interfaceSubnets = {}
    subnetInterfaces = {}
    #this dictionary contains a virtual version of the model (trust me, this is the best way)
    graphPaths = {}
    #populate graph with default things
    graphPaths['path'] = 'deviceName'
    graphPaths['Subjects'] = {'path' : hpol.addDomainDAG(type = 'Subject', name = 'Subject')}
    graphPaths['Actions'] = {'path' : hpol.addDomainDAG(type = 'Action', name = 'Actions')}
    graphPaths['Objects'] = {'path' : hpol.addDomainDAG(type = 'Objects', name = 'Objects')}

    graphPaths['Objects']['IP_addresses'] = createNode(hpol, 'IP_addresses', graphPaths['Objects']['path'], 'Object')
    graphPaths['Subjects']['IP_addresses'] = createNode(hpol, 'IP_addresses', graphPaths['Subjects']['path'], 'Subject')

    graphPaths['Objects']['IP_addresses']['Internal'] = createNode(hpol, 'Internal_IP_addresses', graphPaths['Objects']['IP_addresses']['path'], 'Object')
    graphPaths['Subjects']['IP_addresses']['Internal'] = createNode(hpol, 'Internal_IP_addresses', graphPaths['Subjects']['IP_addresses']['path'], 'Subject')
    
    graphPaths['Objects']['IP_addresses']['External'] = createNode(hpol, 'External_IP_addresses', graphPaths['Objects']['IP_addresses']['path'], 'Object')
    graphPaths['Subjects']['IP_addresses']['External'] = createNode(hpol, 'External_IP_addresses', graphPaths['Subjects']['IP_addresses']['path'], 'Subject')

    graphPaths['Objects']['Interfaces'] = createNode(hpol, 'Interfaces', graphPaths['Objects']['path'], 'Object')
    graphPaths['Subjects']['Interfaces'] = createNode(hpol, 'Interfaces', graphPaths['Subjects']['path'], 'Subject')
    
    graphPaths['Actions']['send'] = createNode(hpol, 'send', graphPaths['Actions']['path'], 'Action')
    graphPaths['Actions']['crypto'] = createNode(hpol, 'crypto', graphPaths['Actions']['path'], 'Action')

    #populate graph with interfaces and subnets for the interfaces and connect the ips (all in this loop)
    for key in interfaces:
        entry = interfaces[key]
        interfaceName = entry[0].replace('/', '_')
        interfaceAttributes = entry[1]
        graphPaths['Objects']['Interfaces'][interfaceName] = createNode(hpol, interfaceName, graphPaths['Objects']['Interfaces']['path'], 'Object')
        SubnodeName = getIPRange(interfaceAttributes['address'][0],interfaceAttributes['address'][1]).replace('/','_')
        ipName = interfaceAttributes['address'][0]
        graphPaths['Objects']['IP_addresses']['Internal'][SubnodeName] = createNode(hpol, SubnodeName, graphPaths['Objects']['IP_addresses']['Internal']['path'], 'Object')
        graphPaths['Objects']['IP_addresses']['Internal'][SubnodeName][ipName] = createNode(hpol, ipName, graphPaths['Objects']['IP_addresses']['Internal'][SubnodeName]['path'], 'Object')
        hpol.addNodeWithUniqueName(subgraphPath = graphPaths['Objects']['Interfaces']['path'], parentPath = graphPaths['Objects']['IP_addresses']['Internal'][SubnodeName][ipName]['path'], type='Object', name=interfaceName)
        graphPaths['Objects']['IP_addresses']['Internal'][SubnodeName][ipName]['interface'] = interfaceName
        graphPaths['Objects']['IP_addresses']['Internal'][SubnodeName][ipName][interfaceName] = graphPaths['Objects']['Interfaces'][interfaceName]
        
        if 'FastEthernet' in interfaceName:
            interfaceSubnets[interfaceName] = SubnodeName
            subnetInterfaces[SubnodeName] = interfaceName
            graphPaths['Subjects']['Interfaces'][interfaceName] = createNode(hpol, interfaceName, graphPaths['Subjects']['Interfaces']['path'], 'Subject')
            graphPaths['Subjects']['IP_addresses']['Internal'][SubnodeName] = createNode(hpol, SubnodeName, graphPaths['Subjects']['IP_addresses']['Internal']['path'], 'Subject')
            graphPaths['Subjects']['IP_addresses']['Internal'][SubnodeName][ipName] = createNode(hpol, ipName, graphPaths['Subjects']['IP_addresses']['Internal'][SubnodeName]['path'], 'Subject')
            hpol.addNodeWithUniqueName(subgraphPath = graphPaths['Subjects']['Interfaces']['path'], parentPath = graphPaths['Subjects']['IP_addresses']['Internal'][SubnodeName][ipName]['path'], type='Subject', name=interfaceName)
            graphPaths['Subjects']['IP_addresses']['Internal'][SubnodeName][ipName]['interface'] = interfaceName
            graphPaths['Objects']['IP_addresses']['Internal'][SubnodeName][ipName][interfaceName] = graphPaths['Objects']['Interfaces'][interfaceName]

    
    #add crypto to graph
    for key in transportModes:
        tMode = transportModes[key]
        attributes = tMode[1]
        cryptomaps = attributes['cryptomaps']
        for entry in cryptomaps['entries']:
            cryptomap = cryptomaps[entry]
            graphPaths['Actions']['crypto'][entry] = createNode(hpol, entry, graphPaths['Actions']['crypto']['path'], 'Action')
            
    #use ipRoutes to find external ipaddresses
    for item in ipRoutes:
        #collect the name of the ip/subnet
        nodeName = item[0]
        #add it to the Objects DAG
        graphPaths['Objects']['IP_addresses']['External'][nodeName] = createNode(hpol, nodeName, graphPaths['Objects']['IP_addresses']['External']['path'], 'Object')
        #add it to the Subjects DAG
        graphPaths['Subjects']['IP_addresses']['External'][nodeName] = createNode(hpol, nodeName, graphPaths['Subjects']['IP_addresses']['External']['path'], 'Subject')
        
    #use Access Lists to find noteable internal/external ip addresses
    for key in accessLists:
        accessList = accessLists[key]
        ips = []
        ips.append(accessList[2])
        ips.append(accessList[3])
        for ip in ips:
            there = False
            #check to make sure its not a known internal ip
            for a in graphPaths['Objects']['IP_addresses']['Internal']:
                if ip in graphPaths['Objects']['IP_addresses']['Internal'][a]:
                    there = True
            if not there:    
                nodeName = ip
                graphPaths['Objects']['IP_addresses']['External'][nodeName] = createNode(hpol,
                                                                                nodeName,
                                                                                graphPaths['Objects']['IP_addresses']['External']['path'],
                                                                                'Object')
    #Define Tunnels
    for key in interfaces:
        entry = interfaces[key]
        interfaceName = entry[0].replace('/', '_')
        interfaceAttributes = entry[1]
        tunnel = interfaceAttributes['tunnel']
        tunnelEndPoints = {}
        tunnelPaths = {}
        if tunnel != None:
            path0 = None
            path1 = None
            there = False
            for sub in graphPaths['Objects']['IP_addresses']['Internal']:
                if tunnel[0] in graphPaths['Objects']['IP_addresses']['Internal'][sub]:
                    there = True
                    path0 = graphPaths['Objects']['IP_addresses']['Internal'][sub][tunnel[0]]
            if there:
                path0 = path0[path0['interface']]['path']
            else:
                there = False
                for sub in graphPaths['Objects']['IP_addresses']['External']:
                    if tunnel[0] in graphPaths['Objects']['IP_addresses']['External'][sub]:
                        there = True
                        path0 = graphPaths['Objects']['IP_addresses']['External'][sub][tunnel[0]]['path']
            there = False
            for sub in graphPaths['Objects']['IP_addresses']['Internal']:
                if tunnel[1] in graphPaths['Objects']['IP_addresses']['Internal'][sub]:
                    there = True
                    path1 = graphPaths['Objects']['IP_addresses']['Internal'][sub][tunnel[1]]
            #print there
            if there:
                path1 = path0[path0['interface']]['path']
            else:
                there = False
                if tunnel[1] in graphPaths['Objects']['IP_addresses']['External']:
                    there = True
                    path1 = graphPaths['Objects']['IP_addresses']['External'][tunnel[1]]['path']
            
            tunnelPath = graphPaths['Objects']['Interfaces'][interfaceName]['path']
            tunnelEndPoints[interfaceName] = (tunnelPath, path1)
            if interfaceAttributes['crypto'] != None:
                cryptoPath = graphPaths['Actions']['crypto'][interfaceAttributes['crypto']]['path']
                hpol.createWildcardLink(fromNode= tunnelPath, toNode = cryptoPath)
                hpol.createWildcardLink(fromNode=cryptoPath, toNode = tunnelPath)

                hpol.createWildcardLink(fromNode=cryptoPath , toNode=path0)
                hpol.createWildcardLink(fromNode=path0, toNode=cryptoPath)
                
                hpol.createWildcardLink(fromNode=path0, toNode=path1)
                hpol.createWildcardLink(fromNode=path1, toNode=path0)
                
                hpol.createWildcardLink(fromNode= tunnelPath, toNode = graphPaths['Actions']['send']['path'])
                hpol.createWildcardLink(fromNode=graphPaths['Actions']['send']['path'], toNode = tunnelPath)
                
               
    #connet subject interfaces to send node
    sendPath = graphPaths['Actions']['send']['path']
    for thing in graphPaths['Subjects']['Interfaces']:
        if thing != 'path':
            stuff = graphPaths['Subjects']['Interfaces'][thing]['path']
            hpol.createWildcardLink(fromNode=sendPath, toNode=stuff)
            hpol.createWildcardLink(fromNode=stuff, toNode=sendPath)
    for thing in graphPaths['Objects']['Interfaces']:
        if thing != 'path' and 'FastEthernet' in thing:
            stuff = graphPaths['Objects']['Interfaces'][thing]['path']
            hpol.createWildcardLink(fromNode=sendPath, toNode=stuff)
            hpol.createWildcardLink(fromNode=stuff, toNode=sendPath)
            
    #create some policies
    
    #internal policies first
    internalsubs = graphPaths['Subjects']['IP_addresses']['Internal']
    internalobjs = graphPaths['Objects']['IP_addresses']['Internal']
    externalobjs = graphPaths['Objects']['IP_addresses']['External']
    externalsubs = graphPaths['Subjects']['IP_addresses']['External']
    for sub1 in internalsubs:
        if sub1 != 'path':
            for sub2 in internalobjs:
                if sub2 != 'path' and sub2 in subnetInterfaces:
                    ppid = hpol.createEmptyPolicyPath(type = 'Policy')
                    hpol.addStartLinkToPolicyPath(ppID = ppid, toNode = internalsubs[sub1]['path'])
                    hpol.addLinkToPolicyPath(ppID = ppid, toNode = graphPaths['Subjects']['Interfaces'][subnetInterfaces[sub1]]['path'],
                                                fromNode = internalsubs[sub1]['path'])
                    hpol.addLinkToPolicyPath(ppID = ppid, toNode = internalobjs[sub2]['path'],
                                                fromNode = graphPaths['Objects']['Interfaces'][subnetInterfaces[sub2]]['path'])
                    hpol.addEndLinkToPolicyPath(ppID = ppid, fromNode = internalobjs[sub2]['path'])
                    
            for route in ipRoutes:
                location = route[0]
                via = route[1]
                ppid = hpol.createEmptyPolicyPath(type = 'Policy')
                hpol.addStartLinkToPolicyPath(ppID = ppid, toNode = internalsubs[sub1]['path'])
                hpol.addLinkToPolicyPath(ppID = ppid, toNode = graphPaths['Subjects']['Interfaces'][subnetInterfaces[sub1]]['path'],
                                                fromNode = internalsubs[sub1]['path'])
                hpol.addLinkToPolicyPath(ppID = ppid, toNode = graphPaths['Objects']['IP_addresses']['External'][location]['path'],
                                                fromNode = tunnelEndPoints[via][1])
                hpol.addEndLinkToPolicyPath(ppID = ppid, fromNode = graphPaths['Objects']['IP_addresses']['External'][location]['path'])
    
    for route in ipRoutes:
        location = route[0]
        via = route[1]
        for sub2 in internalobjs:
            if sub2 != 'path' and sub2 in subnetInterfaces:
                   ppid = hpol.createEmptyPolicyPath(type = 'Policy')
                   hpol.addStartLinkToPolicyPath(ppID = ppid, toNode = graphPaths['Subjects']['IP_addresses']['External'][location]['path'])
                   hpol.addLinkToPolicyPath(ppID = ppid, toNode = tunnelEndPoints[via][1],
                                                fromNode = graphPaths['Subjects']['IP_addresses']['External'][location]['path'])
                   hpol.addLinkToPolicyPath(ppID = ppid, toNode = internalobjs[sub2]['path'],
                                                fromNode = graphPaths['Objects']['Interfaces'][subnetInterfaces[sub2]]['path'])
                   hpol.addEndLinkToPolicyPath(ppID = ppid, fromNode = internalobjs[sub2]['path'])
                                                
                                   
	
def getPolicyDAG(filename, debugMode = False):
    parse = ccp.CiscoConfParse(filename)   
    
    # get device name
    deviceName = parse.find_parents_wo_child('hostname', '')[0].split()[1]
    
    # Get cryto policies
    cryptoPolicies = getCryptoPolicies(parse)
    if debugMode:
        print 'crypto policies:\n', cryptoPolicies
        
    # Get transform-sets
    transformPolicies = getTransformPolicies(parse)
    if debugMode:
        print 'transforms:\n', transformPolicies        
    
    # Get interfaces
    interfacePolicies = getInterfaces(parse)
    if debugMode:
        print 'interfaces:\n', interfacePolicies

    # Get Access Lists
    accessLists = getAccessLists(parse)
    if debugMode:
        print 'access lists:\n', accessLists
        
    # Get ip routes
    ipRoutes = getIPRoutes(parse)
    if debugMode:
        print 'ip Routes:\n', ipRoutes

    # Get Transports Modes
    transportModes = getTransportModes(parse)
    if debugMode:
        print 'Transport Modes:\n', transportModes
        
    hpol = HPol.HPol(type='Type:HpolType', name = deviceName)
    
    populateGraph(hpol, deviceName, 
                  interfacePolicies, 
                  cryptoPolicies, 
                  transformPolicies, 
                  accessLists, transportModes,
                  ipRoutes)
    return hpol
  
        
def main():
    # Set up argument parser
    # inputConfig: file to be parsed
    
    argparser = argparse.ArgumentParser()
    argparser.add_argument("inputConfig", help="Config file to be parsed")
    argparser.add_argument("--debug", help="run with debug mode enabled", action="store_true")
    argparser.add_argument("--nograph", help="do not display graph (debugging)", action="store_true")
    argparser.add_argument("--nohermes", help="disables Hermes style output file", action="store_true")
    
    args = argparser.parse_args()
    
    hpol = getPolicyDAG(args.inputConfig, args.debug)
    
    showGraph = not args.nograph
    if showGraph:
        hpol.show()
        hpol.openZGRViewer()
        #hpol.saveAllGraphFiles()
        
    showHeremes = not args.nohermes
    if showHeremes:
        hpol.convert2Hermes();


if __name__ == "__main__":
    main()
