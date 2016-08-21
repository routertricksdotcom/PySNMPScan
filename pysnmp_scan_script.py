
from pysnmp.hlapi import *
import netaddr


def snmp_devcie_scan(comnty, hostip, ):
    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(),
               CommunityData(comnty, mpModel=0),
               UdpTransportTarget((hostip, 161), timeout=1, retries=0),
               ContextData(),
               ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysName', 0)),
               ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)),
               ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysUpTime', 0)),
               ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysLocation', 0)),
               ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysContact', 0)),
               ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysObjectID', 0)),
               ObjectType(ObjectIdentity('CISCO-SMI', 'sysObjectID', 0)),

               )

    )

    if errorIndication:
        print(errorIndication)
    elif errorStatus:
        print('%s at %s' % (errorStatus.prettyPrint(),
                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
    else:
        for varBind in varBinds:
            # print(' = '.join([x.prettyPrint() for x in varBind]))
            print varBinds
            # return varBinds[0][1], varBinds[1][1], varBinds[2][1], varBinds[3][1]
            # print varBind
            return varBinds

mgmt_ip_list = []
snmp_scanrange = netaddr.IPNetwork('172.16.1.100/24')
for ip in snmp_scanrange.iter_hosts():
    mgmt_ip_list.append(ip)

snmpwalk_data = []
for mgmtIP in mgmt_ip_list:
    # print str(mgmtIP)
    try:
        snmp_raw_data = snmp_devcie_scan(comnty='public', hostip=str(mgmtIP))
        snmpscandata = {'sysname': str(snmp_raw_data[0][1]),
                        'sysdesc': str(snmp_raw_data[1][1]),
                        'sysuptime': str(snmp_raw_data[2][1]),
                        'syslocation': str(snmp_raw_data[3][1]),
                        'syscontact': str(snmp_raw_data[4][1]),
                        'sysobjectid': str(snmp_raw_data[5][1]),
                        'sysobjectid2': str(snmp_raw_data[6][1]),
                        'mgmtIP': str(mgmtIP),
                        }
        snmpwalk_data.append(snmpscandata)
    except:
        print 'snmp scan error %s' % str(mgmtIP)

print snmpwalk_data
