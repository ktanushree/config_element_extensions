#!/usr/bin/env python
"""
CGNX script to enable SSH on interface specified in the CSV or via commandline

tanushree@cloudgenix.com

"""
import cloudgenix
import pandas as pd
import os
import sys
import yaml
from netaddr import IPAddress, IPNetwork
from random import *
import argparse
import logging
import json

# Global Vars
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Config SSH'
CSV_HEADER = ["site","element","interface","prefix","app","action"]

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # will get caught below.
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None

#Global Translation Dictionaries
siteid_sitename_dict = {}
sitename_siteid_dict = {}
elemname_elemid_dict = {}
elemid_elemname_dict = {}
elemid_siteid_dict = {}
elemname_intfnamelist_dict = {}
intfname_intfid_dict = {}
intfid_intfname_dict = {}


def buildtranslationdicts(cgx_session):
    print("INFO: Building translation dicts..")
    print("\tSites")
    resp = cgx_session.get.sites()
    if resp.cgx_status:
        sitelist = resp.cgx_content.get("items",None)

        for site in sitelist:
            sid = site['id']
            sname = site['name']
            if sid == "1":
                continue

            siteid_sitename_dict[sid] = sname
            sitename_siteid_dict[sname] = sid

    print("\tElements")
    resp = cgx_session.get.elements()
    if resp.cgx_status:
        elemlist = resp.cgx_content.get("items", None)

        for elem in elemlist:
            eid = elem['id']
            ename = elem['name']
            sid = elem['site_id']
            if sid == "1":
                continue

            elemname_elemid_dict[ename] = eid
            elemid_elemname_dict[eid] = ename
            elemid_siteid_dict[eid] = sid

            resp = cgx_session.get.interfaces(site_id = sid, element_id = eid)
            if resp.cgx_status:
                intflist = resp.cgx_content.get("items",None)
                interfaces = []
                for intf in intflist:
                    iid = intf['id']
                    iname = intf['name']

                    intfid_intfname_dict[(sid,eid,iid)] = iname
                    intfname_intfid_dict[(sid,eid,iname)] = iid

                    interfaces.append(iname)

                elemname_intfnamelist_dict[ename] = interfaces

    return


def cleanexit(cgx_session):
    print("Logging Out")
    cgx_session.get.logout()
    sys.exit()


def configextention(cgx_session, site, element, interface, prefix, app, action):

    if site in sitename_siteid_dict.keys():
        ssid = sitename_siteid_dict[site]

    else:
        print("ERR: Site {} does not exist".format(site))
        cleanexit(cgx_session)


    if element in elemname_elemid_dict.keys():
        eid = elemname_elemid_dict[element]
        sid = elemid_siteid_dict[eid]
        if ssid != sid:
            print("ERR: Element {} does not belong to site {}".format(element,site))
            cleanexit(cgx_session)

        interfacenamelist = elemname_intfnamelist_dict[element]

        if interface in interfacenamelist:
            iid = intfname_intfid_dict[(sid, eid, interface)]

            resp = cgx_session.get.element_extensions(site_id=sid, element_id=eid)
            if resp.cgx_status:
                extensionlist = resp.cgx_content.get("items", None)

                entitynotfound = True
                for ext in extensionlist:
                    if ext['entity_id'] == iid:
                        entitynotfound = False

                        config = ext.get("conf", None)
                        rules = config.get("rules", None)

                        print("INFO: Configuration rules {} found on {}:{}:{}".format(rules, siteid_sitename_dict[sid], elemid_elemname_dict[eid], interface))

                        rules.append({"app": app, "action": action, "prefix": prefix})
                        config['rules'] = rules
                        ext['conf'] = config

                        resp = cgx_session.put.element_extensions(site_id=sid, element_id=eid, extension_id=ext['id'], data=ext)
                        if resp.cgx_status:
                            print("INFO: Configuration {} edited on {}:{}:{}".format(rules, siteid_sitename_dict[sid], elemid_elemname_dict[eid], interface))
                            cleanexit(cgx_session)

                        else:
                            print("ERR: Could not update configuration to {} on {}:{}:{}".format(rules, siteid_sitename_dict[sid], elemid_elemname_dict[eid], interface))
                            cloudgenix.jd_detailed(resp)
                            cleanexit(cgx_session)

                if entitynotfound:
                    postpayload = {
                        "name": "allowssh",
                        "namespace": "devicemanagement/interface",
                        "entity_id": iid,
                        "disabled": False,
                        "conf": {
                            "rules": [
                                {
                                    "prefix": prefix,
                                    "app": app,
                                    "action": action
                                }
                            ]
                        }
                    }

                    rules = postpayload["conf"]["rules"]
                    resp = cgx_session.post.element_extensions(site_id=sid, element_id=eid, data=postpayload)
                    if resp.cgx_status:

                        print("INFO: Added configuration {} to {}:{}:{}".format(rules, siteid_sitename_dict[sid],elemid_elemname_dict[eid], interface))

                    else:
                        print("ERR: Could not update configuration to {} on {}:{}:{}".format(rules, siteid_sitename_dict[sid], elemid_elemname_dict[eid], interface))
                        cloudgenix.jd_detailed(resp)

        else:
            print("ERR: Interface {} does not exist on element {}".format(interface, element))
            cleanexit(cgx_session)

    else:
        print("ERR: Element {} not found.".format(element))
        cleanexit(cgx_session)

    return

def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default="https://api.elcapitan.cloudgenix.com")

    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-P", help="Use this Password instead of prompting",
                             default=None)

    # Commandline for entering Site info
    config_group = parser.add_argument_group('SSH Config Specific information',
                                           'IP prefix and interface information to enable SSH')
    config_group.add_argument("--site", "-SN", help="Name of the Element", default=None)
    config_group.add_argument("--element", "-EN", help="Name of the Element", default=None)
    config_group.add_argument("--interface", "-IN", help="Interface where you want to enable SSH", default=None)
    config_group.add_argument("--application", "-AP", help="Application you want to add controls to. Accepted values: BGP, DHCP, PING, SNMP, SSH, TRACEROUTE, SpokeHASync", default=None)
    config_group.add_argument("--ipprefix", "-IP", help="IP Prefix", default=None)
    config_group.add_argument("--action", "-AC", help="Action for config. Accepted values: allow or deny", default=None)
    config_group.add_argument("--filename", "-f", help="CSV file containing configuration information. CSV header should match: site,element,interface,ipprefix,app,action", default=None)


    args = vars(parser.parse_args())

    ############################################################################
    # Parse CLI parameters
    ############################################################################
    CONFIGTYPE = None
    filename = args['filename']
    if filename:
        if not os.path.isfile(filename):
            print("ERR: File {} does not exist. Please enter the accurate file".format(filename))
            sys.exit()
        else:
            CONFIGTYPE = "FILE"
    else:
        app = args['application']
        if app not in ["BGP", "DHCP", "PING", "SNMP", "SSH", "TRACEROUTE", "SpokeHASync"]:
            print("ERR: Invalid application: {}. Please choose one: BGP, DHCP, PING, SNMP, SSH, TRACEROUTE or SpokeHASync".format(app))
            sys.exit()

        action = args['action']
        if action not in ["ALLOW", "DENY"]:
            print("ERR: Invalid action: {}. Please choose: ALLOW or DENY".format(action))
            sys.exit()

        element = args['element']
        interface = args['interface']
        prefix = args['ipprefix']
        CONFIGTYPE = "CLI"

    ############################################################################
    # Instantiate API & Login
    ############################################################################

    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=False)
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SDK_VERSION, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # figure out user
    if args["email"]:
        user_email = args["email"]
    elif CLOUDGENIX_USER:
        user_email = CLOUDGENIX_USER
    else:
        user_email = None

    # figure out password
    if args["pass"]:
        user_password = args["pass"]
    elif CLOUDGENIX_PASSWORD:
        user_password = CLOUDGENIX_PASSWORD
    else:
        user_password = None

    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    ############################################################################
    # Build Translation Dictionaries
    ############################################################################
    buildtranslationdicts(cgx_session)

    ############################################################################
    # Configure SSH Extension
    ############################################################################
    if CONFIGTYPE == "CLI":
        configextention(cgx_session=cgx_session, site=site, element=element, interface=interface, prefix=prefix, app=app, action=action)

    else:
        configdata = pd.read_csv(filename)
        columns = list(configdata.columns)

        if set(columns) == set(CSV_HEADER):

            for i,row in configdata.iterrows():
                print("INFO: Configuring row {} from CSV".format(i+1))
                configextention(cgx_session=cgx_session, site=row['site'], element=row['element'], interface=str(row['interface']), prefix=row['prefix'], app=row['app'], action=row['action'])

        else:
            print("ERR: CSV header not in expected format. Please make sure the headers are {}".format(CSV_HEADER))
            cleanexit(cgx_session)


    ############################################################################
    # Logout to clear session.
    ############################################################################
    cleanexit(cgx_session)


if __name__ == "__main__":
    go()