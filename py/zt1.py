#!/usr/bin/env python

import json
import os.path
import platform
import requests
import time
import sys


class ZT1Error(Exception):
    pass


class ZT1NoAuthtoken(ZT1Error):
    pass


class ZT1ValueError(ZT1Error):
    pass


class ZT1ServiceError(ZT1Error):

    def __init__(self, status_code, errcode, errmsg, *args):
        super(ZT1ServiceError, self).__init__(
            status_code, errcode, errmsg, *args)
        self.status_code = status_code
        self.errcode = errcode
        self.errmsg = errmsg
        if errmsg:
            if errcode:
                self.message = "{0}: {1}".format(
                    errcode, errmsg)
            else:
                self.message = str(errmsg)
        elif errcode:
            self.message = str(errcode)
        elif status_code:
            self.message = str(status_code)

    def __str__(self):
        if self.message:
            return self.message
        return repr(self)


class ZT1NotFound(ZT1ServiceError):
    pass


class ZT1Failure(ZT1ServiceError):
    pass


class ZT1Client(object):

    cache_busting = True
    auth_header = True
    zt_home = None

    def __init__(self, url=None, authtoken=None, status=None):
        if self.zt_home is None:
            self.zt_home = self.find_zt_home()
        self.url = url or "http://127.0.0.1:9993"
        self.authtoken = authtoken or self.load_authtoken()
        if not status:
            self.get_status()
        self.status = status or self.get_status()

    def find_zt_home(self):
        """Find the location of zerotier"""
        if platform.system() == "Windows":
            zt_home_c = os.path.join("C:", "ZeroTier", "One")
            try:
                import ctypes.wintypes
                CSIDL_COMMON_APPDATA = 0x23  # Common Application Data
                SHGFP_TYPE_CURRENT = 0       # Want current, not default value
                buf = ctypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
                ctypes.windll.shell32.SHGetFolderPathW(
                    0, CSIDL_COMMON_APPDATA, 0, SHGFP_TYPE_CURRENT, buf)
                appdata = buf.value
                zt_home = os.path.join(appdata, "ZeroTier", "One")
                if os.path.exists(os.path.join(zt_home, "authtoken.secret")):
                    return zt_home
                if os.path.exists(os.path.join(zt_home_c, "authtoken.secret")):
                    return zt_home_c
            except ImportError:
                pass
            return zt_home_c
        zt_homes = {
            "Darwin": "/Library/Application Support/ZeroTier/One",
            " Linux": "/var/lib/zerotier-one",
            None: "/var/db/zerotier-one",
        }
        zt_home = zt_homes.get(platform.system(), zt_homes[None])
        if os.path.exists(zt_home):
            return zt_home
        for zt_home in zt_homes.itervalues():
            if os.path.exists(os.path.join(zt_home, "authtoken.secret")):
                return zt_home
        for zt_home in zt_homes.itervalues():
            if os.path.exists(zt_home):
                return zt_home
        return None

    def load_authtoken(self, fname=None):
        """Load the authentication token from the user home or zt home"""
        if fname is not None:
            self.authtoken = open(fname, "r").read().strip()
            return self.authtoken
        fnames = [
            os.path.expanduser(
                "~/Library/Application Support/ZeroTier/One/authtoken.secret"),
            os.path.expanduser("~/.zeroTierOneAuthToken"),
            "/var/db/zerotier-one/authtoken.secret",
            "/var/lib/zerotier-one/authtoken.secret",
        ]
        if not self.zt_home:
            zt_homed = None
        else:
            zt_homed = os.path.join(self.zt_home, "authtoken.secret")
            fnames.append(zt_homed)
        for fname in fnames:
            if os.path.exists(fname):
                self.authtoken = open(fname, "r").read().strip()
                if self.authtoken:
                    return self.authtoken
        paths = []
        if platform.system() == "Windows":
            pass
        elif platform.system() == "Darwin":
            paths.append(os.path.expanduser(
                "~/Library/Application Support/ZeroTier/One/authtoken.secret"
            ))
        else:
            paths.append(os.path.expanduser("~/.zeroTierOneAuthToken"))
        if zt_homed:
            paths.append(zt_homed)
        paths = "','".join(paths)
        if paths:
            paths = " ({0!r})".format(paths)
        raise ZT1NoAuthtoken("No authtoken found{}".format(paths))

    def get_url(self, path=None, headers=None, params=None):
        """Get an updated url for communication with the local service"""
        if not self.url:
            raise ValueError("Uninitialized or invalid url")
        if not self.authtoken:
            raise ValueError("Uninitialized or invalid authtoken")
        url = "{0}/{1}".format(self.url.rstrip("/"), path.lstrip("/"))
        if headers is None:
            headers = {}
        if params is None:
            params = {}
        if self.auth_header:
            headers["X-ZT1-Auth"] = self.authtoken
        else:
            params["auth"] = self.authtoken
        if self.cache_busting and not params.get("_nocache"):
            params["_nocache"] = int(time.time() * 1000)
        return url, headers, params

    def _do_request(self, method, path, params=None, data=None):
        """Do the get/post/delete"""
        url, headers, params = self.get_url(path, params=params)
        req = getattr(requests, method.lower())(
            url, headers=headers, params=params, data=data)
        if req.status_code == 200:
            return req
        try:
            result = req.json()
        except:
            result = {}
        req.errcode = result.get("errorCode")
        req.errmsg = result.get("errorMessage")
        if req.status_code == 404:
            raise ZT1NotFound(
                req.status_code, req.errcode, req.errmsg,
                method.upper(), path, params, data)
        if 500 <= req.status_code < 600:
            raise ZT1Failure(
                req.status_code, req.errcode, req.errmsg,
                method.upper(), path, params, data)
        raise ZT1ServiceError(
            req.status_code, req.errcode, req.errmsg,
            method.upper(), path, params, data)

    def _get(self, path, params=None):
        return self._do_request("GET", path, params)

    def _post(self, path, params=None, data=None):
        data = json.dumps(data)
        return self._do_request("POST", path, params, data)

    def _delete(self, path, params=None):
        return self._do_request("DELETE", path, params)

    def check_network(self, nwid):
        """Validate the network ID"""
        if len(nwid) == 16:
            try:
                int(nwid, 16)
                return nwid
            except:
                pass
        raise ZT1ValueError("Invalid network", nwid)

    def check_address(self, address):
        """Validate a zt address"""
        if len(address) == 10:
            try:
                int(address, 16)
                return address
            except:
                pass
        print len(address), address
        raise ZT1ValueError("Invalid address", address)

    def get_status(self):
        """Get the status of the local service"""
        self.status = self._get("status").json()
        return self.status

    def get_config(self):
        """Get the configuration of the local service"""
        self.config = self._get("config").json()
        return self.config


class ZT1NodeClient(ZT1Client):

    def get_peer(self, address=None):
        """Get all node peers or a specific peer"""
        if address is None:
            return self._get("peer").json()
        return self._get("peer/{0}".format(self.check_address(address))).json()

    def get_network(self, nwid=None):
        """Get a list of all node networks or a dict of a specific network"""
        if nwid is None:
            return self._get("network").json()
        return self._get("network/{0}".format(self.check_network(nwid))).json()

    def create_network(self, nwid):
        """Create a local network (join)"""
        self._post("network/{0}".format(
            self.check_network(nwid), params={"test": "foo"}))

    def delete_network(self, nwid):
        """Delete a local network (leave)"""
        self._delete("network/{0}".format(self.check_network(nwid)))


class ZT1ControllerClient(ZT1Client):

    nw_defaults = dict(
        # RO nwid, 16-digit hex network ID (string)
        name=None,                      # Short network name (max: 127 chars)
        private=True,                   # False if public network
        enableBroadcast=True,           # True to allow Ethernet broadcast
        allowPassiveBridging=False,     # True to allow any member to bridge
        v4AssignMode="none",            # "none", "zt", or "dhcp"
        v6AssignMode="none",            # "none", "zt", or "dhcp"
        multicastLimit=32,              # Maximum multicast recipients
                                        # per multicast/broadcast address
        # RO creationTime, Time network was created in ms since epoch
        # RO revision, Network config revision number
        # RO members, Array of ZeroTier addresses of network members
        # relays=,   # Array of network-specific relay nodes
        # ipAssignmentPools=, Array of IP auto-assignment pools for "zt"
        # assignment mode
        # rules=, # Array of network flow rules (see below)
    )
    default_rules = [
        {"action": "accept", "ruleNo": 1, "etherType": 0x0800},
        {"action": "accept", "ruleNo": 2, "etherType": 0x0806},
        {"action": "accept", "ruleNo": 3, "etherType": 0x86dd},
    ]

    def get_controller(self):
        return self._get("controller").json()

    def get_network(self, nwid=None):
        """get network list or specific network dict"""
        if nwid is None:
            return self._get("controller/network").json()
        nwid = self.check_network(nwid)
        result = self._get("controller/network/{0}".format(nwid))
        try:
            return result.json()
        except:
            print result.text
            raise
    get_network.help = (
        "get_network [nwid=NetWorkID]\n"
        "    get network list or specific network dict"
    )

    def update_network(self, nwid, **params):
        """Update a network by replacing specified properties"""
        if not nwid:
            nwid = "{0}______".format(self.status["address"])
        else:
            nwid = self.check_network(nwid)
        nw_params = self.nw_defaults.copy()
        if params:
            nw_params.update(params)
        req = self._post("controller/network/{0}".format(nwid), data=nw_params)
        return req.json()
    update_network.help = (
        "update_network [nwid=NetWorkID] [, network properties]\n"
        "    Update a network by replacing specified properties"
    )

    def create_network(self, **params):
        """Create a new network"""
        pre_nw = self.get_network()
        if "rules" not in params and self.default_rules is not None:
            params["rules"] = self.default_rules
        if "nwid" not in params:
            params["nwid"] = None
        self.update_network(**params)
        post_nw = self.get_network()
        new_nw = list([i for i in post_nw if i not in pre_nw])
        return new_nw
    create_network.help = (
        """create_network [network properties]\n"""
        """    Create a new network on the controller with specified """
        """properties\n"""
        """    E.g.: create_network '{"v4AssignMode":"none","name":"Test","""
        """"private":true,"allowPassiveBridging":false}'"""
    )

    def delete_network(self, nwid):
        """Delete a network"""
        nwid = self.check_network(nwid)
        self._delete("controller/network/{0}".format(nwid))
    delete_network.help = (
        "delete_network [nwid=NetWorkID]\n"
        "    Remove a network from the controller"
    )

    def get_member(self, nwid, address=None):
        """Get a network member (node)"""
        if address == 'ffffffffff':
            return
        nwid = self.check_network(nwid)
        if address is None:
            r = self._get("controller/network/{0}/member".format(nwid))
            print r
            print r.text
            return r.json()
            return self._get("controller/network/{0}/member".format(
                nwid)).json()
        address = self.check_address(address)
        return self._get("controller/network/{0}/member/{1}".format(
            nwid, address)).json()
    get_member.help = (
        "get_member nwid=NetworkId, address=member address\n"
        "    Get member info from controller"""
    )

    def update_member(self, nwid, address, **params):
        """Update a network member"""
        nwid = self.check_network(nwid)
        address = self.check_address(address)
        params["nwid"] = nwid
        params["address"] = address
        req = self._post("controller/network/{0}/member/{1}".format(
            nwid, address), data=params)
        return req.json()
    update_member.help = (
        "update_member nwid=NetworkId, address=member [, member properties]\n"
        "    Update member by replacing specified properties"
    )

    def create_member(self, nwid, address, **params):
        """Create a new member in a network"""
        self.update_member(nwid, address, **params)
    create_member.help = (
        "create_member nwid=NetworkId, address=member [, member properties]\n"
        "    Create a new member in a network"
    )

    def delete_member(self, nwid, address):
        """Delete a member from a network"""
        nwid = self.check_network(nwid)
        address = self.check_address(address)
        self._delete("controller/network/{0}/member/{1}".format(
            nwid, address))
    delete_member.help = (
        "delete_member nwid=NetworkId, address=member\n"
        "    Delete a member from a network"
    )


class ZT1(ZT1Client):

    _node = None
    _controller = None

    @property
    def node(self):
        if self._node is None:
            self._node = ZT1NodeClient(self.url, self.authtoken, self.status)
        return self._node

    @property
    def controller(self):
        if self._controller is None:
            self._controller = ZT1ControllerClient(
                self.url, self.authtoken, self.status)
        return self._controller

    def info(self):
        """Get node info"""
        status = self.node.get_status()
        state = "ONLINE" if status["online"] else "OFFLINE"
        print "200 info {address} {state} {version}".format(
            state=state, **status)

    def listpeers(self):
        """List node peers"""
        peers = self.node.get_peer()
        print "200 listpeers <ztaddr> <paths> <latency> <version> <role>"
        for peer in peers:
            ztaddr = peer["address"]
            role = peer["role"]
            version = (
                peer.get("versionMajor", -1),
                peer.get("versionMinor", -1),
                peer.get("versionRev", -1),
            )
            if version[0] < 0 or version[1] < 0 or version[2] < 0:
                version = "-"
            else:
                version = "{}.{}.{}".format(*version)
            latency = peer.get("latency", 0)
            paths = []
            now = int(time.time() * 1000)
            for path in peer.get("paths", []):
                addr = path["address"]
                last_send = path.get("lastSend", 0)
                last_receive = path.get("lastReceive", 0)
                if last_send > 0:
                    last_send = now - last_send
                if last_receive > 0:
                    last_receive = now - last_receive
                if path.get("fixed"):
                    state = "fixed"
                elif path.get("active"):
                    state = "active"
                else:
                    state = "inactive"
                paths.append(
                    "{addr};{last_send};{last_receive};{state}".format(
                        **locals()))
            paths = ",".join(paths) or "-"
            print (
                "200 listpeers "
                "{ztaddr} {paths} {latency} {version} {role}"
            ).format(**locals())

    def listnetworks(self):
        """List node networks"""
        networks = self.node.get_network()
        for network in networks:
            print network
        print (
            "200 listnetworks <nwid> <name> <mac> <status> "
            "<type> <dev> <ZT assigned ips>")
        for network in networks:
            network["ips"] = ",".join(network["assignedAddresses"]) or "-"
            print (
                "200 listnetworks {nwid} {name} {mac} {status} "
                "{type} {portDeviceName} {ips}"
            ).format(**network)

    def join(self, nwid):
        """Join a network"""
        self.node.create_network(nwid)
        print "200 join OK"

    def leave(self, nwid):
        """Leave a network"""
        try:
            self.node.delete_network(nwid)
            print "200 leave OK"
        except ZT1NotFound:
            print "404 leave"

    def dump(self):
        """Dump controller data"""
        for nwid in self.controller.get_network():
            nw = self.controller.get_network(nwid)
            print "create_network", json.dumps(nw)
        for nwid in self.controller.get_network():
            nw = self.controller.get_network(nwid)
            for addr in self.controller.get_member(nwid):
                member = self.controller.get_member(nwid, addr)
                print "create_member", json.dumps(member)
    dump.help = (
        "dump\n"
        "    Dump all controller data needed to restore a controller "
        "with the load command"
    )

    def load(self):
        """Load controller data (from a dump)"""
        nws = {}
        members = {}
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            if line[0] == "#":
                continue
            line = line.strip()
            cmd, params = line.split(" ", 1)
            if cmd == "create_network":
                nw = json.loads(params)
                nws[nw["nwid"]] = nw
            elif cmd == "create_member":
                m = json.loads(params)
                if m is not None:
                    member = {
                        "nwid": m["nwid"],
                        "address": m["address"],
                        "authorized": m.get("authorized", False),
                        "activeBridge": m.get("activeBridge", False),
                        "ipAssignments": m.get("ipAssignments", []),
                    }
                    members[(m["nwid"], m["address"])] = member
        for nw in nws.values():
            try:
                self.controller.create_network(**nw)
            except:
                print nw
                raise
        for m in members.values():
            try:
                self.controller.create_member(**m)
            except:
                print m
                raise
    load.help = "load\n    Load data from dump into controller"

    def networks(self):
        """List all network info from the controller"""
        for nwid in self.controller.get_network():
            nw = self.controller.get_network(nwid)
            print " ", json.dumps(nw)
            for addr in nw["members"]:
                member = self.controller.get_member(nwid, addr)
                print "    *", json.dumps(member)
    networks.help = "networks\n    List all controller networks"

    def authorize(self, nwid, address):
        """Authorize a member on a network"""
        member = self.controller.get_member(nwid, address)
        if not member:
            print "404 member not found"
        member["authorized"] = True
        self.controller.update_member(**member)
    authorize.help = (
        "authorize nwid=NetworkID address=NodeAddress\n"
        "    Authorize a member on a network"
    )

    def setip(self, nwid, address, ips):
        # ips = list([i.strip() for i in ip.split(",") if i.strip()])
        for ip in ips:
            try:
                ipadress, bits = ip.split("/")
                bits = int(bits)
            except:
                print "500 invalid ip", ip
                return
        try:
            member = self.controller.get_member(nwid, address)
        except ZT1NotFound:
            if address != 'ffffffffff':
                print "404 member not found"
                return
            member = self.controller.create_member(
                nwid, address, ipAssignments=ips)
            return "200 setipv4"
        member["ipAssignments"] = ips
        self.controller.update_member(**member)


def cli():
    import argparse
    argparser = argparse.ArgumentParser(
        description="ZeroTier One python client")
    argparser.add_argument(
        "--ctrl",
        action="store_true",
        help="Invoke as controller client",
    )
    argparser.add_argument(
        "-T", "--authtoken",
        type=str,
        metavar="STRING",
        help="Authentication token (default: auto)",
    )
    argparser.add_argument(
        "-U", "--url",
        type=str,
        metavar="URL",
        help=(
            "URL to contact ZeroTierOne service "
            "(default http://127.0.0.1:9993)"
        ),
    )
    argparser.add_argument("cmd", nargs=1)
    argparser.add_argument("arg", nargs="?")
    args = argparser.parse_args()
    if not args.ctrl:
        zt1 = ZT1(args.url, args.authtoken)
        cmd = args.cmd[0]
        arg = [] if args.arg is None else [args.arg]
        if hasattr(zt1, cmd):
            try:
                return getattr(zt1, cmd)(*arg)
            except TypeError:
                raise
                pass
    argparser.print_help()
    sys.exit(1)


def ctrlcli():
    import argparse
    argparser = argparse.ArgumentParser(
        description="ZeroTier One python controller client")
    argparser.add_argument(
        "--ctrl",
        action="store_true",
        help="Invoke as controller client",
    )
    argparser.add_argument(
        "-T", "--authtoken",
        type=str,
        metavar="STRING",
        help="Authentication token (default: auto)",
    )
    argparser.add_argument(
        "-U", "--url",
        type=str,
        metavar="URL",
        help=(
            "URL to contact ZeroTierOne service "
            "(default http://127.0.0.1:9993)"
        ),
    )
    argparser.add_argument(
        "--nwid",
        type=str,
        help="Set or override nwid (network ID)",
    )
    argparser.add_argument(
        "--address",
        type=str,
        help="Set or override node address",
    )
    argparser.add_argument(
        "--json",
        type=str,
        help="Default json parameters",
    )

    argparser.add_argument("cmd", nargs=1)
    argparser.add_argument("params", nargs="*")
    args = argparser.parse_args()
    zt1 = ZT1(args.url, args.authtoken)
    ctrl = zt1.controller
    cmd = args.cmd[0]

    if cmd == "help":
        for inst in (zt1, ctrl):
            for k in dir(inst):
                method = getattr(inst, k, None)
                if method:
                    doc = getattr(method, "help", None)
                    if doc:
                        print doc
        sys.exit(0)
    if hasattr(zt1, cmd):
        cmd_method = getattr(zt1, cmd)
    elif hasattr(ctrl, cmd):
        cmd_method = getattr(ctrl, cmd)
    else:
        sys.stderr.write("Invalid command {!r}\n".format(cmd))
        sys.exit(1)

    if "help" in args.params:
        doc = getattr(cmd_method, "help", None)
        if doc:
            print doc
        if hasattr(zt1, cmd):
            print getattr(zt1, cmd).__doc__
        elif hasattr(ctrl, cmd):
            print getattr(ctrl, cmd).__doc__
        else:
            print "No such command {!r}".format(cmd)
            sys.exit(1)
        sys.exit(0)

    kwargs = {} if args.json is None else json.loads(args.json)
    for param in (args.params or []):
        try:
            kwargs.update(json.loads(param))
            continue
        except:
            pass
        try:
            key, value = param.split("=")
            if value == "true":
                value = True
            elif value == "false":
                value = False
            else:
                try:
                    value = int(value)
                except:
                    pass
            kwargs[key] = value
        except:
            sys.stderr.write("Invalid parameter {!r}\n".format(param))
            sys.exit(1)
    if args.nwid:
        kwargs["nwid"] = args.nwid
    if args.address:
        kwargs["address"] = args.address
    try:
        result = cmd_method(**kwargs)
        if result:
            print json.dumps(result)
        sys.exit(0)
    except TypeError:
        raise
        pass
    argparser.print_help()
    sys.exit(1)


if __name__ == "__main__":
    if (
        sys.argv[0].find("zt1ctrl") == -1 and
        '--ctrl' not in sys.argv[1:]
    ):
        cli()
    else:
        ctrlcli()
