import time
import urllib
import requests
from lxml import etree
import ssl
from OpenSSL import crypto
from pyVim import connect


class VCenter(object):
    """docstring for Vcenter"""
    def __init__(self, username, password, hostname, 
                 proxy_ipaddr=None, proxy_port=443):
        self.username = username
        self.password = password
        self.hostname = hostname
        self.proxy_ipaddr = proxy_ipaddr
        self.proxy_port = proxy_port
        if proxy_ipaddr is not None:
            self.host = proxy_ipaddr
            self.port = proxy_port
        else:
            self.host = hostname
            self.port = 443

        # python 2.7.9 (or maybe newer) causes 'certificate verify failed'
        # exception when connect.Connect(). The following monkey patch is
        # to get around this problem. Hopefully next version of pyvmomi
        # will allow us to ignore this error but until that happens, let
        # me use this monkey patch.
        try:
            _create_unverified_https_context = ssl._create_unverified_context
        except AttributeError:
            # Legacy Python that doesn't verify HTTPS certificates by default
            pass
        else:
            # Handle target environment that doesn't support HTTPS verification
            ssl._create_default_https_context = _create_unverified_https_context

        searcher = connect.Connect(self.host, self.port, username,
                                   password).content.searchIndex
        self.finder = searcher.FindByInventoryPath

    def get_thumbprint(self):
        """docstring for get_thumbprint"""
        cert = ssl.get_server_certificate((self.host, self.port))
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        return x509.digest('sha1')

# class SecurityGroup:
#    def __init__(self, name):
#        self.name = name
#
#    @classmethod
#    def fromxml(cls, xml):
#        root = etree.fromstring(xml)
#        name = root.xpath("/securitygroup/name/text()")[0]
#        return cls(name)
#
#    def toxml(self, pretty_print=False):
#        """docstring for toxml"""
#        root = etree.Element("securitygroup")
#        etree.SubElement(root, "name").text = self.name
#        return etree.tostring(root, pretty_print=pretty_print)

class VCenterInfo(object):
    """docstring for vCenterInfo"""
    def __init__(self, vc):
        self.vc = vc

    def toxml(self):
        root = etree.Element('vcInfo')
        etree.SubElement(root, 'ipAddress').text = self.vc.hostname
        etree.SubElement(root, 'userName').text = self.vc.username
        etree.SubElement(root, 'password').text = self.vc.password
        thumbprint = self.vc.get_thumbprint()
        etree.SubElement(root, 'certificateThumbprint').text = thumbprint
        return etree.tostring(root)


class IpPool(object):
    """docstring for IpPool"""
    def __init__(self, name, gateway, prefix_len, start, end,
                 primary_dns=None, secondary_dns=None, suffix=None):
        self.name = name
        self.gateway = gateway
        self.prefix_len = prefix_len
        self.start = start
        self.end = end
        self.primary_dns = primary_dns
        self.secondary_dns = secondary_dns
        self.suffix = suffix
        
    def toxml(self):
        """docstring for toxml"""
        dto = etree.Element('ipRangeDto')
        etree.SubElement(dto, 'startAddress').text = self.start
        etree.SubElement(dto, 'endAddress').text = self.end
        ranges = etree.Element('ipRanges')
        ranges.append(dto)
        root = etree.Element('ipamAddressPool')
        etree.SubElement(root, 'name').text = self.name
        etree.SubElement(root, 'prefixLength').text = str(self.prefix_len)
        etree.SubElement(root, 'gateway').text = self.gateway
        if self.suffix is not None:
            etree.SubElement(root, 'dnsSuffix').text = self.suffix
        if self.primary_dns is not None:
            etree.SubElement(root, 'dnsServer1').text = self.primary_dns
        if self.secondary_dns is not None:
            etree.SubElement(root, 'dnsServer2').text = self.secondary_dns
        root.append(ranges)
        return etree.tostring(root)


class Controller(object):
    """docstring for Controller"""
    def __init__(self, nsx, datacenter, cluster, datastore, connected_to,
                 ip_pool, password):
        self.nsx = nsx
        self.datacenter = datacenter
        self.cluster = cluster
        self.datastore = datastore
        self.connected_to = connected_to
        self.ip_pool = ip_pool
        self.password = password
        self.cluster_id = nsx.find_cluster_id(datacenter, cluster) 
        self.datastore_id = nsx.find_datastore_id(datacenter, datastore)
        self.connected_to_id = nsx.find_network_id(datacenter, connected_to)
        self.ip_pool_id = nsx.find_ip_pool_id(ip_pool)  
        
    def toxml(self):
        """docstring for toxml"""
        root = etree.Element('controllerSpec')
        etree.SubElement(root, 'ipPoolId').text = self.ip_pool_id
        etree.SubElement(root, 'resourcePoolId').text = self.cluster_id
        etree.SubElement(root, 'datastoreId').text = self.datastore_id
        etree.SubElement(root, 'deployType').text = "medium"
        etree.SubElement(root, 'networkId').text = self.connected_to_id
        etree.SubElement(root, 'password').text = self.password
        return etree.tostring(root)


class HostPrep(object):
    """docstring for HostPrep"""
    def __init__(self, nsx, datacenter, cluster):
        self.nsx = nsx
        self.datacenter = datacenter
        self.cluster = cluster
        self.cluster_id = nsx.find_cluster_id(datacenter, cluster)

    def toxml(self):
        """docstring for toxml"""
        resource_config = etree.Element('resourceConfig')
        etree.SubElement(resource_config, 
                         'resourceId').text = self.cluster_id
        root = etree.Element('nwFabricFeatureConfig')
        root.append(resource_config)
        return etree.tostring(root)


class VxlanPrep(object):
    """docstring for VxlanPrep"""
    def __init__(self, nsx, datacenter, cluster, switch, vlan, mtu, ip_pool,
                 teaming, n_vteps):
        self.nsx = nsx
        self.datacenter = datacenter
        self.cluster = cluster
        self.switch = switch
        self.vlan = vlan
        self.mtu = mtu
        self.ip_pool = ip_pool
        self.teaming = teaming
        self.n_vteps = n_vteps
        self.cluster_id = nsx.find_cluster_id(datacenter, cluster)
        self.switch_id = nsx.find_network_id(datacenter, switch)
        self.ip_pool_id = nsx.find_ip_pool_id(ip_pool)

    def toxml(self):
        """docstring for toxml"""
        switch1 = etree.Element('switch')
        etree.SubElement(switch1, 'objectId').text = self.switch_id
        config_spec_cluster = etree.Element('configSpec', 
                                             {'class': 'clusterMappingSpec'})
        config_spec_cluster.append(switch1)
        etree.SubElement(config_spec_cluster, 
                         'vlanId').text = str(self.vlan)
        etree.SubElement(config_spec_cluster,
                         'vmknicCount').text = str(self.n_vteps)
        etree.SubElement(config_spec_cluster,
                         'ipPoolId').text = self.ip_pool_id
        resource_config1 = etree.Element('resourceConfig')
        etree.SubElement(resource_config1, 
                         'resourceId').text = self.cluster_id
        resource_config1.append(config_spec_cluster)
        
        switch2 = etree.Element('switch')
        etree.SubElement(switch2, 'objectId').text = self.switch_id
        config_spec_vds = etree.Element('configSpec',
                                         {'class': 'vdsContext'})
        config_spec_vds.append(switch2)
        etree.SubElement(config_spec_vds,'mtu').text = str(self.mtu)
        etree.SubElement(config_spec_vds,'teaming').text = self.teaming
        
        resource_config2 = etree.Element('resourceConfig')
        etree.SubElement(resource_config2, 
                         'resourceId').text = self.switch_id
        resource_config2.append(config_spec_vds)
        
        root = etree.Element('nwFabricFeatureConfig')
        etree.SubElement(root, 
                         'featureId').text = 'com.vmware.vshield.vsm.vxlan'
        root.append(resource_config1)
        root.append(resource_config2)
        return etree.tostring(root)


class Segment(object):
    """docstring for Segment"""
    def __init__(self, begin, end):
        self.begin = begin
        self.end = end
        
    def toxml(self):
        """docstring for toxml"""
        root = etree.Element('segmentRange')
        etree.SubElement(root, 'name').text = '%d-%d' % (self.begin, self.end)
        etree.SubElement(root, 'begin').text = str(self.begin)
        etree.SubElement(root, 'end').text = str(self.end)
        return etree.tostring(root)


class TransportZone(object):
    """docstring for TransportZone"""
    def __init__(self, nsx, name, datacenter, clusters, mode='UNICAST_MODE'):
        self.nsx = nsx
        self.name = name
        self.datacenter = datacenter
        self.clusters = clusters
        self.mode = mode
        self.clusters_id = [nsx.find_cluster_id(datacenter, cluster) for
                            cluster in clusters]
        
    def toxml(self):
        """docstring for toxml"""
        clusters = etree.Element('clusters')
        for cluster_id in self.clusters_id:
            cluster2 = etree.Element('cluster')
            etree.SubElement(cluster2, 'objectId').text = cluster_id
            cluster1 = etree.Element('cluster')
            cluster1.append(cluster2)
            clusters.append(cluster1)
            
        root = etree.Element('vdnScope')
        etree.SubElement(root, 'name').text = self.name
        root.append(clusters)
        etree.SubElement(root, 'controlPlaneMode').text = self.mode
        return etree.tostring(root)


class LogicalSwitch(object):
    """docstring for LogicalSwitch"""
    def __init__(self, name, transport_zone, mode='UNICAST_MODE'):
        self.name = name
        self.transport_zone = transport_zone
        self.mode = mode
        
    def toxml(self):
        """docstring for toxml"""
        root = etree.Element('virtualWireCreateSpec')
        etree.SubElement(root, 'name').text = self.name
        # looks like tenantId can be anything
        etree.SubElement(root, 'tenantId').text = 'virtual wire tenant'
        etree.SubElement(root, 'controlPlaneMode').text = self.mode
        return etree.tostring(root)
        

class Vnic(object):
    """docstring for VnicDto"""
    def __init__(self, nsx, logical_switch, datacenter, vm):
        self.nsx = nsx
        self.logical_switch = logical_switch
        self.datacenter = datacenter
        self.vm = vm
        self.vnic_uuid = nsx.find_instance_uuid(datacenter, vm) + '.000'
        self.logical_switch_id = nsx.find_logical_switch_id(logical_switch)
 
    def toxml(self):
        """docstring for fname"""
        root = etree.Element('com.vmware.vshield.vsm.inventory.dto.VnicDto')
        etree.SubElement(root, 'vnicUuid').text = self.vnic_uuid
        etree.SubElement(root, 'portgroupId').text = self.logical_switch_id
        return etree.tostring(root)
        

class Dlr(object):
    """docstring for Dlr"""
    def __init__(self, nsx, name, username, password, datacenter, cluster,
                 datastore, mgmt_iface, interfaces):
        self.nsx = nsx
        self.name = name
        self.username = username
        self.password = password
        self.datacenter = datacenter
        self.cluster = cluster
        self.datastore = datastore
        self.mgmt_iface = mgmt_iface
        self.interfaces = interfaces
        self.cluster_id = nsx.find_cluster_id(datacenter, cluster) 
        self.datastore_id = nsx.find_datastore_id(datacenter, datastore)
        self.mgmt_iface_id = nsx.find_network_id(datacenter, mgmt_iface)
        self.interfaces_id = interfaces
        for iface in interfaces:
            # TODO: need to support VDS
            iface['connected_to'] = nsx.find_logical_switch_id(iface['connected_to'])
        
    def toxml(self):
        """docstring for toxml"""
        root = etree.Element('edge')
        etree.SubElement(root, 'name').text = self.name
        appliances = etree.Element('appliances')
        appliance = etree.Element('appliance')
        etree.SubElement(appliance, 'resourcePoolId').text = self.cluster_id
        etree.SubElement(appliance, 'datastoreId').text = self.datastore_id
        appliances.append(appliance)
        root.append(appliances)
        cli = etree.Element('cliSettings')
        etree.SubElement(cli, 'userName').text = self.username
        etree.SubElement(cli, 'password').text = self.password
        root.append(cli)
        etree.SubElement(root, 'type').text = 'distributedRouter'
        mgmt_iface = etree.Element('mgmtInterface')
        etree.SubElement(mgmt_iface, 'connectedToId').text = self.mgmt_iface_id
        root.append(mgmt_iface)
        
        ifaces = etree.Element('interfaces')
        for iface in self.interfaces_id:
            interface = etree.Element('interface')
            etree.SubElement(interface, 'name').text = iface['name']
            addrgroups = etree.Element('addressGroups')
            addrgroup = etree.Element('addressGroup')
            etree.SubElement(addrgroup, 
                             'primaryAddress').text = iface['address']
            etree.SubElement(addrgroup, 
                             'subnetPrefixLength').text = str(iface['prefixlen'])
            addrgroups.append(addrgroup)
            interface.append(addrgroups)
            etree.SubElement(interface, 'type').text = iface['type']
            etree.SubElement(interface, 'isConnected').text = 'true' # TODO
            etree.SubElement(interface, 
                             'connectedToId').text = iface['connected_to']
            ifaces.append(interface)
        root.append(ifaces)
        
        return etree.tostring(root)


class Esg(object):
    """docstring for Esg"""
    def __init__(self, nsx, name, datacenter, cluster, datastore, interfaces, 
                 username=None, password=None):
        self.nsx = nsx
        self.name = name
        self.username = username
        self.password = password
        self.datacenter = datacenter
        self.cluster = cluster
        self.datastore = datastore
        self.interfaces = interfaces
        self.cluster_id = nsx.find_cluster_id(datacenter, cluster)
        self.datastore_id = nsx.find_datastore_id(datacenter, datastore)
        self.interfaces_id = interfaces
        for iface in self.interfaces_id:
            if iface['connected_to']['type'] == 'DPG':
                iface['connected_to']['name'] = nsx.find_network_id(datacenter, iface['connected_to']['name'])
            elif iface['connected_to']['type'] == 'Logical Switch':
                iface['connected_to']['name'] = nsx.find_logical_switch_id(iface['connected_to']['name'])
        
    def toxml(self):
        """docstring for toxml"""
        root = etree.Element('edge')
        etree.SubElement(root, 'name').text = self.name
        appliances = etree.Element('appliances')
        appliance = etree.Element('appliance')
        etree.SubElement(appliance, 'resourcePoolId').text = self.cluster_id
        etree.SubElement(appliance, 'datastoreId').text = self.datastore_id
        appliances.append(appliance)
        root.append(appliances)
        if self.username or self.password:
            cli = etree.Element('cliSettings')
            if self.username:
                etree.SubElement(cli, 'userName').text = self.username
            if self.password:
                etree.SubElement(cli, 'password').text = self.password
            root.append(cli)
        etree.SubElement(root, 'type').text = 'gatewayServices'
        
        vnics = etree.Element('vnics')
        index = 1
        for iface in self.interfaces_id:
            vnic = etree.Element('vnic')
            etree.SubElement(vnic, 'name').text = iface['name']
            addrgroups = etree.Element('addressGroups')
            addrgroup = etree.Element('addressGroup')
            etree.SubElement(addrgroup, 
                             'primaryAddress').text = iface['address']
            etree.SubElement(addrgroup, 
                             'subnetPrefixLength').text = str(iface['prefixlen'])
            addrgroups.append(addrgroup)
            vnic.append(addrgroups)
            etree.SubElement(vnic, 'type').text = iface['type']
            etree.SubElement(vnic, 'isConnected').text = 'true' # TODO
            etree.SubElement(vnic, 'index').text = str(index)
            index += 1
            etree.SubElement(vnic, 
                             'portgroupId').text = iface['connected_to']['name']
            vnics.append(vnic)
        root.append(vnics)
        
        return etree.tostring(root)      


# class FirewallSection(object):
#     def __init__(self, name, rules=None):
#         self.name = name
#         self.rules = rules
#
#     def toxml(self):
#         root = etree.Element('section', name=self.name)
#         if self.rules:
#             for r in self.rules:
#                 root.append(etree.fromstring(r.toxml()))
#         return etree.tostring(root)
#
#     def get_id(self, etree):
#         if self.etree:
#             return self.etree.xpath('/section/@id')[0]


class FirewallRule(object):
    def __init__(self, nsx, section, name=None, sources=None, 
                 destinations=None, services=None, action='allow'):
        self.nsx = nsx
        self.section = section
        self.name = name
        self.sources = sources
        self.destinations = destinations
        self.services = services
        self.action = action
        self.sources_id = sources
        self.destinations_id = destinations
        if sources:
             self.sources_id = [nsx._lookup_obj_id(src) for src in sources]
        if destinations:
             self.destinations_id = [nsx._lookup_obj_id(dst) for dst 
                                                           in destinations]

    def toxml(self):
        root = etree.Element('rule')
        if self.name:
            etree.SubElement(root, 'name').text = self.name
            
        etree.SubElement(root, 'action').text = self.action

        if self.sources_id:
            sources = etree.Element('sources', excluded='false')
            for src in self.sources_id:
                source = etree.Element('source')
                etree.SubElement(source, 'value').text = src['name']
                etree.SubElement(source, 'type').text = src['type']
            sources.append(source)
            root.append(sources)
            
        if self.destinations_id:
            destinations = etree.Element('destinations', excluded='false')
            for dst in self.destinations_id:
                destination = etree.Element('destination')
                etree.SubElement(destination, 'value').text = dst['name']
                etree.SubElement(destination, 'type').text = dst['type']
            destinations.append(destination)
            root.append(destinations)
            
        if self.services:
            services = etree.Element('services', excluded='false')
            for svc in self.services:
                service = etree.Element('service')
                etree.SubElement(service, 'value').text = svc['name']
                etree.SubElement(service, 'type').text = svc['type']
            services.append(servie)
            root.append(services)
            
        return etree.tostring(root)


class Nsx:
    def __init__(self, vcenter, username, password, ipaddr, 
                 port=443, verbose=True):
        self.vc = vcenter
        self.auth = (username, password)
        self.url = 'https://%s:%s' % (ipaddr, port)
        self.verbose = verbose
        self.debug = True
        requests.packages.urllib3.disable_warnings()

    # Rest Interfaces (private)
    
    def _api_get(self, path):
        """docstring for api_get"""
        if self.debug:
            print "GET %s" % (self.url + path)
            print "---"
        resp = requests.get(self.url + path, auth=self.auth, 
                            verify=False).content
        if self.debug:
            print resp
            print "---"
        return resp

    def _api_post(self, path, xml, headers={}):
        """docstring for api_post"""
        if self.debug:
            print "POST %s" % (self.url + path)
            print "---"
            print xml
            print "---"
        hdrs = {'Content-Type': 'application/xml'}
        hdrs.update(headers)
        resp = requests.post(self.url + path, auth=self.auth, verify=False,
                             data=xml, headers=hdrs).content
        if self.debug:
            print resp
            print "---"
        return resp

    def _api_put(self, path, xml, headers={}):
        """docstring for api_put"""
        if self.debug:
            print "PUT %s" % (self.url + path)
            print "---"
            print xml
            print "---"
        hdrs = {'Content-Type': 'application/xml'}
        hdrs.update(headers)
        resp = requests.put(self.url + path, auth=self.auth, verify=False,
                            data=xml, headers=hdrs).content
        if self.debug:
            print resp
            print "---"
        return resp

    def _api_delete(self, path):
        """docstring for api_delete"""
        if self.debug:
            print "DELETE %s" % (self.url + path)
            print "---"
        resp = requests.delete(self.url + path, auth=self.auth,
                               verify=False).content
        if self.debug:
            print resp
            print "---"
        return resp
    #   
    # NSX API calls
    #
    
    # Job Instances (private)
    
    def _get_job_status(self, job_id):
        """docstring for get_job_status"""
        if self.verbose:
            print "Getting Job Status for %s ..." % job_id
        resp = self._api_get('/api/2.0/services/taskservice/job/%s' % job_id)
        xml = etree.fromstring(resp)
        return xml.xpath('/jobInstances/jobInstance/status/text()')[0]
        
    def _wait_job(self, job_id, sec=600, interval=10):
        """docstring for _wait_job"""
        if job_id == '':
            return False
        retries = 0
        while retries < (sec/interval):
            if self._get_job_status(job_id) == 'COMPLETED':
                return True
            if self.verbose:
                print "Waiting for %s to get completed ..." % job_id
            time.sleep(interval)
            retries = retries + 1
        if self.verbose:
            print "Job %s abandoned!" % job_id
        return False

    # vCenter

    def register_vcenter(self):
        """docstring for register_vcenter"""
        if self.verbose:
            print "Registering vCenter ..."
        vc_info = VCenterInfo(self.vc)
        return self._api_put('/api/2.0/services/vcconfig', vc_info.toxml())
        
    # vCenter Object Finders

    def find_cluster_id(self, datacenter, cluster):
        """docstring for find_cluster_id"""
        return self.vc.finder('%s/host/%s' % (datacenter, cluster))._GetMoId()

    def find_datastore_id(self, datacenter, datastore):
        """docstring for find_datastore_id"""
        return self.vc.finder('%s/datastore/%s' % (datacenter, datastore))._GetMoId()
                                
    def find_network_id(self, datacenter, network):
        """docstring for find_network_id"""
        return self.vc.finder('%s/network/%s' % (datacenter, network))._GetMoId()
    
    def find_instance_uuid(self, datacenter, vm):
        """docstring for find_vm_uuid"""
        vm = self.vc.finder('%s/vm/Discovered virtual machine/%s' % (datacenter, vm))
        return vm.config.instanceUuid

    # NSX Manager Object Finders
                            
    def find_ip_pool_id(self, name):
        """docstring for find_ip_pool"""
        resp = self._api_get('/api/2.0/services/ipam/pools/scope/globalroot-0')
        pools = etree.fromstring(resp)
        pattern = "/ipamAddressPools/ipamAddressPool[name='%s']/objectId/text()" % name
        return pools.xpath(pattern)[0]
    
    def find_transport_zone_id(self, name):
        """docstring for find_transport_zone_id"""
        resp = self._api_get('/api/2.0/vdn/scopes')
        scopes = etree.fromstring(resp)
        pattern = "/vdnScopes/vdnScope[name='%s']/id/text()" % name
        return scopes.xpath(pattern)[0]
    
    def find_logical_switch_id(self, name):
        """docstring for find_logical_switch_id"""
        resp = self._api_get('/api/2.0/vdn/virtualwires')
        virtualwires = etree.fromstring(resp)
        pattern = "/virtualWires/dataPage/virtualWire[name='%s']/objectId/text()" % name
        return virtualwires.xpath(pattern)[0]
        
    def find_firewall_l3_section_id(self, name):
        """docstring for find_firewall_l3_section_id"""
        resp = self._api_get('/api/4.0/firewall/globalroot-0/config/layer3sections?name=%s' % urllib.quote(name))
        section = etree.fromstring(resp)
        return section.xpath('/section/@id')[0]

    def find_firewall_l3_generation_no(self, name):
        """docstring for find_firewall_l3_generation_no"""
        resp = self._api_get('/api/4.0/firewall/globalroot-0/config/layer3sections?name=%s' % urllib.quote(name))
        section = etree.fromstring(resp)
        return section.xpath('/section/@generationNumber')[0]
        
    # utilities (TODO)
        
    def _lookup_obj_id(self, obj):
        """docstring for _lookup_obj_id"""
        obj_type = obj['type']
        obj_name = obj['name']
        if obj_type == 'Cluster':
            return {'type': 'Cluster', 'name': 'TBD'} # TODO
        elif obj_type == 'Logical Switch':
            obj_id = self.find_logical_switch_id(obj_name)
            return {'type': 'VirtualWire', 'name': obj_id}
        else:
            return None
        
    # IP Pools

    def create_ip_pool(self, ip_pool):
        """docstring for create_ip_pool"""
        if self.verbose:
            print "Creating IP Pool %s ..." % ip_pool.name
        return self._api_post('/api/2.0/services/ipam/pools/scope'
                              '/globalroot-0', ip_pool.toxml())

    # Controllers
    
    def create_controller(self, controller):
        """docstring for create_controller"""
        if self.verbose:
            print "Adding Controller ..."
        job_id = self._api_post('/api/2.0/vdn/controller', controller.toxml())
        self._wait_job(job_id)
        
    def create_controllers(self, controller):
        """docstring for create_controllers"""
        if self.verbose:
            print "Adding 3 Controllers ..."
        for i in range(0, 3):
            self.create_controller(controller)
                                
    def host_prep(self, host_prep):
        """docstring for host_prep"""
        if self.verbose:
            print "Preparing Host for Cluster %s ..." % host_prep.cluster
        job_id = self._api_post('/api/2.0/nwfabric/configure', 
                                host_prep.toxml())
        self._wait_job(job_id)
        
    def vxlan_prep(self, vxlan_prep):
        """docstring for vxlan_prep"""
        if self.verbose:
            print "Configuring VXLAN for Cluster %s ..." % vxlan_prep.cluster
        job_id = self._api_post('/api/2.0/nwfabric/configure', 
                                vxlan_prep.toxml())
        self._wait_job(job_id)
        
    def create_segment_id(self, segment):
        """docstring for create_segment_id"""
        return self._api_post('/api/2.0/vdn/config/segments', segment.toxml())
    
    def create_transport_zone(self, transport_zone):
        """docstring for create_transport_zone"""
        return self._api_post('/api/2.0/vdn/scopes', transport_zone.toxml())
        
    def create_logical_switch(self, logical_switch):
        """docstring for create_logical_switch"""
        transport_zone_id = self.find_transport_zone_id(logical_switch.transport_zone)
        path = '/api/2.0/vdn/scopes/%s/virtualwires' % transport_zone_id
        return self._api_post(path, logical_switch.toxml())
        
    def add_vm_to_switch(self, vnic):
        """docstring for add_vm_to_switch"""
        resp = self._api_post('/api/2.0/vdn/virtualwires/vm/vnic',
                              vnic.toxml())
        task = etree.fromstring(resp)
        job_id = task.xpath('//jobId/text()')[0]
        self._wait_job(job_id)
        
    def create_dlr(self, dlr):
        """docstring for create_dlr"""
        return self._api_post('/api/4.0/edges/', dlr.toxml())

    def create_esg(self, esg):
        """docstring for create_esg"""
        return self._api_post('/api/4.0/edges/', esg.toxml())
        
    def add_firewall_l3_rule(self, rule):
        """docstring for add_firewall_l3_rule"""
        section_id = self.find_firewall_l3_section_id(rule.section)
        gen_no = self.find_firewall_l3_generation_no(rule.section)
        return self._api_post('/api/4.0/firewall/globalroot-0/config/'
                              'layer3sections/%s/rules' % section_id,
                              rule.toxml(), 
                              {'If-Match': gen_no})

    # Security Groups
    
    def get_security_groups(self):
        """docstring for get_security_groups"""
        root = etree.fromstring(self._api_get('/api/2.0/services/securitygroup/scope/globalroot-0'))
        return [SecurityGroup.fromxml(etree.tostring(sg)) for sg in root.iterfind("securitygroup")]
    
    def create_security_gruop(self, sg):
        """docstring for create_security_group"""
        return self._api_post('/api/2.0/services/securitygroup/bulk/globalroot-0', sg.toxml())
    
    # Firewall Section
    
    def get_all_firewall_layer3_sections(self):
        """docstring for get_firewall_layer3_sections"""
        return self._api_get('/api/4.0/firewall/globalroot-0/config')
    
    def create_firewall_layer3_section(self, section, autosave=True):
        """docstring for create_firewall_ayer3_section"""
        if autosave:
            path = '/api/4.0/firewall/globalroot-0/config/layer3sections'
        else:
            path = '/api/4.0/firewall/globalroot-0/config/layer3sections?autoSaveDraft=false'
        return self._api_post(path, section.toxml())
    
    def delete_firewall_layer3_section(self, id, autosave=True):
        """docstring for delete_firewall_layer3_section"""
        if autosave:
            path = '/api/4.0/firewall/globalroot-0/config/layer3sections/%s'
        else:
            path = '/api/4.0/firewall/globalroot-0/config/layer3sections/%s?autoSaveDraft=false'
        return self._api_delete(path % id)
    
    # Utilities
    
    def delete_all_firewall_layer3_sections(self, autosave=True):
        """docstring for delete_all_firewall_layer3_sections"""
        pattern = 'layer3Sections/section'
        for section in etree.fromstring(self.getAllFirewallLayer3Sections()).iterfind(pattern):
            print "section %s deleted" % section.attrib['id']
            self.deleteFirewallLayer3Section(section.attrib['id'], autosave)
