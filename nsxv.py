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
                 primary_dns, secondary_dns, suffix):
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
    def __init__(self, cluster_id, datastore_id, connected_to_id, 
                 ip_pool_id, password):
        self.cluster_id = cluster_id
        self.datastore_id = datastore_id
        self.connected_to_id = connected_to_id
        self.ip_pool_id = ip_pool_id
        self.password = password

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
    def __init__(self, cluster_id):
        self.cluster_id = cluster_id

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
    def __init__(self, cluster_id, switch_id, vlan, mtu, ip_pool_id,
                 teaming, n_vteps):
        self.cluster_id = cluster_id
        self.switch_id = switch_id
        self.vlan = vlan
        self.mtu = mtu
        self.ip_pool_id = ip_pool_id
        self.teaming = teaming
        self.n_vteps = n_vteps

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
    def __init__(self, name, clusters_id, mode='UNICAST_MODE'):
        self.name = name
        self.clusters_id = clusters_id
        self.mode = mode
    
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
    def __init__(self, name, mode):
        super(LogicalSwitch, self).__init__()
        self.name = name
        self.mode = mode
        
    def toxml(self):
        """docstring for toxml"""
        root = etree.Element('virtualWireCreateSpec')
        etree.SubElement(root, 'name').text = self.name
        # looks like tenantId can be anything
        etree.SubElement(root, 'tenantId').text = 'virtual wire tenant'
        etree.SubElement(root, 'controlPlaneMode').text = self.mode
        return etree.tostring(root)
        
        
class VnicDto(object):
    """docstring for VnicDto"""
    def __init__(self, vnic_uuid, logical_switch):
        self.vnic_uuid = vnic_uuid
        self.logical_switch = logical_switch
    
    def toxml(self):
        """docstring for fname"""
        root = etree.Element('com.vmware.vshield.vsm.inventory.dto.VnicDto')
        etree.SubElement(root, 'vnicUuid').text = self.vnic_uuid
        etree.SubElement(root, 'portgroupId').text = self.logical_switch
        return etree.tostring(root)


class Dlr(object):
    """docstring for Dlr"""
    def __init__(self, name, cluster_id, datastore_id, username, password, 
                 mgmt_iface, interfaces):
        self.name = name
        self.cluster_id = cluster_id
        self.datastore_id = datastore_id
        self.username = username
        self.password = password
        self.mgmt_iface = mgmt_iface
        self.interfaces = interfaces
        
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
        etree.SubElement(mgmt_iface, 'connectedToId').text = self.mgmt_iface
        root.append(mgmt_iface)
        
        ifaces = etree.Element('interfaces')
        for iface in self.interfaces:
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

                
class FirewallSection(object):
    def __init__(self, name, rules=None):
        self.name = name
        self.rules = rules

    def toxml(self):
        root = etree.Element('section', name=self.name)
        if self.rules:
            for r in self.rules:
                root.append(etree.fromstring(r.toxml()))
        return etree.tostring(root)

    def get_id(self, etree):
        if self.etree:
            return self.etree.xpath('/section/@id')[0]


class FirewallRule(object):
    def __init__(self, name=None, sources=None, destinations=None, 
                 services=None, action='allow'):
        self.name = name
        self.sources = sources
        self.destinations = destinations
        self.services = services
        self.action = action

    def toxml(self):
        root = etree.Element('rule')
        if self.name:
            etree.SubElement(root, 'name').text = self.name
            
        etree.SubElement(root, 'action').text = self.action

        if self.sources:
            sources = etree.Element('sources', excluded='false')
            for src in self.sources:
                source = etree.Element('source')
                etree.SubElement(source, 'value').text = src['name']
                etree.SubElement(source, 'type').text = src['type']
            sources.append(source)
            root.append(sources)
            
        if self.destinations:
            destinations = etree.Element('destinations', excluded='false')
            for dst in self.destinations:
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
        
    # vCenter Object Finders (private)

    def _find_cluster_id(self, datacenter, cluster):
        """docstring for _find_cluster_id"""
        return self.vc.finder('%s/host/%s' % (datacenter, cluster))._GetMoId()

    def _find_datastore_id(self, datacenter, datastore):
        """docstring for _find_datastore_id"""
        return self.vc.finder('%s/datastore/%s' % (datacenter, datastore))._GetMoId()
                                
    def _find_network_id(self, datacenter, network):
        """docstring for _find_network_id"""
        return self.vc.finder('%s/network/%s' % (datacenter, network))._GetMoId()
    
    def _find_instance_uuid(self, datacenter, vm):
        """docstring for _find_vm_uuid"""
        vm = self.vc.finder('%s/vm/Discovered virtual machine/%s' % (datacenter, vm))
        return vm.config.instanceUuid

    # NSX Manager Object Finders (private)
                            
    def _find_ip_pool_id(self, name):
         """docstring for find_ip_pool"""
         resp = self._api_get('/api/2.0/services/ipam/pools/scope/globalroot-0')
         pools = etree.fromstring(resp)
         pattern = "/ipamAddressPools/ipamAddressPool[name='%s']/objectId/text()" % name
         return pools.xpath(pattern)[0]
    
    def _find_transport_zone_id(self, name):
        """docstring for _find_transport_zone_id"""
        resp = self._api_get('/api/2.0/vdn/scopes')
        scopes = etree.fromstring(resp)
        pattern = "/vdnScopes/vdnScope[name='%s']/id/text()" % name
        return scopes.xpath(pattern)[0]
    
    def _find_logical_switch_id(self, name):
        """docstring for _find_logical_switch_id"""
        resp = self._api_get('/api/2.0/vdn/virtualwires')
        virtualwires = etree.fromstring(resp)
        pattern = "/virtualWires/dataPage/virtualWire[name='%s']/objectId/text()" % name
        return virtualwires.xpath(pattern)[0]
        
    def _find_firewall_l3_section_id(self, name):
        """docstring for find_firewall_l3_section_id"""
        resp = self._api_get('/api/4.0/firewall/globalroot-0/config/layer3sections?name=%s' % urllib.quote(name))
        section = etree.fromstring(resp)
        return section.xpath('/section/@id')[0]

    def _find_firewall_l3_generation_no(self, name):
        """docstring for _find_firewall_l3_generation_no"""
        resp = self._api_get('/api/4.0/firewall/globalroot-0/config/layer3sections?name=%s' % urllib.quote(name))
        section = etree.fromstring(resp)
        return section.xpath('/section/@generationNumber')[0]
        
    # utilities
        
    def _lookup_obj_id(self, obj):
        """docstring for _lookup_obj_id"""
        obj_type = obj['type']
        obj_name = obj['name']
        if obj_type == 'Cluster':
            return {'type': 'Cluster', 'name': 'TBD'}
        elif obj_type == 'Logical Switch':
            obj_id = self._find_logical_switch_id(obj_name)
            return {'type': 'VirtualWire', 'name': obj_id}
        else:
            return None
        
    # IP Pools

    def add_ip_pool(self, name, gateway, prefix_len, start, end, 
                    primary_dns=None, secondary_dns=None, suffix=None):
        """docstring for add_ip_pool"""
        if self.verbose:
            print "Creating IP Pool %s ..." % name
        pool = IpPool(name, gateway, prefix_len, start, end, 
                      primary_dns, secondary_dns, suffix)
        return self._api_post('/api/2.0/services/ipam/pools/scope/globalroot-0', 
                               pool.toxml())
        
    # Controllers
    
    def add_controller(self, datacenter, cluster, datastore, connected_to,
                       ip_pool, password):
        """docstring for add_controller"""
        if self.verbose:
            print "Adding Controller ..."
        cluster_id = self._find_cluster_id(datacenter, cluster)
        datastore_id = self._find_datastore_id(datacenter, datastore)
        network_id = self._find_network_id(datacenter, connected_to)
        ip_pool_id = self._find_ip_pool_id(ip_pool)
        
        controller = Controller(cluster_id, datastore_id, network_id,
                                ip_pool_id, password)
        job_id = self._api_post('/api/2.0/vdn/controller', controller.toxml())
        self._wait_job(job_id)
        
    def add_controllers(self, datacenter, cluster, datastore, connected_to,
                       ip_pool, password):
        """docstring for add_controllers"""
        if self.verbose:
            print "Adding 3 Controllers ..."
        for i in range(0, 3):
            self.add_controller(datacenter, cluster, datastore, connected_to,
                                ip_pool, password)
                                
    def host_prep(self, datacenter, cluster):
        """docstring for host_prep"""
        if self.verbose:
            print "Preparing Host for Cluster %s ..." % cluster
        cluster_id = self._find_cluster_id(datacenter, cluster)
        host_prep = HostPrep(cluster_id)
        job_id = self._api_post('/api/2.0/nwfabric/configure', 
                                host_prep.toxml())
        self._wait_job(job_id)
        
    def vxlan_prep(self, datacenter, cluster, switch, vlan, mtu, ip_pool,
                      teaming, n_vteps):
        """docstring for vxlan_prep"""
        if self.verbose:
            print "Configuring VXLAN for Cluster %s ..." % cluster
        cluster_id = self._find_cluster_id(datacenter, cluster)
        switch_id = self._find_network_id(datacenter, switch)
        ip_pool_id = self._find_ip_pool_id(ip_pool)
        vxlan_prep = VxlanPrep(cluster_id, switch_id, vlan, mtu, ip_pool_id,
                               teaming, n_vteps)
        job_id = self._api_post('/api/2.0/nwfabric/configure', 
                                vxlan_prep.toxml())
        self._wait_job(job_id)
        
    def create_segment_id(self, begin, end):
        """docstring for create_segment_id"""
        segment = Segment(begin, end)
        return self._api_post('/api/2.0/vdn/config/segments', segment.toxml())
    
    def create_transport_zone(self, name, datacenter, clusters):
        """docstring for create_transport_zone"""
        clusters_id = [self._find_cluster_id(datacenter, 
                                             cluster) for cluster in clusters]
        transport_zone = TransportZone(name, clusters_id)
        return self._api_post('/api/2.0/vdn/scopes', transport_zone.toxml())
        
    def create_logical_switch(self, name, transport_zone, mode='UNICAST_MODE'):
        """docstring for create_logical_switch"""
        transport_zone_id = self._find_transport_zone_id(transport_zone)
        logical_switch = LogicalSwitch(name, mode)
        path = '/api/2.0/vdn/scopes/%s/virtualwires' % transport_zone_id
        return self._api_post(path, logical_switch.toxml())
        
    def add_vm_to_switch(self, logical_switch, datacenter, vm):
        """docstring for add_vm_to_switch"""
        logical_switch_id = self._find_logical_switch_id(logical_switch)
        instance_uuid = self._find_instance_uuid(datacenter, vm)
        # TODO
        # can't find a way to get the 'virtualdevice id'. It doesn't
        # work as documented. So, simply assumes it's '.000' for now.
        vnic_dto = VnicDto(instance_uuid + '.000', logical_switch_id)
        resp = self._api_post('/api/2.0/vdn/virtualwires/vm/vnic',
                              vnic_dto.toxml())
        task = etree.fromstring(resp)
        job_id = task.xpath('//jobId/text()')[0]
        self._wait_job(job_id)
        
    def create_dlr(self, name, username, password, datacenter, cluster,
                   datastore, mgmt_iface, interfaces):
        """docstring for create_dlr"""
        cluster_id = self._find_cluster_id(datacenter, cluster)
        datastore_id = self._find_datastore_id(datacenter, datastore)
        mgmt_iface_id = self._find_network_id(datacenter, mgmt_iface)
        for iface in interfaces:
            # TODO: need to support VDS
            iface['connected_to'] = self._find_logical_switch_id(iface['connected_to'])
        dlr = Dlr(name, cluster_id, datastore_id, username, password,
                  mgmt_iface_id, interfaces)
        return self._api_post('/api/4.0/edges/', dlr.toxml())
        
    def add_firewall_l3_rule(self, section, name=None, sources=None, 
                             destinations=None, services=None, 
                             action='allow'):
        """docstring for add_firewall_l3_rule"""
        if sources:
            sources = [self._lookup_obj_id(src) for src in sources]
        if destinations:
            destinations = [self._lookup_obj_id(dst) for dst in destinations]
        
        section_id = self._find_firewall_l3_section_id(section)

        rule = FirewallRule(name, sources, destinations, services, action)
        gen_no = self._find_firewall_l3_generation_no(section)
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