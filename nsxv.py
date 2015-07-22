import requests 
from lxml import etree

#class SecurityGroup:
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
    def __init__(self, host, username, password):
        self.host = host            # it can be either an IP address or FQDN
        self.username = username
        self.password = password
    
    def toxml(self):
        root = etree.Element("vcInfo")
        etree.SubElement(root, "ipAddress").text = self.host
        etree.SubElement(root, "userName").text = self.username
        etree.SubElement(root, "password").text = self.password
        return etree.tostring(root)
        
        
class FirewallSection(object):
    def __init__(self, name, rules=None):
        self.name = name
        self.rules = rules
        
    def toxml(self):
        root = etree.Element("section", name=self.name)
        if self.rules:
            for r in self.rules:
                root.append(etree.fromstring(r.toxml()))
        return etree.tostring(root)
        
    def get_id(self, etree):
        if self.etree:
            return self.etree.xpath("/section/@id")[0]

        
class FirewallRule(object):
    def __init__(self, action, name=None):
        self.action = action
        self.name = name
        
    def toxml(self):
        root = etree.Element("rule")
        if self.name:
            etree.SubElement(root, "name").text = self.name
        etree.SubElement(root, "action").text = self.action
        return etree.tostring(root)


class Nsx:
    def __init__(self, url, username, password):
        self.url = url
        self.auth = (username, password)
        requests.packages.urllib3.disable_warnings()
        
    # Rest Interfaces
        
    def __api_get(self, path):
        """docstring for api_get"""
        return requests.get(self.url + path, auth=self.auth, verify=False).content
        
    def __api_post(self, path, xml):
        """docstring for api_post"""
        headers = {'Content-Type': 'application/xml'}
        return requests.post(self.url + path, auth=self.auth, verify=False, data=xml, headers=headers).content
        
    def __api_put(self, path, xml):
        """docstring for api_put"""
        headers = {'Content-Type': 'application/xml'}
        return requests.put(self.url + path, auth=self.auth, verify=False, data=xml, headers=headers).content        
        
    def __api_delete(self, path):
        """docstring for api_delete"""
        return requests.delete(self.url + path, auth=self.auth, verify=False).content
        
    # NSX API calls
    
    # Configure vCenter Server with NSX Manager
    
    def configurevCenter(self, vc):
        """docstring for configurevCenter"""
        return self.__api_put('/api/2.0/services/vcconfig', vc.toxml())

    # Security Groups
    
    def getSecurityGroups(self):
        """docstring for getSecurityGroups"""
        root = etree.fromstring(self.__api_get('/api/2.0/services/securitygroup/scope/globalroot-0'))
        
        return [SecurityGroup.fromxml(etree.tostring(sg)) for sg in root.iterfind("securitygroup")]
    
    def createSecurityGruop(self, sg):
        """docstring for createSecurityGroup"""
        return self.__api_post('/api/2.0/services/securitygroup/bulk/globalroot-0', sg.toxml())
        
    # Firewall Section
    
    def getAllFirewallLayer3Sections(self):
        """docstring for getFirewallSections"""
        return self.__api_get('/api/4.0/firewall/globalroot-0/config')
    
    def createFirewallLayer3Section(self, section, autosave=True):
        """docstring for createFirewallSectionLayer3"""
        if autosave:
            path = '/api/4.0/firewall/globalroot-0/config/layer3sections'
        else:
            path = '/api/4.0/firewall/globalroot-0/config/layer3sections?autoSaveDraft=false'
        return self.__api_post(path, section.toxml())
        
    def deleteFirewallLayer3Section(self, id, autosave=True):
        """docstring for deleteFirewallLayer3Section"""
        if autosave:
            path = '/api/4.0/firewall/globalroot-0/config/layer3sections/%s'
        else:
            path = '/api/4.0/firewall/globalroot-0/config/layer3sections/%s?autoSaveDraft=false'
        return self.__api_delete(path % id)

    # Utilities
    
    def deleteAllFirewallLayer3Sections(self, autosave=True):
        """docstring for deleteAllFirewallLayer3Sections"""
        pattern = 'layer3Sections/section'
        for section in etree.fromstring(self.getAllFirewallLayer3Sections()).iterfind(pattern):
            print "section %s deleted" % section.attrib['id']
            self.deleteFirewallLayer3Section(section.attrib['id'], autosave)

        
        #print "Deleting Firewall Layer 3 sections %s ..." % sec.name
        #print nsx.deleteFirewallLayer3Section(sec)
        #print '---'

