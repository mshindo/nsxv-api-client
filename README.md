This is an NSX-v API library so that people can consume NSX-v API using Python 
easily. The intention is to free someone who writes a API script from directly 
manipulating the XML.

Currently the following operations are supported:

 * creating IP Pool
 * creating Controllers
 * Host Preparation
 * VXLAN Preparation
 * creating Segment ID
 * creating Transport Zone
 * creating Logical Switch
 * attaching VMs to Logical Switch
 * creating Distributed Logical Router
 * creating Firewall Rule
 * creating Edge Service Gateway
 * OSPF routing configuration
 * BGP routing configuration
 
Also, lab-basic.py aligns with "NSX-vSphere-61-BASIC-V1.1" lab available on 
OneCloud. The short term goal is to fully automate the procedure described
in this lab but it is just half way through. 

It is easy and straingtforward to add API calls, your contrbibution is very 
much welcome.

Motonori Shindo
mshindo@vmware.com 
@motonori_shindo