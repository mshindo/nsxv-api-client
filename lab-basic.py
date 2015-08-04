import nsxv

vc = nsxv.VCenter(username='root',
                  password='VMware1!',
#                  hostname='vc-l-01a.corp.local',
                  hostname='192.168.110.22',
                  proxy_ipaddr='10.152.64.61',
                  proxy_port=5443)

nsx = nsxv.Nsx(vcenter=vc,
               username='admin',
               password='VMware1!',
               ipaddr='10.152.64.61',
               port=4443)

# For some reason, register_vcenter() doesn't work. NSX plugin
# is installed in vCenter Client, but not assicated with NSX Manager.
# Needs more investigation.
# nsx.register_vcenter()

nsx.add_ip_pool(name='Controller-Pool',
                gateway='192.168.110.2',
                prefix_len=24,
                primary_dns = '192.168.110.10',
                start='192.168.110.201',
                end='192.168.110.210')

nsx.add_ip_pool(name='VTEP1-Pool',
                gateway='192.168.150.2',
                prefix_len=24,
                start='192.168.150.51',
                end='192.168.150.60')

nsx.add_ip_pool(name='VTEP2-Pool',
                gateway='192.168.250.2',
                prefix_len=24,
                start='192.168.250.51',
                end='192.168.250.60')

nsx.add_controllers(datacenter='ABC Medical',
                    cluster='Management and Edge Cluster',
                    datastore='ds-site-a-nfs01',
                    connected_to='Mgmt_Edge_VDS - Mgmt',
                    ip_pool='Controller-Pool',
                    password='VMware1!VMware1!')

for cluster in ['Management and Edge Cluster',
                'Compute Cluster A',
                'Compute Cluster B']:
    nsx.host_prep(datacenter='ABC Medical', cluster=cluster)


nsx.vxlan_prep(datacenter='ABC Medical',
               cluster='Management and Edge Cluster',
               switch='Mgmt_Edge_VDS',
               vlan=0,
               mtu=1600,
               ip_pool='VTEP1-Pool',
               teaming='FAILOVER_ORDER',
               n_vteps=1)

for cluster in ['Compute Cluster A',
                'Compute Cluster B']:
    nsx.vxlan_prep(datacenter='ABC Medical',
               cluster=cluster,
               switch='Compute_VDS',
               vlan=0,
               mtu=1600,
               ip_pool='VTEP2-Pool',
               teaming='FAILOVER_ORDER',
               n_vteps=1)

nsx.create_segment_id(5000, 5999)

nsx.create_transport_zone(name='Global-Transport-Zone',
                          datacenter='ABC Medical',
                          clusters=['Management and Edge Cluster',
                                    'Compute Cluster A',
                                    'Compute Cluster B'])

for name in ['Transit-Network-01', 
             'Web-Tier-01',
             'App-Tier-01',
             'DB-Tier-01']:
    nsx.create_logical_switch(name=name,
                              transport_zone='Global-Transport-Zone')

for vm in ['web-sv-01a', 'web-sv-02a']:
    nsx.add_vm_to_switch(logical_switch='Web-Tier-01', 
                         datacenter='ABC Medical',
                         vm=vm)                              