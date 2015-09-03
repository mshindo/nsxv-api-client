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

controller_pool = nsxv.IpPool(name='Controller-Pool',
                              gateway='192.168.110.2',
                              prefix_len=24,
                              start='192.168.110.201',
                              end='192.168.110.210',
                              primary_dns='192.168.110.10')

vtep1_pool = nsxv.IpPool(name='VTEP1-Pool',
                         gateway='192.168.150.2',
                         prefix_len=24,
                         start='192.168.150.51',
                         end='192.168.150.60')

vtep2_pool = nsxv.IpPool(name='VTEP2-Pool',
                         gateway='192.168.250.2',
                         prefix_len=24,
                         start='192.168.250.51',
                         end='192.168.250.60')

for pool in [controller_pool, vtep1_pool, vtep2_pool]:
    nsx.create_ip_pool(pool)

controller = nsxv.Controller(nsx=nsx,
                             datacenter='ABC Medical',
                             cluster='Management and Edge Cluster',
                             datastore='ds-site-a-nfs01',
                             connected_to='Mgmt_Edge_VDS - Mgmt',
                             ip_pool='Controller-Pool',
                             password='VMware1!VMware1!')

nsx.create_controllers(controller)

for cluster in ['Management and Edge Cluster',
                'Compute Cluster A',
                'Compute Cluster B']:
    nsx.host_prep(nsxv.HostPrep(nsx=nsx,
                                datacenter='ABC Medical',
                                cluster=cluster))

vxlan_preps = [nsxv.VxlanPrep(nsx=nsx,
                             datacenter='ABC Medical',
                             cluster=cluster,
                             switch=switch,
                             vlan=0,
                             mtu=1600,
                             ip_pool=ip_pool,
                             teaming='FAILOVER_ORDER',
                             n_vteps=1) for (cluster, switch, ip_pool) in
                                 [('Management and Edge Cluster',
                                   'Mgmt_Edge_VDS',
                                   'VTEP1-Pool'),
                                  ('Compute Cluster A',
                                   'Compute_VDS',
                                   'VTEP2-Pool'),
                                  ('Compute Cluster B',
                                   'Compute_VDS',
                                   'VTEP2-Pool')]]

for vxlan_prep in vxlan_preps:
    nsx.vxlan_prep(vxlan_prep)

nsx.create_segment_id(nsxv.Segment(begin=5000, end=5999))

transport_zone = nsxv.TransportZone(nsx=nsx,
                                    name='Global-Transport-Zone',
                                    datacenter='ABC Medical',
                                    clusters=['Management and Edge Cluster',
                                              'Compute Cluster A',
                                              'Compute Cluster B'])

nsx.create_transport_zone(transport_zone)

for name in ['Transit-Network-01',
             'Web-Tier-01',
             'App-Tier-01',
             'DB-Tier-01']:
    logical_switch = nsxv.LogicalSwitch(name=name,
                                        transport_zone='Global-Transport-Zone')
    nsx.create_logical_switch(logical_switch)

for vm in ['web-sv-01a', 'web-sv-02a']:
    vnic = nsxv.Vnic(nsx=nsx,
                     logical_switch='Web-Tier-01',
                     datacenter='ABC Medical',
                     vm=vm)
    nsx.add_vm_to_switch(vnic)

nsx.add_vm_to_switch(nsxv.Vnic(nsx=nsx,
                               logical_switch='App-Tier-01',
                               datacenter='ABC Medical',
                               vm='app-sv-01a'))

nsx.add_vm_to_switch(nsxv.Vnic(nsx=nsx,
                               logical_switch='DB-Tier-01',
                               datacenter='ABC Medical',
                               vm='db-sv-01a'))

dlr = nsxv.Dlr(nsx=nsx,
               name='Distributed-Router-01',
               username='admin',
               password='VMware1!VMware1!',
               datacenter='ABC Medical',
               cluster='Management and Edge Cluster',
               datastore='ds-site-a-nfs01',
               mgmt_iface='Mgmt_Edge_VDS - VM Mgmt',
               interfaces=[{'name': 'Transit-Network-01',
                            'type': 'uplink',
                            'connected_to': 'Transit-Network-01',
                            'address': '192.168.10.5',
                            'prefixlen': 29},
                           {'name': 'Web-Tier-01',
                            'type': 'internal',
                            'connected_to': 'Web-Tier-01',
                            'address': '172.16.10.1',
                            'prefixlen': 24},
                           {'name': 'App-Tier-01',
                            'type': 'internal',
                            'connected_to': 'App-Tier-01',
                            'address': '172.16.20.1',
                            'prefixlen': 24},
                           {'name': 'DB-Tier-01',
                            'type': 'internal',
                            'connected_to': 'DB-Tier-01',
                            'address': '172.16.30.1',
                            'prefixlen': 24}])
nsx.create_dlr(dlr)

rule = nsxv.FirewallRule(nsx=nsx,
                         section='Default Section Layer3',
                         name='Web Segmentation',
                         sources=[{'type': 'Logical Switch',
                                   'name': 'Web-Tier-01'}],
                         destinations=[{'type': 'Logical Switch',
                                        'name': 'Web-Tier-01'}],
                         action='deny')

nsx.add_firewall_l3_rule(rule)

esg = nsxv.Esg(nsx=nsx,
               name='Edge-Gateway-01',
               datacenter='ABC Medical',
               cluster='Management and Edge Cluster',
               datastore='ds-site-a-nfs01',
               interfaces=[{'name': 'HQ Uplink',
                            'type': 'uplink',
                            'connected_to': {'type': 'DPG',
                                             'name': 'Mgmt_Edge_VDS - HQ Uplink'},
                            'address': '192.168.100.3',
                            'prefixlen': 24},
                           {'name': 'Transit Internal',
                            'type': 'internal',
                            'connected_to': {'type': 'Logical Switch',
                                             'name': 'Transit-Network-01'},
                            'address': '192.168.10.1',
                            'prefixlen': 29},
                           {'name': 'VLAN100 Internal',
                            'type': 'internal',
                            'connected_to': {'type': 'DPG',
                                             'name': 'Mgmt_Edge_VDS - Bridge_VLAN'},
                            'address': '172.16.100.1',
                            'prefixlen': 24}],
                username='admin',
                password='VMware1!VMware1!')

nsx.create_esg(esg)
