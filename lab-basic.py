# Copyright 2023 Motonori Shindo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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

nsx.add_vm_to_switch(logical_switch='App-Tier-01',
                         datacenter='ABC Medical',
                         vm='app-sv-01a')

nsx.add_vm_to_switch(logical_switch='DB-Tier-01',
                         datacenter='ABC Medical',
                         vm='db-sv-01a')

nsx.create_dlr(name='Distributed-Router-01',
               username='admin',
               password='VMware1!VMware1!',
               datacenter='ABC Medical',
               cluster='Management and Edge Cluster',
               datastore='ds-site-a-nfs01',
               mgmt_iface='Mgmt_Edge_VDS - VM Mgmt',
               interfaces=[{'name': 'Transit-Uplink',
                            'type': 'uplink',
                            'connected_to': 'Transit-Network-01',
                            'address': '192.168.10.5',
                            'prefixlen': 29},
                           {'name': 'Web-Tier',
                            'type': 'internal',
                            'connected_to': 'Web-Tier-01',
                            'address': '172.16.10.1',
                            'prefixlen': 24},
                           {'name': 'App-Tier',
                            'type': 'internal',
                            'connected_to': 'App-Tier-01',
                            'address': '172.16.20.1',
                            'prefixlen': 24},
                           {'name': 'DB-Tier',
                            'type': 'internal',
                            'connected_to': 'DB-Tier-01',
                            'address': '172.16.30.1',
                            'prefixlen': 24}])

nsx.add_firewall_l3_rule(section='Default Section Layer3',
                         name='Web Segmentation',
                         sources=[{'type': 'Logical Switch',
                                   'name': 'Web-Tier-01'}],
                         destinations=[{'type': 'Logical Switch',
                                        'name': 'Web-Tier-01'}],
                         action='deny')

nsx.create_esg(name='Edge-Gateway-01',
               username='admin',
               password='VMware1!VMware1!',
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
                            'prefixlen': 24}]
               )

nsx.routing_global(name='Distributed-Router-01',
                   router_id='192.168.10.5',
                   log='true')

nsx.routing_ospf(name='Distributed-Router-01',
                 enabled='true',
                 protocol_address='192.168.10.6',
                 forwarding_address='192.168.10.5',
                 areas=[{'area': 10}],
                 interfaces=[{'name': 'Transit-Uplink',
                              'area': 10,
                              'hello_interval': 1,
                              'dead_interval': 4}])

nsx.routing_global(name='Edge-Gateway-01',
                   router_id='192.168.100.3',
                   log={'enable': 'true',
                        'level': 'info'})

nsx.routing_ospf(name='Edge-Gateway-01',
                 enabled='true',
                 default_originate='true',
                 areas=[{'area': 10}],
                 vnics=[{'name': 'Transit Internal',
                         'area': 10,
                         'hello_interval': 1,
                         'dead_interval': 4}])

nsx.routing_bgp(name='Edge-Gateway-01',
                enabled='true',
                default_originate='true',
                local_as=65001,
                neighbours=[{'address': '192.168.100.2',
                             'remote_as': 65002,
                             'holddown_timer': 3,
                             'keepalive_timer': 1}],
                redistribution={'enabled': 'true',
                                'rules': [{'from': ['connected','ospf'],
                                           'action': 'permit'}]})
