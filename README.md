Python binding for NSX-v API
============================

by Motonori Shindo <motonori@shin.do> (2012 - 2018)

Introduction
------------

This is an NSX-v API library so that people can consume NSX-v API using Python
easily. This library alleviates the pain of manipulating XML parameters
directly.

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

Please see lab-basic.py as an example that uses this binding. This example
basically aligns with the NSX Hands On Lab available from VMware.

License
-------

Apache License, version 2.0
