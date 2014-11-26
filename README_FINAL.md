Virtual Software Router
=======================

Implemented a fully functional Internet router that routes real network traffic. Implemented ARP, ICMP, and basic IP forwarding as part of the project. The router runs on top of the Virtual Network System built at Stanford that allows building virtual network topologies consisting of nodes that operate on actual Ethernet frames. Router functionality is to handle ARP requests and replies, ICMP echo requests, ICMP messages, traceroutes through it (where it is not the end host) and to it (where it is the end host), route packets between the gateway and the application servers, ARP cache whose entries were invalidated after a timeout period (timeouts should be on the order of 15 seconds), tcp/udp packets sent to one of its interface

#Building your own Internet Router

##Introduction (Course Project CSC525 Principles of Computer Networks)

In this assignment we implemented a fully functional Internet router that routes real network traffic. The goal is to give you hands-on experience as to how a router really works. Your router will run as a user process locally, and when finished will route real packets that are flowing across the CS department network to application servers. We'll be giving you a skeleton, incomplete router (the "sr" or simple router) that you have to complete, and then demonstrate that it works by performing traceroutes, pings and downloading some files from a web server via your router.
Overview of the Virtual Network Lab (VNL)

Virtual Network Lab (VNL) is an educational platform where students can gain hands-on experience on network protocols by programming routers and hosts. It is inspired by Stanford VNS. VNL is comprised of two components: (1) The VNL services which run in a set of virtual machines on postino.cs.arizona.edu, and (2) VNL soft-hosts such as your router. The service intercepts packets on the network, forwards the packets to the soft-hosts, receives packets from the soft-host and injects them back into the network. The soft-hosts are run locally by the students as regular user processes and connect to the service via ssh tunnels. Clients, once connected to the server, are forwarded all packets that they are supposed to see in the topology. The soft-hosts can manipulate the packets in any way they wish, generate responses based on the packets, or make routing decisions for those packets and send the replies back to the service to place back onto the network.

###1-router 4-server topology

For example, on the above topology, the VNL service on vrhost might receive a TCP SYN packet from the CS department network destined for application server 1. The VNL service sends the packet to the VNL soft-host which would receive the packet on interface eth0, decrement the TTL, recalculate the header checksum, consult the routing table and send the packet back to the service with directions to inject it back onto the network out of interface eth1. What will the destination ethernet address be for the packet sent back by the client? What if the client doesn't know the ethernet address for application server 1?

In this assignment we are provide with the skeleton code for a basic VNL soft-host (called sr or Simple Router) that can connect and talk to the VNL service. Therefore, you don't need to be concerned about the interaction between VNL service and soft-host, or how packets flow in the physical topology. You can just focus on the virtual topology and your own router. Your job is to make the router fully functional by implementing the packet processing and forwarding part within the skeleton code. More specifically, you'll need to implement ARP, ICMP, and basic IP forwarding.
Test Driving the sr Stub Code



