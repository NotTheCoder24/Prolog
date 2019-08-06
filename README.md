# Prolog
Implementing FIREWALL in prolog

PacketInfo:

List which contains 11 comma separated info : (adapterId, etherVid, etherProto, IPsrc, IPdest, IPproto, tcp/udp, tcp/udp src, tcp/udp dest, icmp type, icmp code)

Predicates:

packetCheck(PacketInfo, X)
Checks whether packet needs to be dropped/rejected/accepted

toDrop(PacketInfo)
Checks whether packet needs to be dropped

toReject(PacketInfo)
Checks whether packet needs to be dropped

fillValue(X,dropped|rejected|accepted)
Fills value of dropped/rejected/accepted to X 


extractAdapt(PacketInfo, Adapter, EtherVid, EtherProto, IPSource, IPDestination, IPProto, Source, Destination, Type, Code)
Extracts Adapter info from packet and calls the next parsing procedure

extractAdapt1(PacketInfo, Adapter, FilteredPacketInfo)
Fills the values of Adapter Id into `Adapter` Variable

extractEther(PacketInfo, EtherVid, EtherProto, IPSource, IPDestination, IPProto, Source, Destination, Type, Code
Extracts EtherInfo from the packet and calls the next parsing procedure

extractEtherVID(PacketInfo, EtherVid, EtherProto, IPSource, IPDestination, IPProto, Source, Destination, Type, Code)
Extracts EtherVID from the packet and calls the next parsing procedure

extractEtherVID1(PacketInfo, EtherVid, EtherProto, IPSource, IPDestination, IPProto, Source, Destination, Type, Code)
Fills the values of Ether Vid into `EtherVid` Variable

extractEtherProto(PacketInfo, EtherVid, EtherProto, IPSource, IPDestination, IPProto, Source, Destination, Type, Code)
Extracts EtherProto from the packet and calls the next parsing procedure

extractEtherProto1(PacketInfo, EtherVid, EtherProto, IPSource, IPDestination, IPProto, Source, Destination, Type, Code)
Fills the values of Ether Proto into `EtherProto` Variable

extractIP(PacketInfo ,IPSource, IPDestination, IPProto, Source, Destination, Type, Code)
Extracts EtherIP from the packet and calls the next parsing procedure

extractIPsrc(PacketInfo ,IPSource, IPDestination, IPProto, Source, Destination, Type, Code)
Extracts EtherIP  src from the packet and calls the next parsing procedure

extractIPdest(PacketInfo ,IPSource, IPDestination, IPProto, Source, Destination, Type, Code)
Extracts EtherIP dest from the packet and calls the next parsing procedure

extractIPsrc1(PacketInfo ,IPSource, IPDestination, IPProto, Source, Destination, Type, Code)
Fills the values of IP src into `Source` Variable

extractIPdest1(PacketInfo ,IPSource, IPDestination, IPProto, Source, Destination, Type, Code)
Fills the values of IP dest into `Destination` Variable

extractIPproto(PacketInfo ,IPSource, IPDestination, IPProto, Source, Destination, Type, Code)
Extracts EtherIP Proto from the packet and calls the next parsing procedure

extractIPproto1(PacketInfo ,IPSource, IPDestination, IPProto, Source, Destination, Type, Code)
Fills the values of IP proto into `Proto` Variable

extractTCP(PacketInfo ,Source, Destination, Type, Code)
Checks whether packet corresponds to tcp or udp

extractTCPsrc(PacketInfo ,Source, Destination, Type, Code)
Extracts EtherIP src from the packet and calls the next parsing procedure

extractTCPdest(PacketInfo ,Source, Destination, Type, Code)
Extracts EtherIP dest from the packet and calls the next parsing procedure

extractTCPsrc1(PacketInfo ,Source, Destination, Type, Code)
Fills the values of IP dest into `Destination` Variable

extractTCPdest1(PacketInfo ,Source, Destination, Type, Code)
Fills the values of IP dest into `Destination` Variable

extractICMP(PacketInfo, Type, Code)
Extracts ICMP info from the packet and calls the next parsing procedure

extractICMPtype(PacketInfo, Type, Code)
Extracts ICMP type from the packet and calls the next parsing procedure

extractICMPtype1(PacketInfo, Type, Code)
Fills the values of ICMP type into `Type` Variable

extractICMPcode(PacketInfo, Type, Code)
Extracts ICMP code from the packet and calls the next parsing procedure

extractICMPcode1(PacketInfo, Type, Code)
Fills the values of ICMP code into `Code` Variable

Database: 


drop(a,1,0x1234,'192.0.0.1','192.0.0.0',0x1234,tcp,'172.1.98.98','172.1.99.99',10,65000).

reject(b,2,0xffff,'192.0.0.0','192.0.0.1',0xffff,udp,'172.1.99.99','172.1.98.98',10,0).

More data can be added with facts of the form:
drop/reject(AdapterID,EtherVID,EtherProto,IPSource,IPDestination,IPProto,Tcp/Udp,Source,Destination,ICMPType,ICMPCode).

			
Sample Input/Output : 

Input:packetCheck([adapter,a,ether,vid,1,proto,0x1234,ip,src,'192.0.0.1',dst,'192.0.0.0',proto,0x1234,tcp,src,'172.1.98.98',dst,'172.1.99.99',icmp,type,10,code,65000],Ans).
Output: Ans = dropped .

Input:packetCheck([adapter,b,ether,vid,2,proto,0xffff,ip,src,'192.0.0.0',dst,'192.0.0.1',proto,0xffff,udp,src,'172.1.99.99',dst,'172.1.98.98',icmp,type,10,code,0],Ans).
Output: Ans = rejected .

Input: packetCheck([],Ans).
Output: Ans = accepted.

Input: packetCheck([adapter,ether,ip,tcp,icmp],Ans).
Output: Ans = accepted.
