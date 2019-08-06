packetCheck([H|T],X):-toDrop([H|T]),fillValue(X,dropped).
packetCheck([H|T],X):-toReject([H|T]),fillValue(X,rejected).
packetCheck([H|T],X):-not(toReject([H|T])),not(toDrop([H|T])),fillValue(X,accepted).
packetCheck([],X):-fillValue(X,accepted).

toReject([H|T]):-extractAdap([H|T],A,V,P,S,D,P2,Tc,Sr,Ds,Ty,C),reject(A,V,P,S,D,P2,Tc,Sr,Ds,Ty,C).
toDrop([H|T]):-extractAdap([H|T],A,V,P,S,D,P2,Tc,Sr,Ds,Ty,C),drop(A,V,P,S,D,P2,Tc,Sr,Ds,Ty,C).

extractAdap([H|T],A,V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-not(fillValue(H,adapter)),fillValue(A,any),extractEther([H|T],V,P,S,D,P2,Tc,Sr,Ds,Ty,C).
extractAdap([H|T],A,V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,adapter),extractAdap1(T,A,V,P,S,D,P2,Tc,Sr,Ds,Ty,C).
extractAdap1([],A,V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(A,any),extractEther([],V,P,S,D,P2,Tc,Sr,Ds,Ty,C).
extractAdap1([H|T],A,V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-not(fillValue(H,ether)),not(fillValue(H,ip)),not(fillValue(H,tcp)),not(fillValue(H,udp)),not(fillValue(H,icmp)),fillValue(H,A),extractEther(T,V,P,S,D,P2,Tc,Sr,Ds,Ty,C).
extractAdap1([H|T],A,V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,ether),fillValue(A,any),extractEther([H|T],V,P,S,D,P2,Tc,Sr,Ds,Ty,C).
extractAdap1([H|T],A,V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,ip),fillValue(A,any),extractEther([H|T],V,P,S,D,P2,Tc,Sr,Ds,Ty,C).
extractAdap1([H|T],A,V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,tcp),fillValue(A,any),extractEther([H|T],V,P,S,D,P2,Tc,Sr,Ds,Ty,C).
extractAdap1([H|T],A,V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,udp),fillValue(A,any),extractEther([H|T],V,P,S,D,P2,Tc,Sr,Ds,Ty,C).
extractAdap1([H|T],A,V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,icmp),fillValue(A,any),extractEther([H|T],V,P,S,D,P2,Tc,Sr,Ds,Ty,C).

extractEther([H|T],V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-not(fillValue(H,ether)),fillValue(V,any),fillValue(P,any),extractIP([H|T],S,D,P2,Tc,Sr,Ds,Ty,C).
extractEther([H|T],V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,ether),extractEtherVID(T,V,P,S,D,P2,Tc,Sr,Ds,Ty,C).
extractEtherVID([],V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(V,any),fillValue(P,any),extractIP([],S,D,P2,Tc,Sr,Ds,Ty,C).
extractEtherVID([H|T],V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-not(fillValue(H,vid)),fillValue(V,any),extractEtherProto([H|T],P,S,D,P2,Tc,Sr,Ds,Ty,C).
extractEtherVID([H|T],V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,vid),extractEtherVID1(T,V,P,S,D,P2,Tc,Sr,Ds,Ty,C).
extractEtherVID1([],V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(V,any),fillValue(P,any), extractIP([],S,D,P2,Tc,Sr,Ds,Ty,C).
extractEtherVID1([H|T],V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-not(fillValue(H,ip)),not(fillValue(H,tcp)),not(fillValue(H,udp)),not(fillValue(H,icmp)),not(fillValue(H,proto)),fillValue(H,V),extractEtherProto(T,P,S,D,P2,Tc,Sr,Ds,Ty,C).
extractEtherVID1([H|T],V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,ip),fillValue(V,any),fillValue(P,any), extractIP([H|T],S,D,P2,Tc,Sr,Ds,Ty,C).
extractEtherVID1([H|T],V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,tcp),fillValue(V,any),fillValue(P,any), extractIP([H|T],S,D,P2,Tc,Sr,Ds,Ty,C).
extractEtherVID1([H|T],V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,udp),fillValue(V,any),fillValue(P,any), extractIP([H|T],S,D,P2,Tc,Sr,Ds,Ty,C).
extractEtherVID1([H|T],V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,icmp),fillValue(V,any),fillValue(P,any), extractIP([H|T],S,D,P2,Tc,Sr,Ds,Ty,C).
extractEtherVID1([H|T],V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,proto),fillValue(V,any),extractEtherProto([H|T],P,S,D,P2,Tc,Sr,Ds,Ty,C).
extractEtherProto([],P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(P,any), extractIP([],S,D,P2,Tc,Sr,Ds,Ty,C).
extractEtherProto([H|T],P,S,D,P2,Tc,Sr,Ds,Ty,C):-not(fillValue(H,proto)),fillValue(P,any), extractIP([H|T],S,D,P2,Tc,Sr,Ds,Ty,C).
extractEtherProto([H|T],P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,proto),extractEtherProto1(T,P,S,D,P2,Tc,Sr,Ds,Ty,C).
extractEtherProto1([],P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(P,any), extractIP([],S,D,P2,Tc,Sr,Ds,Ty,C).
extractEtherProto1([H|T],P,S,D,P2,Tc,Sr,Ds,Ty,C):-not(fillValue(H,ip)),not(fillValue(H,tcp)),not(fillValue(H,udp)),not(fillValue(H,icmp)),fillValue(H,P), extractIP(T,S,D,P2,Tc,Sr,Ds,Ty,C).
extractEtherProto1([H|T],P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,ip),fillValue(P,any), extractIP([H|T],S,D,P2,Tc,Sr,Ds,Ty,C).
extractEtherProto1([H|T],P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,tcp),fillValue(P,any), extractIP([H|T],S,D,P2,Tc,Sr,Ds,Ty,C).
extractEtherProto1([H|T],P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,udp),fillValue(P,any), extractIP([H|T],S,D,P2,Tc,Sr,Ds,Ty,C).
extractEtherProto1([H|T],P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,icmp),fillValue(P,any), extractIP([H|T],S,D,P2,Tc,Sr,Ds,Ty,C).

extractIP([H|T],S,D,P2,Tc,Sr,Ds,Ty,C):-not(fillValue(H,ip)),fillValue(S,any),fillValue(D,any),fillValue(P2,any),extractTCP([H|T],Tc,Sr,Ds,Ty,C).
extractIP([H|T],S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,ip),extractIPsrc(T,S,D,P2,Tc,Sr,Ds,Ty,C).
extractIPsrc([],S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(S,any),fillValue(D,any),fillValue(P2,any),extractTCP([],Tc,Sr,Ds,Ty,C).
extractIPsrc([H|T],S,D,P2,Tc,Sr,Ds,Ty,C):-not(fillValue(H,src)),fillValue(S,any),extractIPdest([H|T],D,P2,Tc,Sr,Ds,Ty,C).
extractIPsrc([H|T],S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,src),extractIPsrc1(T,S,D,P2,Tc,Sr,Ds,Ty,C).
extractIPsrc1([],S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(S,any),fillValue(D,any),fillValue(P2,any), extractTCP([],Tc,Sr,Ds,Ty,C).
extractIPsrc1([H|T],S,D,P2,Tc,Sr,Ds,Ty,C):-not(fillValue(H,tcp)),not(fillValue(H,udp)),not(fillValue(H,icmp)),not(fillValue(H,dst)),not(fillValue(H,proto)),fillValue(H,S),extractIPdest(T,D,P2,Tc,Sr,Ds,Ty,C).
extractIPsrc1([H|T],S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,tcp),fillValue(S,any),fillValue(D,any),fillValue(P2,any), extractTCP([H|T],Tc,Sr,Ds,Ty,C).
extractIPsrc1([H|T],S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,udp),fillValue(S,any),fillValue(D,any),fillValue(P2,any), extractTCP([H|T],Tc,Sr,Ds,Ty,C).
extractIPsrc1([H|T],S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,icmp),fillValue(S,any),fillValue(D,any),fillValue(P2,any), extractTCP([H|T],Tc,Sr,Ds,Ty,C).
extractIPsrc1([H|T],S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,dst),fillValue(S,any),extractIPdest([H|T],D,P2,Tc,Sr,Ds,Ty,C).
extractIPsrc1([H|T],S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,proto),fillValue(S,any),fillValue(D,any),ext
ractIPproto([H|T],P2,Tc,Sr,Ds,Ty,C).
extractIPdest([],D,P2,Tc,Sr,Ds,Ty,C):-fillValue(D,any),fillValue(P2,any), extractTCP([],Tc,Sr,Ds,Ty,C).
extractIPdest([H|T],D,P2,Tc,Sr,Ds,Ty,C):-not(fillValue(H,dst)),fillValue(D,any),extractIPproto([H|T],P2,Tc,Sr,Ds,Ty,C).
extractIPdest([H|T],D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,dst),extractIPdest1(T,D,P2,Tc,Sr,Ds,Ty,C).
extractIPdest1([],D,P2,Tc,Sr,Ds,Ty,C):-fillValue(D,any),fillValue(P2,any), extractTCP([],Tc,Sr,Ds,Ty,C).
extractIPdest1([H|T],D,P2,Tc,Sr,Ds,Ty,C):-not(fillValue(H,tcp)),not(fillValue(H,udp)),not(fillValue(H,icmp)),not(fillValue(H,proto)),fillValue(H,D),extractIPproto(T,P2,Tc,Sr,Ds,Ty,C).
extractIPdest1([H|T],D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,tcp),fillValue(D,any),fillValue(P2,any), extractTCP([H|T],Tc,Sr,Ds,Ty,C).
extractIPdest1([H|T],D,Tc,Sr,Ds,Ty,C):-fillValue(H,udp),fillValue(D,any),fillValue(P2,any), extractTCP([H|T],Tc,Sr,Ds,Ty,C).
extractIPdest1([H|T],D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,icmp),fillValue(D,any),fillValue(P2,any), extractTCP([H|T],Tc,Sr,Ds,Ty,C).
extractIPdest1([H|T],D,P2,Tc,Sr,Ds,Ty,C):-fillValue(H,proto),fillValue(D,any),extractIPproto([H|T],P2,Tc,Sr,Ds,Ty,C).
extractIPproto([],P2,V,P,S,D,P2,Tc,Sr,Ds,Ty,C):-fillValue(P2,any), extractTCP([],Tc,Sr,Ds,Ty,C).
extractIPproto([H|T],P2,Tc,Sr,Ds,Ty,C):-not(fillValue(H,proto)),fillValue(P2,any), extractTCP([H|T],Tc,Sr,Ds,Ty,C).
extractIPproto([H|T],P2,Tc,Sr,Ds,Ty,C):-fillValue(H,proto),extractIPproto1(T,P2,Tc,Sr,Ds,Ty,C).
extractIPproto1([],P2,Tc,Sr,Ds,Ty,C):-fillValue(P2,any),fillValue([],Tc,Sr,Ds,Ty,C).
extractIPproto1([H|T],P2,Tc,Sr,Ds,Ty,C):-not(fillValue(H,tcp)),not(fillValue(H,udp)),not(fillValue(H,icmp)),fillValue(H,P2), extractTCP(T,Tc,Sr,Ds,Ty,C).
extractIPproto1([H|T],P2,Tc,Sr,Ds,Ty,C):-fillValue(H,tcp),fillValue(P2,any), extractTCP([H|T],Tc,Sr,Ds,Ty,C).
extractIPproto1([H|T],P2,Tc,Sr,Ds,Ty,C):-fillValue(H,udp),fillValue(P2,any), extractTCP([H|T],Tc,Sr,Ds,Ty,C).
extractIPproto1([H|T],P2,Tc,Sr,Ds,Ty,C):-fillValue(H,icmp),fillValue(P2,any), extractTCP([H|T],Tc,Sr,Ds,Ty,C).

extractTCP([H|T],Tc,Sr,Ds,Ty,C):-not(fillValue(H,tcp)),not(fillValue(H,udp)),fillValue(Tc,any),fillValue(Sr,any),fillValue(Ds,any),extractICMP([H|T],Ty,C).
extractTCP([H|T],Tc,Sr,Ds,Ty,C):-fillValue(H,tcp),fillValue(Tc,tcp),extractTCPsrc(T,Sr,Ds,Ty,C).
extractTCP([H|T],Tc,Sr,Ds,Ty,C):-fillValue(H,udp),fillValue(Tc,udp),extractTCPsrc(T,Sr,Ds,Ty,C).
extractTCPsrc([],Sr,Ds,Ty,C):-fillValue(Sr,any),fillValue(Ds,any),extractICMP([],Ty,C).
extractTCPsrc([H|T],Sr,Ds,Ty,C):-not(fillValue(H,src)),fillValue(Sr,any),extractTCPdest([H|T],Ds,Ty,C).
extractTCPsrc([H|T],Sr,Ds,Ty,C):-fillValue(H,src),extractTCPsrc1(T,Sr,Ds,Ty,C).
extractTCPsrc1([],Sr,Ds,Ty,C):-fillValue(Sr,any),fillValue(Ds,any), extractICMP([],Ty,C).
extractTCPsrc1([H|T],Sr,Ds,Ty,C):-not(fillValue(H,icmp)),not(fillValue(H,dst)),fillValue(H,Sr),extractTCPdest(T,Ds,Ty,C).
extractTCPsrc1([H|T],Sr,Ds,Ty,C):-fillValue(H,icmp),fillValue(Sr,any),fillValue(Ds,any), extractICMP([H|T],Ty,C).
extractTCPsrc1([H|T],Sr,Ds,Ty,C):-fillValue(H,dst),fillValue(Sr,any),extractTCPdest([H|T],Ds,Ty,C).
extractTCPdest([],Ds,Ty,C):-fillValue(Ds,any), extractICMP([],Ty,C).
extractTCPdest([H|T],Ds,Ty,C):-not(fillValue(H,dst)),fillValue(Ds,any), extractICMP([H|T],Ty,C).
extractTCPdest([H|T],Ds,Ty,C):-fillValue(H,dst),extractTCPdest1(T,Ds,Ty,C).
extractTCPdest1([],Ds,Ty,C):-fillValue(Ds,any), extractICMP([],Ty,C).
extractTCPdest1([H|T],Ds,Ty,C):-not(fillValue(H,icmp)),fillValue(H,Ds), extractICMP(T,Ty,C).
extractTCPdest1([H|T],Ds,Ty,C):-fillValue(H,icmp),fillValue(Ds,any), extractICMP([H|T],Ty,C).

extractICMP([],Ty,C):-fillValue(Ty,any),fillValue(C,any).
extractICMP([H|T],Ty,C):-not(fillValue(H,icmp)),fillValue(Ty,any),fillValue(C,any).
extractICMP([H|T],Ty,C):-fillValue(H,icmp),extractICMPtype(T,Ty,C).
extractICMPtype([],Ty,C):-fillValue(Ty,any),fillValue(C,any).
extractICMPtype([H|T],Ty,C):-not(fillValue(H,type)),fillValue(Ty,any),extractICMPcode([H|T],C).
extractICMPtype([H|T],Ty,C):-fillValue(H,type),extractICMPtype1(T,Ty,C).
extractICMPtype1([],Ty,C):-fillValue(Ty,any),fillValue(C,any).
extractICMPtype1([H|T],Ty,C):-not(fillValue(H,code)),fillValue(H,Ty),extractICMPcode(T,C).
extractICMPtype1([H|T],Ty,C):-fillValue(H,code),fillValue(Ty,any),extractICMPcode([H|T],C).
extractICMPcode([],C):-fillValue(C,any).
extractICMPcode([H|T],C):-fillValue(H,code),extractICMPcode1(T,C).
extractICMPcode1([],C):-fillValue(C,any).
extractICMPcode1([H|T],C):-fillValue(H,C).

fillValue(X,X).

drop(a,1,0x1234,'192.0.0.1','192.0.0.0',0x1234,tcp,'172.1.98.98','172.1.99.99',10,65000).
reject(b,2,0xffff,'192.0.0.0','192.0.0.1',0xffff,udp,'172.1.99.99','172.1.98.98',10,0).