#!/usr/bin/env python
import dpkt
import math


#Packet[SourcePort,DesinationPort,SeequenceNumber,AckNumber,Flags,Length]
#Packets[Packet1,Packet2...]

def packetinit(timestamp, buf): #PacketDefinition
    packet = []
    sourceport = int.from_bytes(buf[34:36], byteorder='big')
    desinationport = int.from_bytes(buf[36:38], byteorder='big')
    sequencenumber = int.from_bytes(buf[38:42], byteorder='big')
    acknumber = int.from_bytes(buf[42:46], byteorder='big')
    flag = int.from_bytes(buf[46:48], byteorder='big') & 0x0FFF
    windowsize = int.from_bytes(buf[48:50], byteorder='big')

    packet.append(sourceport)
    packet.append(desinationport)
    packet.append(sequencenumber)
    packet.append(acknumber)
    packet.append(flag)
    packet.append(len(buf))
    packet.append(windowsize)
    packet.append(timestamp)

    return packet

def Firstwovalues(listofuniqueports,listofpackets):
    ## Print the first two values
    k = 0
    for val in listofpackets:
        sourcepacket = 0
        destinationpacket = 0
        currsource = listofuniqueports[k][0] #130.245.145.12
        currdest = listofuniqueports[k][1]  #128.208.2.198
        print("For Port",currsource)
        for val2 in val:
            if(val2[4]==16):
                clientsource = val2[0]
                clientdestin = val2[1]
                if sourcepacket == 2 and destinationpacket == 2:
                    print("\n")
                    break
                if (currsource == clientsource and currdest == clientdestin and sourcepacket != 2):
                    if(sourcepacket==0):
                        print("Sender Message")
                    print("Source:", val2[0], "Destination :", val2[1], "Sequence Number : ",
                          val2[2], "Ack Number :", val2[3],"Window Size:",val2[6])
                    sourcepacket += 1
                elif (currsource == clientdestin and currdest == clientsource and destinationpacket != 2):
                    if(destinationpacket==0):
                        print("Destination Message")
                    print("Source :", val2[0], "Destination", val2[1], "Sequence Number", val2[2],
                          "Ack Number", val2[3],"Window size:",val2[6])
                    destinationpacket += 1
        k += 1

def EffectiveThroughpout(listofpackets):
    k=1
    for eachpacket in listofpackets:
        sum = 0
        for pk in eachpacket:
            sum += pk[5]

        startingtime = eachpacket[0][7]
        endingtime = eachpacket[len(eachpacket) - 1][7]
        time = endingtime - startingtime
        print("The Empirical Throughput for Flow ",k,"is", sum / time)
        k +=1
    print("\n")


def LossRate(listofuniqueports,listofpackets):
    k=1
    t=0
    listofLossRate=[]
    for uniqueport in listofpackets:
        seqnoretrans = {}
        count = 0 #Iterator to go through the packets
        noofpacketsent = 0
        skiphandshakepacket = 0 #Skip the Ack in the handshake packet
        sourceport = listofuniqueports[t][0]
        desinationport = listofuniqueports[t][1]
        noofpacketsnotrecieved = 0
        for templist in uniqueport:
            if(templist[4] == 2 or templist[4] == 18 or skiphandshakepacket == 2): #Skipped initial Handshake packets
                skiphandshakepacket += 1
                count += 1
                continue
            if(len(uniqueport)-1 == count or len(uniqueport) -2 == count): #Skipped the Final packets
                continue
            if(templist[0] == sourceport and templist[1] == desinationport): #Sender to Reciever
                noofpacketsent += 1
                if(templist[2] in seqnoretrans):
                    noofpacketsnotrecieved += 1
                else:
                    seqnoretrans[templist[2]] = 1
            count += 1
        if (noofpacketsnotrecieved != 0):
            lossrate = noofpacketsnotrecieved / noofpacketsent
            listofLossRate.append(lossrate)
            print("The loss rate for Flow", k, "is", lossrate)

        else:
            listofLossRate.append(-1)
            print("The loss rate for Flow", k, "is",0)
        t+=1
        k+=1
    print("\n")
    return listofLossRate

def MessageSent(listofuniqueports,listofpackets):
    listofmessagesent=[]
    k = 0
    for uniqueport in listofpackets:
        messagesent = {}
        count = 0 #Iterator to go through the packets
        skiphandshakepacket = 0 #Skip the Ack in the handshake packet
        sourceport = listofuniqueports[k][0]
        desinationport = listofuniqueports[k][1]
        for templist in uniqueport:
            if(templist[4] == 2 or templist[4] == 18 or skiphandshakepacket == 2): #Skipped initial Handshake packets
                skiphandshakepacket += 1
                count += 1
                continue
            if(len(uniqueport)-1 == count or len(uniqueport) - 2 == count): #Skipped the Final packets
                continue
            if(templist[0] == sourceport and templist[1] == desinationport): #From Source to Destination
                if(templist[2] not in messagesent):
                    messagesent[templist[2]] = templist[7]                  #Time at which a message is sent
            count += 1
        listofmessagesent.append(messagesent)
        k+=1
    return listofmessagesent

def MessageRecieved(listofuniqueports,listofpackets):
    listofmessagerecieved = []  # Contains a map with values
    k = 0

    for uniqueport in listofpackets:
        messagerecieved = {} #Time it took for a message to recieve at the destination side.
        count = 0 #Iterator to go through the packets
        skiphandshakepacket = 0 #Skip the Ack in the handshake packet
        sourceport = listofuniqueports[k][0]
        desinationport = listofuniqueports[k][1]
        for templist in uniqueport:
            if(templist[4] == 2 or templist[4] == 18 or skiphandshakepacket == 2): #Skipped initial Handshake packets
                skiphandshakepacket += 1
                count += 1
                continue
            if(len(uniqueport)-1 == count or len(uniqueport) - 2 == count): #Skipped the Final packets
                continue
            if(templist[0] == desinationport and templist[1] == sourceport): #Destination to source
                if(templist[3] not in messagerecieved): #Adding Ack recieved from the reciever indicating message
                    messagerecieved[templist[3]] = templist[7]       #key => Ack, Value => Time taken to recieve the message
                count += 1
        listofmessagerecieved.append(messagerecieved)
        k += 1
    return listofmessagerecieved

def RTT(listofmessagesent,listofmessagerecieved):
    k = 1
    listofRTT=[]
    for i in range(0,len(listofmessagesent)):
        Roundtriptime = 0
        totaltime = 0
        for messagesent in listofmessagesent[i]:
            for messagerecieved in listofmessagerecieved[i]:
                if(messagesent != messagerecieved):
                    continue
                else:
                    timetosend = listofmessagesent[i].get(messagesent)
                    timetorecieve = listofmessagerecieved[i].get(messagerecieved)
                    Roundtriptime += timetorecieve - timetosend
                    totaltime += 1
        listofRTT.append(Roundtriptime/totaltime)
        print("Average RTT for Flow",k,"is",Roundtriptime/totaltime)
        k += 1

    print("\n")
    return listofRTT

def TheoreticalThroughput(listofRTT, listofLossRate):
    MaximumSegSize = 1460

    val = math.sqrt(3)/math.sqrt(2)

    for i in range(0,len(listofRTT)):
        if(listofLossRate[i]<0):
            print("The Theoretical Throughput for Flow",i+1,"is Infinity")
        else:
            print("The Theoretical Throughput for Flow",i+1,"is",val*(1/(math.sqrt(listofLossRate[i])))*(MaximumSegSize/listofRTT[i]))


f = open('assignment2.pcap','rb')
pcap = dpkt.pcap.Reader(f)
count=0
numofpacket = 0
packets=[]
for ts, buf in pcap:
    x = packetinit(ts,buf)
    packets.append(x)

k = 1
listofuniqueports=[]
for uniqueportnumbers in packets:
    if(uniqueportnumbers[4]==18):
        templist=[]
        desinationport = uniqueportnumbers[0]
        sourceport = uniqueportnumbers[1]
        templist.append(sourceport)
        templist.append(desinationport)
        listofuniqueports.append(templist)
    k = k+1


val = 0
listofpackets=[]
for uniqueport in listofuniqueports:
    uniquesourceport = uniqueport[0]
    uniquedestinationport = uniqueport[1]
    templist=[]
    for eachpacket in packets:
        packetsourceport = eachpacket[0]
        packetdestinationport = eachpacket[1]
        if((uniquesourceport == packetsourceport and uniquedestinationport == packetdestinationport) or (uniquesourceport == packetdestinationport and uniquedestinationport == packetsourceport)):
            templist.append(eachpacket)
    listofpackets.append(templist)
    val += 1


print("The Number of flow initiated is", len(listofuniqueports))
print("CLIENT       FLOW        SERVER")
for uniqueport in listofuniqueports:
    print(uniqueport[0],"<------------------->",uniqueport[1])
Firstwovalues(listofuniqueports,listofpackets) #1-a
EffectiveThroughpout(listofpackets) #1-b
listofLossRate = LossRate(listofuniqueports,listofpackets)  #1-c
#1-d
listofmessagesent = MessageSent(listofuniqueports,listofpackets)
listofmessagerecieved = MessageRecieved(listofuniqueports,listofpackets)
listofRTT = RTT(listofmessagesent,listofmessagerecieved)
TheoreticalThroughput(listofRTT,listofLossRate)


f.close()
