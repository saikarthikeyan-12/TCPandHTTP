import dpkt


packets=[]
#Packet[SourcePort,DesinationPort,SequenceNumber,AckNumber,Flags,Length]
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

def PreComputedSenderPackets(listofpackets,listofuniqueports):
    t = 0
    ListofPacketsFromSender = []
    for uniqueportpacket in listofpackets:
        sourceport = listofuniqueports[t][0]
        desinationport = listofuniqueports[t][1]
        skippackets = 0
        packetsfromsender = []
        for templist in uniqueportpacket:
            if (templist[4] == 2 or templist[4] == 18 or skippackets < 4):  # Skipped an extra packet to account for the loss of ack packet
                skippackets += 1
                continue
            if (templist[0] == sourceport and templist[1] == desinationport):  # Source
                packetsfromsender.append(templist)
        ListofPacketsFromSender.append(packetsfromsender)
        t += 1
    return ListofPacketsFromSender

#CongestionWindow
def First10CongestionWindow(listofpackets,listofuniqueports,ListofPacketsFromSender):
    t = 0
    for uniqueportpacket in listofpackets:
        sourceport = listofuniqueports[t][0]
        desinationport = listofuniqueports[t][1]
        lastpacketread = -1
        iteratorstart = 0
        iteratorend = 0
        skippackets = 0  # Skip the Ack in the handshake packet
        firstensize = 0
        print("The Source Port is", sourceport)
        print("First 10 Congestion size")
        for templist in uniqueportpacket:
            if firstensize == 10:
                break
            if (templist[4] == 2 or templist[4] == 18 or skippackets < 4):  # Skipped an extra packet to account for the loss of ack packet
                skippackets += 1
                continue
            if (templist[0] == sourceport and templist[1] == desinationport):  #At Sender
                iteratorend += 1
            else: #Reciever
                if (ListofPacketsFromSender[t][iteratorstart][2] == templist[3]):  # Seqno == Ack
                    lastpacketread = ListofPacketsFromSender[t][iteratorstart][2]
                    print(iteratorend - iteratorstart + 1)
                    firstensize += 1
                    iteratorstart += 1
        t += 1
def RetransmissionOccured(listofpackets,listofuniqueports,ListofPacketsFromSender):
    t = 0
    for uniqueportpacket in listofpackets:
        sourceport = listofuniqueports[t][0]
        desinationport = listofuniqueports[t][1]
        lastpacketread = -1
        iteratorstart = 0
        iteratorend = 0
        skippackets = 0  # Skip the Ack in the handshake packet
        seqnocount = {}      #Stores Sequence, count
        acknocount = {}      #Stores Ack of Seqno, Count
        timeoutretransmission = 0
        duplicateackretransmission =0
        print("The Source Port is", sourceport)
        for templist in uniqueportpacket:
            if (templist[4] == 2 or templist[4] == 18 or skippackets < 4):  # Skipped an extra packet to account for the loss of ack packet
                skippackets += 1
                continue
            if (templist[0] == sourceport and templist[1] == desinationport): #Source
                iteratorend += 1
                if(templist[2] not in seqnocount):
                    seqnocount[templist[2]] = 1
                else:
                    seqnocount[templist[2]] = seqnocount[templist[2]]+1 #If it is being sent multiple times, check the no of times reciever pinged it
                if(seqnocount[templist[2]] == 2): #If the count is 2, a packet has been retransmitted
                    if acknocount[templist[2]] == 1: #If only one ack is received, time out retransmission
                        timeoutretransmission += 1
                    elif acknocount[templist[2]] > 3:
                        #print("hiw")
                        duplicateackretransmission += 1
            else:      #Destination
                if (ListofPacketsFromSender[t][iteratorstart][2] == templist[3]):  # Seqno == Ack
                    lastpacketread = ListofPacketsFromSender[t][iteratorstart][2]
                    #print(iteratorend - iteratorstart + 1)
                    iteratorstart += 1
                if (templist[3] not in acknocount):
                    acknocount[templist[3]] = 1
                else:
                    acknocount[templist[3]] = acknocount[templist[3]] + 1
        print("Retransmission due to Triple Duplicate",duplicateackretransmission)
        print("Retransmission due to Time out",timeoutretransmission)
        print("\n")
        t += 1

f = open('assignment2.pcap','rb')
pcap = dpkt.pcap.Reader(f)
for ts, buf in pcap:
    x = packetinit(ts,buf)
    packets.append(x)
k = 1
listofuniqueports=[]
for uniqueportnumbers in packets:
    if(uniqueportnumbers[4]==2):   #Checks 18 as it returns fin =1
        templist=[]
        sourceport = uniqueportnumbers[0]
        desinationport = uniqueportnumbers[1]
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

ListofPacketsFromSender = PreComputedSenderPackets(listofpackets,listofuniqueports)

First10CongestionWindow(listofpackets,listofuniqueports,ListofPacketsFromSender)

RetransmissionOccured(listofpackets,listofuniqueports,ListofPacketsFromSender)
