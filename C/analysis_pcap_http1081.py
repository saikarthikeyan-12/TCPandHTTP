import dpkt

#Packet[SourcePort,DesinationPort,SeequenceNumber,AckNumber,Flags,Length,WindowSize, Timestamp]
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

f = open('tcp_1081.pcap','rb')
pcap = dpkt.pcap.Reader(f)
count=0
numofpacket = 0
temppackets=[]
for ts, buf in pcap:
    x = packetinit(ts,buf)
    temppackets.append(x)

packets = []
sentpacket = 0
sentbytes = 0
for uniquepacket in temppackets:
    if(uniquepacket[0] == 1081):
        packets.append(uniquepacket)
    elif(uniquepacket[1] == 1081):
        sentpacket += 1
        sentbytes += uniquepacket[5]   #Buffer Length
        packets.append(uniquepacket)

listofuniqueports=[]

for uniqueportnumbers in packets:
    if(uniqueportnumbers[4] == 18):   #Checks 18 as it returns fin =1
        templist=[]
        desinationport = uniqueportnumbers[0]
        sourceport = uniqueportnumbers[1]
        templist.append(sourceport)
        templist.append(desinationport)
        listofuniqueports.append(templist)
#print("the length",len(packets))
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


t=0
http10flag = 1
minvaluepayload = 166
for uniqueport in listofpackets:
    sourceport = listofuniqueports[t][0]
    desinationport = listofuniqueports[t][1]
    countgetmessagepacket = {}
    count = 0
    for templist in uniqueport:
        if(templist[5] < minvaluepayload):       #Removes the Values without payload
            continue
        if (templist[0] == sourceport and templist[1] == desinationport):  #Sender to Reciever
            #GET REQUEST
            if(templist[3] not in countgetmessagepacket):
                countgetmessagepacket[templist[3]] = 1
            else:
                http10flag = 0
            #print("Send message",templist)
        count+=1
    #print("total Count is",count)
    t += 1

#C-2
print("The HTTP Version is")
if len(listofuniqueports) == 2:   #One for Encyption, One for Data
    print("HTTP 2")
elif(http10flag == 0 and len(listofuniqueports)==6):
    print("HTTP 1.1")
elif (http10flag == 1):
    print("HTTP 1.0")

#C-3

print("Number of sent packets",sentpacket)
print("Number of Raw bytes sent", sentbytes)
print("The Transmission time for Port: 1081 is",packets[len(packets)-1][7] -packets[0][7])