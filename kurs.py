import socket
import struct
import dpkt

PORT = 25565 

HOST = socket.gethostbyname(socket.gethostname()) ##GETTING IP
socketInf = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP) ##IPV4

socketInf.bind((HOST,PORT))

socketInf.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)#TO RECIVE ALL

def main():
    f = open("log.txt", 'w')
    for n in range(200):
        print('Packet Number: ', n)
        data=socketInf.recvfrom(65515) ##MAX SIZE OF PACKETS
        packet=data[0]
        address= data[1] 
        header=struct.unpack('!BBHHHBBHBBBBBBBB', packet[:20]) ##BY FIRST NUMBERS IN PACKET GETTING NAME OF PROTOCOL
        if(header[6]==6): 
            f.write("ID = " + str(n) + " TCP:\n   ")
            print("Protocol = TCP")
        elif(header[6]==17):
            f.write("ID = " + str(n) + " UDP:\n    ")
            print("Protocol = UDP")
            f.write("ACII 8-bit:\n    " + str(dpkt.udp.UDP(packet)) + "\n    HEX:\n   ")
        elif(header[6]==1):
            f.write("ID = " + str(n) + " ICMP:\n   ")
            print("Protocol = ICMP")
        print(address)
        f.write("{}".format(''.join(' {:02x}'.format(b) for b in packet)))
        print("{}".format(''.join(' {:02x}'.format(b) for b in packet)))
        f.write("\n    DEC:\n  " + "{}".format(''.join(' {:3d}'.format(b) for b in packet)) + '\n\n')
        n=n+1

if __name__ == "__main__":
    main()