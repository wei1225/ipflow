////////////////////////////////////
//Author:Focus                    //
//time:2013.4.26                  //
//Description:Get information from//
//            http packet!(Demo)  //
//                                //
////////////////////////////////////
#include "gnInclude.h"
#include "libcom.h"
#include "gnDb.h"
#include "gnNet.h"
#include "gnLog.h"
#include "string.h"
#include "math.h"
#include "arpa/inet.h"
#include "time.h"
#define HOST        "localhost"
#define DB_NAME     "test"
#define USER_NAME   "root" 
#define PASSWD      "buptnic"
#define MODE_NORMAL 1
#define MODE_URGENT 0
#define IP_VERSION4 4
#define IP_VERSION6 6
#define IP_SRC 0
#define IP_DEST
/////////////////////////////////////
int sockfd1 =-1,sockfd2=-1;
int flag=0,mode=1;
int debug_flag=0;
int pkt_id=0;
struct rule{
    UINT1 ip_version;
    UINT4 sip;
    UINT1 smask_len;
    UINT4 dip;
    UINT1 dmask_len;
    UINT1 sip_v6[16];
    UINT1 dip_v6[16];
    UINT2 sport_low;
    UINT2 sport_high;
    UINT2 dport_low;
    UINT2 dport_high;
    UINT1 proto;
};
struct list{
    struct rule *r;
    int length;
};
struct packet{
    UINT2 ether_type;
    UINT4 sip;
    UINT4 dip;
    UINT1 sip_v6[16];
    UINT1 dip_v6[16];
    UINT2 sport;
    UINT2 dport;
    UINT1 proto;
};
struct packet *pkt;
struct list *l;
clock_t start,start1,end,end1;
/////////////////////////////////////

int method_normal(struct packet *pkt,tEthpkt *pkthdr,struct list *l){
    int i=0,j,flag=1,sbtes=0,dbytes=0;
    UINT4 pkt_msip=0,pkt_mdip=0,r_msip=0,r_mdip=0,smask,dmask;
    while(i<l->length){
        smask=0,dmask=0;
        if(pkt->ether_type==ETHERTYPE_IP && l->r[i].ip_version==IP_VERSION4){
            for(j=1;j<=l->r[i].smask_len;j++){
                smask+=1<<(32-j);
            }
            for(j=1;j<=l->r[i].dmask_len;j++){
                dmask+=1<<(32-j);
            }
            pkt_msip=pkt->sip & smask;
            pkt_mdip=pkt->dip & dmask;
            r_msip=l->r[i].sip & smask;
            r_mdip=l->r[i].dip & dmask;
        }
        else if(pkt->ether_type==ETHERTYPE_IPv6 && l->r[i].ip_version==IP_VERSION6){
            sbytes=l->r[i].smask_len/8;
            dbytes=l->r[i].dmask_len/8;
            for(j=1;j<=l->r[i].smask_len%8;j++){
                smask+=1<<(8-j);
            }
            for(j=1;j<=l->r[i].dmask_len%8;j++){
                dmask+=1<<(8-j);
            }
            pkt_msip=pkt->sip_v6[sbytes] & smask;
            pkt_mdip=pkt->dip_v6[dbytes] & dmask;
            r_msip=l->r[i].sip_v6[sbytes] & smask;
            r_mdip=l->r[i].dip_v6[dbytes] & dmask;
            for(j=0;j<sbytes;j++){
                if(pkt->sip_v6[j]!=l->r[i].sip_v6[j])
                    flag=0;
            }
            for(j=0;j<dbytes;j++){
                if(pkt->dip_v6[j]!=l->r[i].dip_v6[j])
                    flag=0;
            }
        }
        else{
            i++;
            continue;
        } 
       
        if(flag==1&&pkt_msip==r_msip&&pkt_mdip==r_mdip&&pkt->sport>=l->r[i].sport_low&&pkt->sport<=l->r[i].sport_high&&pkt->dport>=l->r[i].dport_low&&pkt->dport<=l->r[i].dport_high&&
        	pkt->proto==l->r[i].proto){
              printf("packet %d mach rule %d\n",pkt_id,i+1);
              return 1;
        }
        i++;
    }
    printf("packet %d match no rule\n",pkt_id);
    xmit_packet(sockfd2,pkthdr->pid,pkthdr);
    return 1;


}
int method_urgent(struct packet *pkt,tEthpkt *pkthdr,struct list *l){
    int i=0,j,flag=1,sbytes=0,dbytes=0;
    UINT4 pkt_msip=0,pkt_mdip=0,r_msip=0,r_mdip=0,smask=0,dmask=0;
    while(i<l->length){
        if(pkt->ether_type==ETHERTYPE_IP){
            for(j=1;j<=l->r[i].smask_len;j++){
                smask+=1<<(32-j);
            }
            for(j=1;j<=l->r[i].dmask_len;j++){
                dmask+=1<<(32-j);
            }
            pkt_msip=pkt->sip & smask;
            pkt_mdip=pkt->dip & dmask;
            r_msip=l->r[i].sip & smask;
            r_mdip=l->r[i].dip & dmask;
        }
        else if(pkt->ether_type==ETHERTYPE_IPv6){
            sbytes=l->r[i].smask_len/8;
            dbytes=l->r[i].dmask_len/8;
            for(j=1;j<=l->r[i].smask_len%8;j++){
                smask+=1<<(8-j);
            }
            for(j=1;j<=l->r[i].dmask_len%8;j++){
                dmask+=1<<(8-j);
            }
            pkt_msip=pkt->sip_v6[sbytes] & smask;
            pkt_mdip=pkt->dip_v6[dbytes] & dmask;
            r_msip=l->r[i].sip_v6[sbytes] & smask;
            r_mdip=l->r[i].dip_v6[dbytes] & dmask;
            for(j=0;j<sbytes;j++){
                if(pkt->sip_v6[j]!=l->r[i].sip_v6[j])
                    flag=0;
            }
            for(j=0;j<dbytes;j++){
                if(pkt->dip_v6[j]!=l->r[i].dip_v6[j])
                    flag=0;
            }
        }
        if(flag==1&&pkt_msip==r_msip&&pkt_mdip==r_mdip&&pkt->sport>=l->r[i].sport_low&&pkt->sport<=l->r[i].sport_high&&pkt->dport>=l->r[i].dport_low&&pkt->dport<=l->r[i].dport_high&&
        	pkt->proto==l->r[i].proto){
              printf("packet %d mach rule %d\n",pkt_id,i+1);
              xmit_packet(sockfd2,pkthdr->pid,pkthdr);
              return 1;
        }
        i++;
    }
    printf("packet %d match no rule\n",pkt_id);
    return 1;
}
void convert(char *sip,char *dip,int row){
    int i;
    l->r[row].smask_len=0;
    l->r[row].dmask_len=0;
    if(l->r[row].ip_version==IP_VERSION4){	
        char *cursor;
        cursor=strchr(sip,'/')+1;
        while(*cursor!='\0'){
            l->r[row].smask_len+=pow(10,(float)(strlen(sip)-(cursor-sip+1)))*(*cursor-'0');           
            cursor++;
        }
        cursor=strchr(dip,'/')+1;
        while(*cursor!='\0'){
            l->r[row].dmask_len+=pow(10,(float)(strlen(dip)-(cursor-dip+1)))*(*cursor-'0');           
            cursor++;
        }
        *strchr(sip,'/')='\0';
        *strchr(dip,'/')='\0';
        l->r[row].sip=ntohl(inet_addr(sip));
        l->r[row].dip=ntohl(inet_addr(dip));
    }
    else if(l->r[row].ip_version==IP_VERSION6){
        struct in6_addr src_ip,dest_ip;
        char *cursor;
        cursor=strchr(sip,'/')+1;
        while(*cursor!='\0'){
            l->r[row].smask_len+=pow(10,(float)(strlen(sip)-(cursor-sip+1)))*(*cursor-'0');            
            cursor++;
        }
        cursor=strchr(dip,'/')+1;
        while(*cursor!='\0'){
            l->r[row].dmask_len+=pow(10,(float)(strlen(dip)-(cursor-dip+1)))*(*cursor-'0');            
            cursor++;
        }
        *strchr(sip,'/')='\0';
        *strchr(dip,'/')='\0';
        inet_pton(AF_INET6,sip,(void*)&src_ip);
        inet_pton(AF_INET6,dip,(void*)&dest_ip);
        for(i=0;i<16;i++){
            l->r[row].sip_v6[i]=src_ip.s6_addr[i];
            l->r[row].dip_v6[i]=dest_ip.s6_addr[i];
        }
    }
   
}
int db_qurry(struct list *l,int mode){
	int handle;
	int retValue;
	int row=0;
    char sql[100];
    char *db_table="blacklist",*sip,*dip;
	retValue = db_init();
	if(retValue == DB_FAILURE){
		if(debug_flag){
		    printf("db_init failure!\n");
		}
		return -1;
	}

	handle = db_open(HOST, DB_NAME, USER_NAME, PASSWD, DB_MYSQL);
	if(handle == DB_FAILURE){
		if(debug_flag){
			printf("open database failure!\n");
		}
		db_shutdown();
		return -1;
	}
    if(mode==MODE_NORMAL)
    	db_table="blacklist";
    else if(mode==MODE_URGENT)
    	db_table="whitelist";
	sprintf(sql, "select * from %s",db_table);
    retValue = db_getfirst(handle, sql);
	if(retValue == DB_FAILURE){
		if(debug_flag){
			printf("excute sql failure!\n");
		}
		db_close(handle);
		db_shutdown();
		return -1;
	}
    while(retValue!=DB_FAILURE){
        l->length++;
        sip=db_get_string(handle,2);
        dip=db_get_string(handle,3);
        l->r[row].ip_version=db_get_int(handle,1);
        convert(sip,dip,row);
        l->r[row].sport_low=db_get_int(handle,4);
        l->r[row].sport_high=db_get_int(handle,5);
        l->r[row].dport_low=db_get_int(handle,6);
        l->r[row].dport_high=db_get_int(handle,7);
        l->r[row].proto=db_get_int(handle,8);
        retValue = db_getnext(handle);
        row++;
    }
	db_close(handle);
	db_shutdown();
	return 1;

}
static int ProcFramePkt(tEthpkt *pkthdr, tEther *pEth){
    int i;
    pkt_id++;
    if(pkt_id==1){
        printf("first packet!\n");
        start1=clock();
    }
    tIp *pIp=NULL;
    tIpv6 *pIpv6=NULL;
    tTcp *pTcp=NULL;
    tUdp *pUdp=NULL;
    pkt->ether_type=ntohs(pEth->proto);
    switch(pkt->ether_type){
        case ETHERTYPE_IP:
        pIp=(tIp *)pEth->data;
        pkt->sip=ntohl(pIp->src);
        pkt->dip=ntohl(pIp->dest);
        pkt->proto=pIp->proto;
        if (pIp->proto==PROTO_TCP){
            pTcp=(tTcp *)pIp->data;
            pkt->sport=ntohs(pTcp->sport);
            pkt->dport=ntohs(pTcp->dport);
        }
        else if(pIp->proto==PROTO_UDP){
            pUdp=(tUdp *)pIp->data;
            pkt->sport=ntohs(pUdp->sport);
            pkt->dport=ntohs(pUdp->dport);
        }
        break;
          
        case ETHERTYPE_IPv6:
        pIpv6=(tIpv6 *)pEth->data;
        for(i=0;i<IPV6_ADDR_LEN;i++){
            pkt->sip_v6[i]=pIpv6->src[i];
            pkt->dip_v6[i]=pIpv6->dest[i];
        }
        pkt->proto=pIpv6->next_head;
        if (pIpv6->next_head==PROTO_TCP){
            pTcp=(tTcp *)pIpv6->data;
            pkt->sport=ntohs(pTcp->sport);
            pkt->dport=ntohs(pTcp->dport);
        }
        else if(pIpv6->next_head==PROTO_UDP){
            pUdp=(tUdp *)pIpv6->data;
            pkt->sport=ntohs(pUdp->sport);
            pkt->dport=ntohs(pUdp->dport);
        }
        break;
    }
    
    switch(mode){
        case MODE_NORMAL:
        method_normal(pkt,pkthdr,l);
        printf("pkt_id=%d\n",pkt_id);
        if(pkt_id==5110){
            end1=clock();
            printf("last packet!\n");
            printf("processing %d packets takes %lf secs\n",pkt_id,(double)(end1-start1)/CLOCKS_PER_SEC);
        }
        break;
     
        case MODE_URGENT:
        method_urgent(pkt,pkthdr,l);
        break;

        default:
         break;
    }
	return 1;
}

int main(){
    pkt=(struct packet *)malloc(sizeof(struct packet));
    l=(struct list *)malloc(sizeof(struct list));
    char ifname1[16],ifname2[16];
    int opt1,opt2;
    l->r=(struct rule*)malloc(1000*sizeof(struct rule*));
    l->length=0;
    lib_init();
    start=clock();
    db_qurry(l,mode);
    end=clock();
    printf("loading %d rules takes %lf secs\n",l->length,(double)(end-start)/CLOCKS_PER_SEC);
	sprintf(ifname1,"eth11");
	sprintf(ifname2,"eth8");
	sockfd1 = open_sock(ifname1,DMA_MODE,DMA_MODE,RECEIVE_MODE,1);
	sockfd2 = open_sock(ifname2,DMA_MODE,DMA_MODE,PEEK_MODE,1);
	if(sockfd1 < 0){
	    printf("open_sock %s failure!\n",ifname1);
		exit(0);
	}
	if(sockfd2 < 0){
		printf("open_sock %s failure!\n",ifname2);
		exit(0);
	}
	set_frame_proc(sockfd1,(RX_PROC)ProcFramePkt);
	opt1 = PACKET_OUT;
	opt2 = PACKET_OUT;
	set_sockopt(sockfd1,SET_IF_INOUT,&opt1);
	set_sockopt(sockfd2,SET_IF_INOUT,&opt2);
	start_proc(sockfd1);
	start_proc(sockfd2);
	while(1)
	{
		sleep(2);
	}
	close_sock(sockfd1);
	close_sock(sockfd2);
	return 1;
}
