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

#define HOST        "localhost"
#define DB_NAME     "test"
#define USER_NAME   "root" 
#define PASSWD      "buptnic"
#define MODE_NORMAL 1
#define MODE_URGENT 0
/////////////////////////////////////
int sockfd1 =-1,sockfd2=-1;
int flag=0,mode=1;
int debug_flag=0;
struct rule{
    UINT4 sip_low;
    UINT4 sip_high;
    UINT4 dip_low; 
    UINT4 dip_high;
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
    UINT4 sip;
    UINT4 dip;
    UINT2 sport;
    UINT2 dport;
    UINT1 proto;
};
struct packet *pkt;
struct list *l;

/////////////////////////////////////

int method_normal(struct packet *pkt,tEthpkt *pkthdr,struct list *l){
	int i=0;
    while(i<l->length){
        if(pkt->sip>=l->r[i].sip_low&&pkt->sip<=l->r[i].sip_high&&pkt->dip>=l->r[i].dip_low&&pkt->dip<=l->r[i].dip_high&&
        	pkt->sport>=l->r[i].sport_low&&pkt->sport<=l->r[i].sport_high&&pkt->dport>=l->r[i].dport_low&&pkt->dport<=l->r[i].dport_high&&
        	pkt->proto==l->r[i].proto){
            return 1;

        }
        i++;
    }
    xmit_packet(sockfd2,pkthdr->pid,pkthdr);
    return 1;


}
int method_urgent(struct packet *pkt,tEthpkt *pkthdr,struct list *l){
	int i=0;
    while(i<l->length){
        if(pkt->sip>=l->r[i].sip_low&&pkt->sip<=l->r[i].sip_high&&pkt->dip>=l->r[i].dip_low&&pkt->dip<=l->r[i].dip_high&&
        	pkt->sport>=l->r[i].sport_low&&pkt->sport<=l->r[i].sport_high&&pkt->dport>=l->r[i].dport_low&&pkt->dport<=l->r[i].dport_high&&
        	pkt->proto==l->r[i].proto){
        	xmit_packet(sockfd2,pkthdr->pid,pkthdr);
            return 1;

        }
        i++;
    }
    return 1;
}
void convert(char *ip, UINT4 *ip_low,UINT4 *ip_high){
    int d1=0,d2=0,d3=0,d4=0,d5=0,i;
    UINT4 mask=0;	
    char *p1,*p2,*p3,*p4,*cursor;
    *ip_low=0;
    *ip_high=0;
    p1=strchr(ip,'.');
    p2=strchr((p1+1),'.');
    p3=strchr((p2+1),'.');
    p4=strchr(ip,'/');
    cursor=ip;
    while(*cursor!='\0'){
      if(cursor>=ip && cursor<p1){
        d1+=pow(10,(float)(p1-cursor-1))*((*cursor)-'0');
      } 
      else if(cursor>p1 && cursor<p2){
        d2+=pow(10,(float)(p2-cursor-1))*((*cursor)-'0');
      }
      else if(cursor>p2 && cursor<p3){
        d3+=pow(10,(float)(p3-cursor-1))*((*cursor)-'0');
      } 
      else if(cursor>p3 && cursor<p4){
        d4+=pow(10,(float)(p4-cursor-1))*((*cursor)-'0');
      }
      else if(cursor>p4){
        d5+=pow(10,(float)(strlen(ip)-(cursor-ip+1)))*(*cursor-'0'); 
      }
      cursor++;
    }
    for(i=1;i<=d5;i++){
      mask+=1<<(32-i);
    }
    printf("d1=%d,d2=%d,d3=%d,d4=%d,d5=%d\n",d1,d2,d3,d4,d5);
    printf("mask=%u\n",mask);
    *ip_low=((d1<<24)+(d2<<16)+(d3<<8)+d4)&mask;
    printf("ip_low=%u\n",*ip_low);
    *ip_high=*ip_low+(1<<(32-d5))-1;
    printf("ip_high=%u\n",*ip_high);
   
}
int db_qurry(struct list *l,int mode){
	int handle;
	int retValue;
	int row=0;
    UINT4 sip_low,sip_high;
	UINT4 dip_low,dip_high;
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
        sip=db_get_string(handle,1);
        dip=db_get_string(handle,2);
        convert(sip,&sip_low,&sip_high);
        convert(dip,&dip_low,&dip_high);
        l->r[row].sip_low=sip_low;
        l->r[row].sip_high=sip_high;
        l->r[row].dip_low=dip_low;
        l->r[row].dip_high=dip_high;
        l->r[row].sport_low=db_get_int(handle,3);
        l->r[row].sport_high=db_get_int(handle,4);
        l->r[row].dport_low=db_get_int(handle,5);
        l->r[row].dport_high=db_get_int(handle,6);
        l->r[row].proto=db_get_int(handle,7);
        retValue = db_getnext(handle);
        row++;
    }
	db_close(handle);
	db_shutdown();

	return 1;

}
static int ProcFramePkt(tEthpkt *pkthdr, tEther *pEth){
	tIp *pIp;
	tTcp *pTcp;
	pIp  = (tIp *)pEth->data;
	pTcp = (tTcp *)pIp->data;
	pkt->sip=pIp->src;
	pkt->dip=pIp->dest;
	pkt->proto=pIp->proto;
	pkt->sport=pTcp->sport;
	pkt->dport=pTcp->dport;
    
    switch(mode){

     case MODE_NORMAL:
     method_normal(pkt,pkthdr,l);
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
    int opt,count;
    l->r=(struct rule*)malloc(1000*sizeof(struct rule*));
    l->length=0;
    lib_init();
    db_qurry(l,mode);
	sprintf(ifname1,"eth8");
	sprintf(ifname2,"eth2");
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
	opt = PACKET_OUT;
	set_sockopt(sockfd1,SET_IF_INOUT,&opt);
	set_sockopt(sockfd2,SET_IF_INOUT,&opt);
	start_proc(sockfd1);
	count = 30;
	while(count--)
	{
		sleep(1);
	}
	close_sock(sockfd1);
	close_sock(sockfd2);
	return 1;
}
