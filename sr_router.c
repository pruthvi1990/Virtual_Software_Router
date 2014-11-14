/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 * 90904102
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <inttypes.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"

// Structures for ARP_Cache
struct arp_cache{
	uint32_t  arpc_ip_addr;
	unsigned char arpc_mac_addr[ETHER_ADDR_LEN];
	struct arp_cache *clink;
	time_t arpc_timeout;
};

struct arp_nodes{
	struct arp_cache *first;
	struct arp_cache *last;
};
//END

// Structures for ARP_Queue
struct packetq{
	uint8_t *packet;
	unsigned len;
	char icmp_ifname[sr_IFACE_NAMELEN];
	struct packetq *next;
};

struct ptr_pack{
	struct packetq *first;
	struct packetq *last;
};

struct queue{
	uint32_t arpq_ip_addr;
	struct sr_if *arpq_if_name;
	struct ptr_pack arpq_packets;
	time_t arpq_lastreq;
	uint8_t arpq_numreqs;
	struct queue *next;
	struct queue *prev;
};

struct queue_nodes{
	struct queue *first;
	struct queue *last;
};
//END

//ICMP
struct icmp_hdr{
	uint8_t icmp_type;
	uint8_t icmp_code;
	uint16_t icmp_checksum;
	uint32_t icmp_data;
}__attribute__((packed));

struct icmp_echoreply_hdr{
	uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_checksum;
	uint16_t icmp_id;
	uint16_t icmp_seq;
}__attribute__((packed));

//END

static struct arp_nodes sr_arpcache = {0,0};
static struct queue_nodes sr_arp_queue = {0,0};

static void arpreq_ethrnet_hdr_packet_fill(struct sr_ethernet_hdr *ethr_adr, uint8_t *src_mac_addr);
static int send_arp_packet (struct queue *ent, struct sr_if *arp_if, struct sr_instance *arp_instance, uint32_t destn_ip);
static void arp_request_packet_fill(struct sr_arphdr* arp_hdr, char* mac_addr, uint32_t source_ip, uint32_t destn_ip );

static void print_ip (uint32_t *ip)
{
	uint8_t *ip_8bits = (uint8_t*) ip;
	int i;

	for (i=0; i<=3 ; i++)
	{
		printf("%u.", ip_8bits[i]);

	}
	
}

//print the number of packets for the particular IP link

static void print_numpkts(struct queue *ip_queue)
{

	struct ptr_pack numpackets = ip_queue->arpq_packets;
	int count =0;
	
	while ((numpackets.first)->next == 0)
	{
		count++;	
	}
	
	printf("The number of packets for the particular IP link is %d\n", count);
}



static void arpreq_ethrnet_hdr_packet_fill(struct sr_ethernet_hdr *ethr_adr, uint8_t *src_mac_addr)
{
	assert(ethr_adr);
	int i;
	//printf("I think i figure out the problem\n");
	//memcpy(ethr_adr->ether_dhost ,arp_broadcast_IP, ETHER_ADDR_LEN);
	for (i=0; i<ETHER_ADDR_LEN;i++)
	{
		ethr_adr->ether_dhost[i] =arp_broadcast_IP; 
	}
	memcpy(ethr_adr->ether_shost ,src_mac_addr, ETHER_ADDR_LEN);
	ethr_adr->ether_type = htons(ETHERTYPE_ARP);
}

/*To find whether the packet is for Interface IP */

static struct sr_if*  check_inteface_for_destnIP(struct sr_instance *sr, uint32_t targetIP )
{
	assert(sr);
	assert(targetIP);

	struct sr_if *currnt_if = sr->if_list;
	
	while (currnt_if && targetIP != currnt_if->ip)
	{
//		printf("this is exec..\n");
		currnt_if = currnt_if->next;
	}
		
	if (currnt_if)
	{
		return currnt_if;
	}
	return 0;	
}

/* Send the ARP packet */
static int send_arp_packet (struct queue *ent, struct sr_if *arp_if, struct sr_instance *arp_instance, uint32_t destn_ip)
{
    unsigned  len;
    uint8_t *packet_buf;

    len = sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr );
    packet_buf = (uint8_t*)malloc(len);

        if (packet_buf)
         {
             //printf("I am in sendd_arp_packet \n");
	     arp_request_packet_fill((struct sr_arphdr*)(packet_buf + sizeof(struct sr_ethernet_hdr)), arp_if->addr, arp_if->ip,destn_ip);
            // getchar();
	     arpreq_ethrnet_hdr_packet_fill((struct sr_ethernet_hdr*)packet_buf, arp_if->addr);
	    //  printf("I am passed here in ether filling\n");
	     time(&ent->arpq_lastreq); 
	     ent->arpq_numreqs +=1;
	     //printf("Number of ARP request sent is %d\n", ent->arpq_numreqs);
	     return sr_send_packet(arp_instance, packet_buf,len,arp_if->name);
			
         }
        else
         {
            printf("Error: failed to allocate memory\n");
	    exit(-1);
         }

}

//Search ARP cache for a given ip address
static struct arp_cache *arp_cache_search(struct arp_cache *src,uint32_t ip){
	while(src){
		if(ip==src->arpc_ip_addr)
			return src;
		src=src->clink;
	}
	return 0;
}

//Fill cache with new entries
static struct arp_cache *arp_cache_entry(struct arp_nodes *arc,uint32_t ip,unsigned char *mac_addr){
	assert(arc);
	assert(mac_addr);
	time_t tm;

	struct arp_cache *new_node;
	if(new_node=(struct arp_cache*) malloc(sizeof(struct arp_cache))){
		new_node->arpc_ip_addr=ip;
		memcpy(new_node->arpc_mac_addr,mac_addr,ETHER_ADDR_LEN);
		new_node->clink=NULL;
		new_node->arpc_timeout=time(&tm)+ARPC_TIMEOUT;
		if(arc->first)
			arc->last->clink=new_node;
		else
			arc->first=new_node;
		arc->last=new_node;
	}
	return new_node;
}

//Update ARP cache
static void arp_update(struct arp_cache *update,unsigned char *mac_addr){
	time_t tm;
	assert(update);
	assert(mac_addr);
	memcpy(update->arpc_mac_addr,mac_addr,ETHER_ADDR_LEN);
	update->arpc_timeout=time(&tm)+ARPC_TIMEOUT;
}

//Clear timed out cache entries
static void arp_clear_cache(struct arp_nodes *ptr){
	assert(ptr);
	struct arp_cache *curr = ptr->first;
	struct arp_cache *prev = NULL;
	struct arp_cache *temp = 0;
	time_t tm;
	while(curr){
		if(time(&tm) >= curr->arpc_timeout){
			if(prev==NULL){
				curr=curr->clink;
				free(ptr->first);
			}
			else {
				prev->clink=curr->clink;
				free(curr);
				curr=prev->clink;
			}
		}
		else {
			prev=curr;
			curr=curr->clink;
		}
	}
}

//Add new packet to ARP queue of packets of particular IP
static struct packetq *add_packet_queue(struct queue *arp,uint8_t *packet,unsigned packet_len,char *if_name){
	assert(packet);
	assert(arp);
	assert(if_name);
	struct packetq *new_packet;
	if(new_packet=(struct packetq*)malloc(sizeof(struct packetq))){
		new_packet->packet=(uint8_t*) malloc(packet_len);
		new_packet->len=packet_len;
		memcpy(new_packet->icmp_ifname, if_name, sr_IFACE_NAMELEN);
		memcpy(new_packet->packet,packet,packet_len);

	//	DebugMAC(((struct sr_ethernet_hdr*)new_packet)->ether_shost);

		new_packet->next=0;
//		printf("Its working fine till here \n");
		if ((arp->arpq_packets).first)
		{
			//printf("New Packet is getting added\n");
			((arp->arpq_packets).last)->next=new_packet;
		}
		else
		{
			(arp->arpq_packets).first=new_packet;
			//printf("Ufff, finally packet in qu \n");
		}
		(arp->arpq_packets).last=new_packet;
		//printf("I am ARP queue , your packet size is %u \n", new_packet->packet);
	}
	return new_packet;
}

//Add new queue entry i.e.,new IP to the list
static struct queue *add_queue_entry(struct queue_nodes *add,uint32_t ip_addr,struct sr_if *int_face, char *interface, uint8_t *packet,unsigned len){
    assert(add);
    assert(int_face);
    assert(packet);
    struct queue *new_entry;
//    printf ("I am @ the entry\n");
//    DebugMAC(int_face->addr );
    if(new_entry=(struct queue*) malloc(sizeof(struct queue))){
        new_entry->arpq_ip_addr=ip_addr;
        new_entry->arpq_if_name=int_face;
        (new_entry->arpq_packets).first=(new_entry->arpq_packets).last=0;
        if(add_packet_queue(new_entry,packet,len,interface)){
          printf("I am arp_queue_entry, I am executing always for the same IP\n");
	    new_entry->arpq_numreqs=1;
            new_entry->next=0;
            new_entry->prev=add->last;
            if(add->first)
                add->last->next=new_entry;
            else
                add->first=new_entry;
            add->last=new_entry;
            return new_entry;
        }
    }
    return 0;
}

//Clean ARP queue with 5 or more entries with last req over a minute ago
static void arp_clear_queue(struct sr_instance*sr,struct queue_nodes *entry){
    assert(entry);
    struct queue *curr=entry->first;
    struct queue *temp=0;
    time_t now;

    while(curr){
        temp=0;
        if(time(&now)-1 > curr->arpq_lastreq){
            if(curr->arpq_numreqs >= ARPQ_MAXREQ)
                temp=curr;
            else if(send_arp_packet(curr, curr->arpq_if_name,sr,curr->arpq_ip_addr)){
                fprintf(stderr,"ARP Request Send failed!!\n");
            }
            }
            curr=curr->next;
            if(temp){
                if(temp->prev)
                    temp->prev->next=temp->next;
                else
                    entry->first=temp->next;
                if(temp->next)
                    temp->next->prev=temp->prev;
                else
                    entry->last=temp->prev;
                free(temp);
                temp=0;
            }
        }
}

//Search ARP queue for queue of ARP requests for a given IP
static struct queue *arp_queue_search(struct queue *src,uint32_t ip){
	while(src){
		if(ip==src->arpq_ip_addr)
			return src;
		src=src->next;
	}
	return 0;
}



/* Fill the ARP Packets for Request*/
static void arp_request_packet_fill(struct sr_arphdr* arp_hdr, char* mac_addr, uint32_t source_ip, uint32_t destn_ip )
{

    arp_hdr ->ar_hln = 6;
    arp_hdr ->ar_hrd = htons(1);
    arp_hdr ->ar_op  = htons(ARP_REQUEST);
    arp_hdr ->ar_pln = 4;
    arp_hdr ->ar_pro = htons(ETHERTYPE_IP);
    memcpy(arp_hdr ->ar_sha, mac_addr, ETHER_ADDR_LEN);
    arp_hdr ->ar_sip = source_ip;
    memset(arp_hdr ->ar_tha, 0, ETHER_ADDR_LEN);
    arp_hdr ->ar_tip = destn_ip;
}

//Fill ARP packet
static void arp_reply_packet_fill(struct sr_ethernet_hdr *ethdr, struct sr_arphdr *arphdr, struct sr_if *sr_intr )
{

	memcpy(ethdr->ether_dhost, ethdr->ether_shost, ETHER_ADDR_LEN);
	memcpy(ethdr->ether_shost, sr_intr->addr,ETHER_ADDR_LEN);
	memcpy(arphdr->ar_tha, arphdr->ar_sha,ETHER_ADDR_LEN);
	memcpy(arphdr->ar_sha, sr_intr->addr, ETHER_ADDR_LEN);
	arphdr->ar_op= htons(ARP_REPLY);
	arphdr->ar_hln= 6;
	arphdr->ar_pln= 4;
	arphdr->ar_tip= arphdr->ar_sip;
	arphdr->ar_sip=sr_intr->ip;

//	printf("Debug: \n");
//	DebugMAC(sr_intr->addr);
//	getchar();
}

//checksum computation
static uint16_t compute_checksum(uint16_t *data,size_t len){
	assert(data);
	uint32_t sum=0;
	size_t len_16=len/2;  //len is in terms of bytes=8 bits; converting into 16 bits
	while(len_16--)
		sum+=*data++;
	if(len%2)
		sum+=*((uint8_t*)data);
	while(sum>>16)
		sum=(sum & 0xffff) + (sum >> 16); //make 17th bit to 0 and add carry(17th bit)
	return((uint16_t) ~sum);
}
//swap source and destination ethernet addresses
static void swap_ether_addr(struct sr_ethernet_hdr *hdr){
	assert(hdr);
	uint8_t temp[ETHER_ADDR_LEN];
	memcpy(temp,hdr->ether_shost,ETHER_ADDR_LEN);
	memcpy(hdr->ether_shost,hdr->ether_dhost,ETHER_ADDR_LEN);
	memcpy(hdr->ether_dhost,temp,ETHER_ADDR_LEN);
}

//Form ICMP echo reply keeping few parameters same as echo request
static void fill_icmp_echoreply(uint8_t *packet,size_t icmp_len){
	assert(packet);
	swap_ether_addr((struct sr_ethernet_hdr*) packet);

	struct ip *iphdr=(struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
	struct in_addr temp=iphdr->ip_src;
	iphdr->ip_src=iphdr->ip_dst;
	iphdr->ip_dst=temp;

	struct icmp_echoreply_hdr *icmphdr=(struct icmphdr*)(packet + sizeof(struct sr_ethernet_hdr) + iphdr->ip_hl*4);
	icmphdr->icmp_type=0;
	icmphdr->icmp_checksum=0;
	icmphdr->icmp_checksum= compute_checksum((uint16_t*)icmphdr,icmp_len);
	iphdr->ip_sum=0;
	iphdr->ip_sum= compute_checksum((uint16_t*)iphdr,iphdr->ip_hl*4);
}



//Upon ARP reply, send the queued packets to dest address
static void send_pkt_after_arpreply(struct sr_instance *sr,struct queue_nodes *que,struct queue *q_entry,unsigned char *dha){
	assert(que);
	assert(q_entry);
	assert(dha);

	struct packetq *pq;
	while(pq=(q_entry->arpq_packets).first){

		memcpy(((struct sr_ethernet_hdr*)(pq->packet))->ether_shost,q_entry->arpq_if_name->addr,ETHER_ADDR_LEN);
	//	printf("I coiped mac addres for shost\n");
		memcpy(((struct sr_ethernet_hdr*)(pq->packet))->ether_dhost,dha,ETHER_ADDR_LEN);	
		struct ip* ip_ptr= (struct ip*)((pq->packet) + sizeof(struct sr_ethernet_hdr));
	//	printf("I oppied everything to sent to the server\n");

		ip_ptr->ip_sum=0;
		ip_ptr->ip_sum= compute_checksum((uint16_t*) ip_ptr,ip_ptr->ip_hl * 4);
		if(sr_send_packet(sr,pq->packet,pq->len,q_entry->arpq_if_name->name))
			printf("Send packet from ARP queue failed\n");
		if(!((q_entry->arpq_packets).first = pq->next))
			(q_entry->arpq_packets).last=0;
		free(pq);
	}
	if(q_entry->prev)
		q_entry->prev->next=q_entry->next;
	else
		que->first=q_entry->next;
	if(q_entry->next)
                q_entry->next->prev=q_entry->prev;
        else
                que->last=q_entry->prev;
	free(q_entry);
}

//Fill few predetermined values in IP packets when destination host unreachable and time exceeded messages
static void icmp_prefill(struct ip *iphdr,struct icmp_hdr *icmphdr,uint8_t type,uint8_t code){
	assert(iphdr);
	iphdr->ip_v=4;
	iphdr->ip_hl=5;
	iphdr->ip_tos=0;
	iphdr->ip_id=0;
	iphdr->ip_off=0;
	iphdr->ip_ttl=64;
	iphdr->ip_p=IPPROTO_ICMP;

	assert(icmphdr);
	icmphdr->icmp_type=type;
	icmphdr->icmp_code=code;
	icmphdr->icmp_data=0;
}

//Fill specific fields to fill ICMP sending packet
static void icmp_specfill(struct ip *iphdr,struct icmp_hdr *icmphdr,uint32_t sip,uint32_t dip,uint8_t *icmp_data,size_t icmp_data_len){
	assert(iphdr);
	assert(icmphdr);
	assert(icmp_data);

	iphdr->ip_len=htons(iphdr->ip_hl*4 + ICMP_HDR_LEN+ icmp_data_len);
	(iphdr->ip_src).s_addr=sip;
	(iphdr->ip_dst).s_addr=dip;
	iphdr->ip_sum=0;
	iphdr->ip_sum=compute_checksum((uint16_t*)iphdr,iphdr->ip_hl*4);
	memcpy(icmphdr+1,icmp_data,icmp_data_len);
	icmphdr->icmp_checksum=compute_checksum((uint16_t*)icmphdr,ICMP_HDR_LEN+icmp_data_len);
}

//Allocate memory to whole ICMP packet and re-initialize pointers
static void icmp_ip_ether_fill(unsigned old_len, unsigned *len_ptr,uint8_t **packet_ptr,struct ethernet_hdr **ether_ptr,struct ip **ip_ptr,struct icmp_hdr **icmp_ptr){
	assert(len_ptr);
	assert(packet_ptr);
	*len_ptr= sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + ICMP_HDR_LEN + old_len + ICMP_DATA_LEN;
	if(*packet_ptr = (uint8_t*) malloc(*len_ptr)){
		*ether_ptr=(struct sr_ethernet_hdr*) *packet_ptr;
		*ip_ptr=(struct ip*) (*packet_ptr + sizeof(struct sr_ethernet_hdr));
		*icmp_ptr=(struct icmp_hdr*)(*packet_ptr + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip));
	}
	else {
		printf("Malloc failed");
		exit(-1);
	}
}

//To send ICMP packet for destination unreachable or time-exceeded packet
static void send_icmp_packet(struct sr_instance *sr,struct sr_ethernet_hdr *ether_hdr,struct ip *ip_hdr,struct icmp_hdr *icmphdr, uint8_t *dha, char *ifname, uint32_t dip,uint8_t *icmp_data,size_t icmp_data_len, unsigned total_len){
	assert(ether_hdr);	
	assert(ip_hdr);
	assert(dha);
	struct sr_if *send_if_list = sr_get_interface(sr,ifname);
	memcpy(ether_hdr->ether_dhost, dha, ETHER_ADDR_LEN);
	memcpy(ether_hdr->ether_shost, send_if_list->addr, ETHER_ADDR_LEN);
	icmp_specfill(ip_hdr,icmphdr, send_if_list->ip, dip, icmp_data, icmp_data_len);
	if(sr_send_packet(sr,(uint8_t*) ether_hdr, total_len, ifname)){
		printf("Error sending ICMP host unreachable");
	}
}

static void send_icmp_from_arpq(struct sr_instance *sr,struct ptr_pack *pq){
	assert(pq);
	unsigned int packet_len;
	struct ip *ip_hdr;
	struct sr_ethernet_hdr *eth_hdr;
	struct icmp_hdr *icmp_hdr;
	uint8_t *packet_ptr;
	unsigned int prev_iphl, iphdr_bytelen;

	icmp_ip_ether_fill(sizeof(struct ip), &packet_len,&packet_ptr,&eth_hdr,&ip_hdr,&icmp_hdr);
	icmp_prefill(ip_hdr,icmp_hdr,ICMP_UNREACH,ICMP_HOST_UNREACH);
	icmp_hdr->icmp_data=0;
	eth_hdr->ether_type=htons(ETHERTYPE_IP);
	struct packetq *curr;
	while(curr = pq->first){
		struct ip *ip_ptr=(struct ip*)(curr->packet+sizeof(struct sr_ethernet_hdr));
		iphdr_bytelen = ip_ptr->ip_hl * 4;
		prev_iphl = sizeof(struct ip);
		if(ip_ptr->ip_p=IPPROTO_ICMP){
			struct icmp_hdr *icmp_ptr=(struct icmp_hdr*)(curr->packet+sizeof(struct sr_ethernet_hdr)+iphdr_bytelen);
			if(icmp_ptr->icmp_type == ICMP_UNREACH || icmp_ptr->icmp_type == ICMP_TTL)
				return;
		}
		unsigned int diff;
		if(iphdr_bytelen != prev_iphl){
			diff = iphdr_bytelen - prev_iphl;
			packet_len += diff;
			prev_iphl=iphdr_bytelen;
			if(!realloc(packet_ptr,packet_len)){
				printf("Realloc failed");
				exit(-1);
			}
		}
		send_icmp_packet(sr,eth_hdr,ip_hdr,icmp_hdr, ((struct sr_ethernet_hdr*)(curr->packet))->ether_shost, curr->icmp_ifname, (ip_ptr->ip_src).s_addr,(uint8_t*) ip_ptr,iphdr_bytelen+ICMP_DATA_LEN,packet_len);
		if(!(pq->first = curr->next))
			pq->last=0;
		free(curr);
	}
	free(packet_ptr);
}

static struct sr_rt* rt_find_best_match( struct sr_instance *sr, uint8_t *dest_ip )

{
	struct sr_rt *bestmatch=0, *curr, *default_prefix=0;
	uint8_t count=0, mismatch=0, longest_match=0, match_byte=0;
	uint8_t *mask_byte, *rt_dest_addr_byte, *dest_ipaddr; 
	
//	printf("This works fine \n");
	
	for (curr = sr->routing_table; curr; curr= curr->next )	
	{
		if (!default_prefix){
			if ((curr->dest).s_addr == 0)
				default_prefix = curr;
			}
		
		dest_ipaddr = dest_ip;
		rt_dest_addr_byte = (uint8_t*)&((curr->dest).s_addr);
		mask_byte =(uint8_t*) &((curr->mask).s_addr);
		
		for ( ; dest_ipaddr < dest_ip + 4 ; ++dest_ipaddr, ++mask_byte, ++rt_dest_addr_byte)
		{
			if (!( match_byte = (*dest_ipaddr) & (*mask_byte)))
				break;			   
			if (match_byte != *rt_dest_addr_byte){
			    mismatch =1;
			    break;
			   }
			count +=1;
		}

		if (mismatch)
			mismatch =0;

		else if  (count > longest_match)
		{
			longest_match = count;
			bestmatch = curr;
		}
		count =0; 
	}
	
	if (bestmatch)
	{
		return bestmatch;
	}
	else
	{
		return default_prefix;
	}
}

	
/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
void sr_init(struct sr_instance* sr)
{
	    /* REQUIRES */
	        assert(sr);

		    /* Add initialization code here! */

} /* -- sr_init -- */

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);
   
    printf("*** -> Received packet of length %d \n",len);

	
	uint16_t packet_type = ntohs (((struct sr_ethernet_hdr *) packet ) -> ether_type);
	
	if(packet_type==ETHERTYPE_ARP)
	{

				struct sr_arphdr *arp_hdr = (struct sr_arphdr*) (packet + sizeof(struct sr_ethernet_hdr));
	
				struct sr_if *target_interface;
				struct arp_cache *arp_node_info;

				if (arp_node_info =arp_cache_search(sr_arpcache.first, arp_hdr->ar_sip))
					{
						//printf("I am in the ARP cache");
						arp_update(arp_node_info, arp_hdr->ar_sha);
					}
				else
					{

						if(target_interface = check_inteface_for_destnIP(sr,arp_hdr->ar_tip))
						{
								//	printf("I found the interface node \n");
									if(arp_cache_entry(&sr_arpcache, arp_hdr->ar_sip, arp_hdr->ar_sha))
									{
										//	printf("I added the mac to cache\n");
											struct queue *pq;
											if(pq = arp_queue_search(sr_arp_queue.first,arp_hdr->ar_sip))
											{
											//	printf("I found the source IP\n");
												//DebugMAC(((struct sr_ethernet_hdr*)(pq->arpq_packets).first->packet)->ether_shost);
												//getchar();
												send_pkt_after_arpreply(sr,&sr_arp_queue,pq,arp_hdr->ar_sha);
											//	printf("I sent the packet successfully, hurray!!!!\n");
											}
									}
									else
											printf("Error adding new entry to ARP cache");

		
						}
					}
				
				if(target_interface = check_inteface_for_destnIP(sr,arp_hdr->ar_tip))
				{
					if (htons(arp_hdr->ar_op)== ARP_REQUEST)
					{
						 arp_reply_packet_fill((struct sr_ethernet_hdr*)packet, arp_hdr, target_interface );
						 sr_send_packet(sr,packet, len,interface);
					}
				}
				
	}
				
	else if(packet_type==ETHERTYPE_IP){
	struct ip *ip_packet=(struct ip*)(packet+sizeof(struct sr_ethernet_hdr));
	uint16_t received_sum=ip_packet->ip_sum;
 	ip_packet->ip_sum=0;
	if(compute_checksum((uint16_t*)ip_packet,ip_packet->ip_hl * 4)!= received_sum){
        	printf("IP checksum failed,packet dropped");
                return;
        }

	if((ip_packet->ip_ttl -= 1) == 0){
		if(ip_packet->ip_p==IPPROTO_ICMP){
			struct icmp_hdr *icmphdr=(struct icmp_hdr*)(packet+sizeof(struct sr_ethernet_hdr) + ip_packet->ip_hl*4);
		if(icmphdr->icmp_type == ICMP_UNREACH || icmphdr->icmp_type == ICMP_TTL)
			return;
		}
	//	printf("I am ICMP with TTL 0\n");
		unsigned int packet_len;
		uint8_t *packet_ptr;
		struct sr_ethernet_hdr *ether_ptr;
		struct ip *ip_ptr;
		struct icmp_hdr *icmp_ptr;
	 	icmp_ip_ether_fill(ip_packet->ip_hl * 4,&packet_len,&packet_ptr,&ether_ptr,&ip_ptr,&icmp_ptr);
		ether_ptr->ether_type = htons(ETHERTYPE_IP);
		ip_packet->ip_ttl += 1;
		icmp_prefill(ip_ptr,icmp_ptr,ICMP_TTL,0);
		send_icmp_packet(sr,ether_ptr,ip_ptr,icmp_ptr,((struct sr_ethernet_hdr*) packet)->ether_shost, interface, (ip_packet->ip_src).s_addr,(uint8_t*) ip_packet,ip_packet->ip_hl * 4 + ICMP_DATA_LEN,packet_len);	
		free(packet_ptr);
		return;
	}	

	if (check_inteface_for_destnIP(sr,(ip_packet->ip_dst).s_addr)) 
	{
		//print_ip (&(ip_packet->ip_dst).s_addr);
		if (ip_packet->ip_p == IPPROTO_ICMP) {
			//printf("I am ICMP \n");
			struct icmp_hdr *icmp_packet = (struct icmp_hdr*) (packet + sizeof(struct sr_ethernet_hdr) + ip_packet->ip_hl * 4 );
			if(icmp_packet->icmp_type==ICMP_ECHO_REQ)
			{
				uint16_t received_sum=icmp_packet->icmp_checksum;
				icmp_packet->icmp_checksum=0;
				if(compute_checksum((uint16_t*)icmp_packet,ntohs(ip_packet->ip_len)-(ip_packet->ip_hl * 4))!= received_sum)
				{
					printf("ICMP checksum failed,packet dropped");
					return;
				}
				fill_icmp_echoreply(packet,ntohs(ip_packet->ip_len)-(ip_packet->ip_hl * 4));
				if(sr_send_packet(sr,packet, len,interface))
					printf("Packet send failed");
			}
		}
	
		else if ((ip_packet->ip_p == TCP) || (ip_packet->ip_p == UDP))
			{
                                //printf("I am the UDP packet\n");
				unsigned send_pkt_len = sizeof(struct ip) + sizeof(struct sr_ethernet_hdr) + ICMP_HDR_LEN + ICMP_DATA_LEN + (ip_packet->ip_hl *4) ;  
				uint8_t *send_pkt = (uint8_t *) malloc (send_pkt_len);

				struct ip *send_ip_hdr = (struct ip *) (send_pkt + sizeof(struct sr_ethernet_hdr));
				struct icmp_hdr *send_icmp_hdr = (struct icmp_hdr*) (send_ip_hdr +1);
				ip_packet->ip_ttl +=1;
				icmp_prefill (send_ip_hdr,send_icmp_hdr,ICMP_UNREACH, ICMP_PORT_UNREACH);
				icmp_specfill (send_ip_hdr, send_icmp_hdr, (ip_packet->ip_dst).s_addr,(ip_packet->ip_src).s_addr, (uint8_t*)ip_packet, (( ip_packet->ip_hl *4)+ ICMP_DATA_LEN ));
			
				memcpy(send_pkt, packet,  sizeof(struct sr_ethernet_hdr));
				swap_ether_addr ((struct sr_ethernet_hdr*)send_pkt);

				//printf("I am almost their\n");
				if (sr_send_packet(sr, send_pkt, send_pkt_len, interface))
				{
					printf("Error sending the packet, on response of receiving the packet on interface %s",interface);
					
				}
			}	
			
		}
	
		else 
		{		//  if the packet has the IP which is not destined for interface, lookup rtable and send pkt to next hop     	
				
				uint32_t destn_ip = (ip_packet->ip_dst).s_addr;
				struct sr_rt *nexthop_rt= rt_find_best_match(sr, (uint8_t *)&destn_ip);
				uint32_t nexthop =(nexthop_rt->gw).s_addr;

				if ( nexthop == 0)
				{
					nexthop=(ip_packet->ip_dst).s_addr;
				}
				//print_ip (&nexthop);
				
				//printf("Hi i am for the IP which is not for router\n");
				
				struct sr_if *src_interface;
				
				// Search for interface node corrosponding to the one in routing table 
				if (!(src_interface = sr_get_interface(sr, nexthop_rt->interface))) 
				{ 
					printf("Error: Failed to find the router interface node %s\n", nexthop_rt->interface );
				}
				
				struct arp_cache *arp_cache_node = arp_cache_search(sr_arpcache.first,nexthop);
				unsigned char *gateway_mac_addr = arp_cache_node->arpc_mac_addr;
			
				if (arp_cache_node) // if the MAC found in cache, send the packet or else genretae ARP request
				{
				//	getchar();
					memcpy(((struct sr_ethernet_hdr*)packet)->ether_shost,src_interface->addr, ETHER_ADDR_LEN);
					memcpy(((struct sr_ethernet_hdr*)packet)->ether_dhost,gateway_mac_addr , ETHER_ADDR_LEN);
			//	 	getchar();		
					ip_packet->ip_sum = compute_checksum((uint16_t*)ip_packet, (ip_packet->ip_hl *4) );
					if (sr_send_packet(sr, packet,len, src_interface->name))
					{
					printf("Error : packet forwarding failed\n");
					}		

				}
				

				else   // if the MAC is not found in the cache, send the ARP request to get the gateway MAC address 
				{
							struct queue *queued_pkt;
							if ( queued_pkt = arp_queue_search(sr_arp_queue.first ,nexthop))
							{

						//	printf("Hi, I got the packet\n");
							time_t current_time;
							
								if (time(&current_time)-1 > queued_pkt->arpq_lastreq)						
								{
									if (queued_pkt->arpq_numreqs > ARPQ_MAXREQ)
									{
										send_icmp_from_arpq (sr, &queued_pkt->arpq_packets);
										free(queued_pkt);
									}
								
									else if (send_arp_packet(queued_pkt, queued_pkt->arpq_if_name, sr, nexthop) )
									{
										printf("Error: Sending ARP Request failed for the queued packet \n");
									}
								}
						
								assert ((queued_pkt->arpq_packets).first);
						//		print_numpkts(queued_pkt);
								
								if (!add_packet_queue(queued_pkt, packet, len, interface));
								{
								print_numpkts(queued_pkt);
								print_ip (&queued_pkt->arpq_ip_addr);
								printf("Error: Failed to add new ARP packet to the queue \n");
								}
							
							}
				
				else 
				 {	
					if  (queued_pkt = add_queue_entry(&sr_arp_queue, nexthop, src_interface, interface, packet, len ))
				 	{
						assert(queued_pkt);
						if (send_arp_packet(queued_pkt, src_interface, sr, nexthop))   // check this function
							{
								printf("Error: Sending ARP request failed for the newly added ARP packet\n");
							}
				 	}
					else
					{
					printf("Error: Adding new IP packet to the queue failed \n");	
					}
				
				}
				
			}	
		} 
    }				


} // end sr_ForwardPacket 


/*---------------------------------------------------------------------
 * Method:
 *
 *---------------------------------------------------------------------*/


