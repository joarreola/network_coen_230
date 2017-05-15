/*
    Simple udp server
*/

#include<stdio.h> //printf
#include<string.h> //memset
#include<stdlib.h> //exit(0);
#include<arpa/inet.h>
#include<sys/socket.h>
 
#define BUFLEN 264  //Max length of buffer was 512
#define ACKBUFLEN 7
#define REJECTBUFLEN 10
#define PORT 8888   //The port on which to listen for incoming data
 
void die(char *s)
{
    perror(s);
    exit(1);
}

/*
 * Check packet structure
 *      start id:       0xFFFF
 *      client id:      0x0a    // for example
 *      Pkt types:
 *          DATA:       0xFFF1
 *          ACK:        0xFFF2
 *          REJECT:     0xFFF3
 *      For DATA Type:
 *          sent segment:   0x01    // ex: for 1st segment
 *          data length:    0xFF    // for 255 data bytes
 *          payload:        0xFF bytes // using "da" for data
 *      For ACK Type:
 *          rcvd segment:   0x01    // ex: for 1st segment
 *      For REJECT Type:
 *          Reject subcode: 
 *              out of sequence:    0xFFF4
 *              length misatch:     0xFFF5
 *              end id missing:     0xFFF6
 *              duplicate packet:   0xFFF7
 *          rcvd segment:   0X01    // ex: for 1st segment
 *      end id:         0xFFFF
 */
static int check_packet(char buf[], char resp_buf[]) {
    int data_packet = 0;
    int length;
    int start = 0;
    int i = 0;
    int reject_code = 0x00;

    //for (i=0; i < BUFLEN; i++) {
    //        printf((i<start)?"   ":"%02x%c", (unsigned char)buf[i],((i+1)&15)?' ':'\n');
    //}

    // check header: start[0-1], client[2], type[3-4]
    if ((unsigned char)buf[0] != 0xff && (unsigned char)buf[1] != 0xff) {
        printf("Start of packet ID not 0xffff: buf[0]: %02x  buf[1]: %02x\n",
            (unsigned char)buf[0], (unsigned char)buf[1]);
        data_packet= 1;
    }
    if ((unsigned char)buf[2] != 0x0a) {
        printf("Client ID not 0x0a\n: buf[2]: %02x\n", (unsigned char)buf[2]);
        data_packet = 1;
    }
    if ((unsigned char)buf[3] != 0xff && (unsigned char)buf[4] != 0xf1) {
        printf("Packet type not DATA 0xfff1: buf[3]: %02x  buf[4]: %02x\n",
            (unsigned char)buf[3], (unsigned char)buf[4]);
        data_packet = 1;
    } else {
        printf("Packet type: DATA\n");
    }

    // check DATA header: seg[5], length[6], payload[length[6]]
    // need to detect out of sequence
    if (data_packet && (unsigned char)buf[5] != 0x01) {
        printf("Data packet segment not 0x01: buf[5]: %02x\n",
            (unsigned char)buf[5]);
        data_packet = 1;
        reject_code = 0xf4;
    }

    // need to detect out of sequence
    // need to detect duplicate packet
    // need to detect length mismatch
    
    // check end id[2]
    length = buf[6];
    if (data_packet && (unsigned char)buf[6 + length] != 0xff &&
        (unsigned char)buf[6 + length + 1] != 0xff) {
        printf("End of Packet Id not 0xffff: buf[6]: %02x buf[6 + %d + 1]: %02x\n",
            (unsigned char)buf[6], length, (unsigned char)buf[6 + length + 1]);
        data_packet = 1;
        reject_code = 0xf6;
    }

    // check ACK header: seg[1]
    
    // check REJECT header: subcode[2]

    // compose resp_buf
    if (data_packet == 0) {
        // ACK packet
        resp_buf[0] = 0xff;     // packet start id
	    resp_buf[1] = 0xff;
	    resp_buf[2] = buf[2];   // client id
	    resp_buf[3] = 0xff;     // packet type: ACK
	    resp_buf[4] = 0xf2; 
	    resp_buf[5] = buf[5];   // seg no
	    resp_buf[6] = 0xff;     // packet end
	    resp_buf[7] = 0xff;
	    resp_buf[8] = 0x00;     // pad
    } else {
        // REJECT packet
        resp_buf[0] = 0xff;     // packet start id
	    resp_buf[1] = 0xff;
	    resp_buf[2] = buf[2];   // client id
	    resp_buf[3] = 0xff;     // packet type:  REJECT
	    resp_buf[4] = 0xf3; 
	    resp_buf[5] = 0xff;     // reject subcode
	    resp_buf[6] = reject_code;
	    resp_buf[7] = buf[5];   // segment
	    resp_buf[8] = 0xff;     // packet end
	    resp_buf[9] = 0xff;     // pad
    }

    return(data_packet);
}

int main(void)
{
    struct sockaddr_in si_me, si_other;
     
    int s, i, slen = sizeof(si_other) , recv_len;
    char buf[BUFLEN];
    char resp_buf[REJECTBUFLEN];
    int start = 0;
     
    //create a UDP socket
    if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        die("socket");
    }
     
    // zero out the structure
    memset((char *) &si_me, 0, sizeof(si_me));
     
    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(PORT);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);
     
    //bind socket to port
    if( bind(s , (struct sockaddr*)&si_me, sizeof(si_me) ) == -1)
    {
        die("bind");
    }
     
    //keep listening for data
    while(1)
    {
        printf("\nWaiting for data...");
        fflush(stdout);
         
        //try to receive some data, this is a blocking call
        memset(buf,'\0', BUFLEN);
        if ((recv_len = recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen)) == -1)
        {
            die("recvfrom()");
        }
         
        //print details of the client/peer and the data received
        printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
        //printf("Data: %s\n" , buf);
        
        start = 0;
        printf("Packet Header: ");
        for (i=0; i < 7; i++) {
            printf((i<start)?"   ":"%02x%c", (unsigned char)buf[i],((i+1)&15)?' ':'\n');
	    }
	    printf("\n");
	    
	    // call a packet inspector
	    if ((check_packet(buf, resp_buf)) != 0) {
	        printf("check_packet did not detect data packet. sending REJECT\n");
	    } else {
	        printf("check_packet detected data packet. sending ACK\n");
	    }

        start = 0;
        printf("ACK Packet: ");
        for (i=0; i < 7; i++) {
            printf((i<start)?"   ":"%02x%c", (unsigned char)resp_buf[i],((i+1)&15)?' ':'\n');
	    }
	    printf("\n");
	    
        //now reply to the client with the resp_buf (ACK or REJECT)
        if (sendto(s, resp_buf, REJECTBUFLEN, 0, (struct sockaddr*) &si_other, slen) == -1)
        {
            die("sendto()");
        }

    }
 
    close(s);
    return 0;
}
