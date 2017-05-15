/*
    Simple udp client
*/
#include<stdio.h> //printf
#include<string.h> //memset
#include<stdlib.h> //exit(0);
#include<arpa/inet.h>
#include<sys/socket.h>
 
#define SERVER "127.0.0.1"
#define BUFLEN 264  //Max length of buffer was 512
#define PORT 8888   //The port on which to send data

// globals
int segment_number = 0x00;

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
static int check_packet(char buf[]) {
    int invalid_packet = 0x00;
    int ack_packet = 0;
    int reject_packet = 0;
    int length;
    int start = 0;
    int i = 0;
    int reject_subcode = 0x00;
    int ret = 0x00;

    // check header: start[0-1], client[2], type[3-4]
    if ((unsigned char)buf[0] != 0xff && (unsigned char)buf[1] != 0xff) {
        printf("Start of packet ID not 0xffff: buf[0]: %02x  buf[1]: %02x\n",
            (unsigned char)buf[0], (unsigned char)buf[1]);
        invalid_packet = 0x10;
    }
    if ((unsigned char)buf[2] != 0x0a) {
        printf("Client ID not 0x0a\n: buf[2]: %02x\n", (unsigned char)buf[2]);
        invalid_packet = 0x10;
    }
    if ((unsigned char)buf[3] != 0xff &&
        ((unsigned char)buf[4] != 0xf2 || (unsigned char)buf[4] != 0xf3)) {
        printf("Packet type not ACK nor REJECT 0xfff1: buf[3]: %02x  buf[4]: %02x\n",
            (unsigned char)buf[3], (unsigned char)buf[4]);
        invalid_packet = 0x10;
    } else {
        if ((unsigned char)buf[4] == 0xf2) {
            printf("Packet type: ACK\n");
            ack_packet = 1;
            reject_subcode = 0x00;
        }
        if ((unsigned char)buf[4] == 0xf3) {
            printf("Packet type: REJECT\n");
            invalid_packet = 0x10;
            printf("setting reject_packet after Packet type: REJECT\n");
            reject_packet = 1;
        }
    }

    // check ACK header: seg[5]
    // need to detect out of sequence
    if (ack_packet && (unsigned char)buf[5] != segment_number) {
        printf("ACK packet segment not %02x buf[5]: %02x\n",
            segment_number, (unsigned char)buf[5]);
        invalid_packet = 0x10;
    }

    // need to detect out of sequence
    // need to detect duplicate packet
    // need to detect length mismatch
    
    // check end id[2]
    if (ack_packet && (unsigned char)buf[6] != 0xff &&
        (unsigned char)buf[6] != 0xff) {
        printf("End of Packet Id not 0xffff: buf[6]: %02x\n",
            (unsigned char)buf[6]);
        invalid_packet = 0x10;
    }

    // check REJECT header: subcode[5-6]
    if (reject_packet && ((unsigned char)buf[5] != 0xff &&
        ((unsigned char)buf[6] < 0xf4) || (unsigned char)buf[6] > 0xf7)) {
        printf("Invalid Reject Sub-code: buf[5]: %02x buf[6]: %02x\n",
            (unsigned char)buf[5], (unsigned char)buf[6]);
        invalid_packet = 0x10;

    } else if (reject_packet && (unsigned char)buf[5] == 0xff &&
        ((unsigned char)buf[6] > 0xf43) || (unsigned char)buf[6] < 0xf8) {
        // check sub codes
        if ((unsigned char)buf[6] == 0xf4) {
            printf(" Reject Packet Sub-code: Out of sequence segment\n");
            reject_subcode = 0x04;
        }
        if ((unsigned char)buf[6] == 0xf5) {
            printf(" Reject Packet Sub-code: Length misatch\n");
            reject_subcode = 0x05;
        }
        if ((unsigned char)buf[6] == 0xf6) {
            printf(" Reject Packet Sub-code: End of packet missing\n");
            reject_subcode = 0x06;
        }
        if ((unsigned char)buf[6] == 0xf7) {
            printf(" Reject Packet Sub-code: Duplicate packet\n");
            reject_subcode = 0x07;
        }
    }
    ret = invalid_packet | reject_subcode;

    return(ret);
}

int main(void)
{
    struct sockaddr_in si_other;
    int s, i, slen=sizeof(si_other);
    char buf[BUFLEN];
    char message[BUFLEN];
    char cmd[BUFLEN];
    int ret = 0x00;
    int start;
 
    if ( (s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        die("socket");
    }
 
    memset((char *) &si_other, 0, sizeof(si_other));
    si_other.sin_family = AF_INET;
    si_other.sin_port = htons(PORT);
     
    if (inet_aton(SERVER , &si_other.sin_addr) == 0)
    {
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }
 
    // cmd buf memory
    memset(cmd,'\0', 1);
    while(1)
    {
        printf("Send message?: (y/n) ");
        gets(cmd);
        if (strcmp((const char *)cmd, "n") == 0) {
		    break;
	    } else {
	        printf("Sending segment: %d\n", segment_number);
	    }
    
        memset(message,'\0', BUFLEN);
	    message[0] = 0xff; // packet start id
	    message[1] = 0xff;
	    message[2] = 0x0a; // client id
	    message[3] = 0xff; // packet type = data
	    message[4] = 0xf1; 
	    message[5] = segment_number; // seg no
	    message[6] = 0xff; // length of 264 bytes
	    // payload of 255 bytes
	    int i;
	    for (i=7; i<=261;i++) {
		    message[i] = 0xda;
	    }
	    message[262] = 0xff; // packet end
	    message[263] = 0xff;
        
        start = 0;
        printf("Sending packet with header: ");
        for (i=0; i < 9; i++) {
            printf((i<start)?"   ":"%02x%c",
                (unsigned char)message[i],((i+1)&15)?' ':'\n');
	    }
	    printf("\n");
        //send the 1st packet
        if (sendto(s, message, strlen(message) , 0 ,
            (struct sockaddr *) &si_other, slen)==-1)
        {
            die("sendto()");
        }
        
        //receive a reply and print it
        //clear the buffer by filling null, it might have previously received data
        memset(buf,'\0', BUFLEN);
        //try to receive some data, this is a blocking call
        if (recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen) == -1)
        {
            die("recvfrom()");
        }
         
        //puts(buf);
        start = 0;
        printf("Replay Packet: ");
        for (i=0; i < 9; i++) {
            printf((i<start)?"   ":"%02x%c", (unsigned char)buf[i],((i+1)&15)?' ':'\n');
	    }
	    printf("\n");
	    
	    // check the reply packet:
	    //      0x1N => invalid packet
	    //      0x0N => valid packet ack or reject.
	    ret = check_packet(buf);
	    if ((ret | 0x0f) == 0x1f) {
	        printf("Invalid Replay packet\n");
	    } else if ((ret & 0x0f) == 0x00) {
	        printf("ACK\n");
	    } else if ((ret & 0x0f) == 0x04) {
	        printf("REJECT: out of sequence\n");
	    } else if ((ret & 0x0f) == 0x05) {
	        printf("REJECT: length mismatch");
	    } else if ((ret & 0x0f) == 0x06) {
	        printf("REJECT: end of packet missing\n");
	    } else if ((ret & 0x0f) == 0x07) {
	        printf("REJECT: duplicate packet\n");
	    }

	    // increment the segment number
	    segment_number++;
	    
	    if (segment_number > 5) {
	        break;
	    }
    }
 
    close(s);
    return 0;
}
