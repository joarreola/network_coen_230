/*
    Simple udp client
*/
#include<stdio.h> //printf
#include<string.h> //memset
#include<stdlib.h> //exit(0);
#include<arpa/inet.h>
#include<sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>

#define SERVER "127.0.0.1"
#define BUFLEN 109  //Max length of buffer was 512
#define PORT 8888   //The port on which to send data
#define SENDRETRYS 3
#define DATAPKTHEADER 7
#define ACKBUFLEN 8
#define REJECTBUFLEN 10
#define TIMEOUT 5
#define TENBYTES 10
#define TWENTYTHREEBYTES 23

// globals
int segment_number = 0x00;
int client_id = 0x0a;
int s;
char buf[BUFLEN];
char message[BUFLEN];
int seq_error = 0;
int dup_err = 0;
int end_error = 0;
int length_err = 0;
int end_id_index = 0;

void die(char *s)
{
    perror(s);
    exit(1);
}

static void print_header(char buf[], int header_length, char *title)
{
    int start = 0;
    int i;

    printf("%s ", title);
    for (i=0; i < header_length; i++)
    {
        printf((i<start)?"   ":"%02x%s", (unsigned char)buf[i],((i+1)&15)?" ":"\n ");
    }
    printf("\n");
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
 *          payload:        0xNN bytes // using "dd" for data
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
static int check_packet(char buf[])
{
    int invalid_packet = 0x00;
    int ack_packet = 0;
    int reject_packet = 0;
    int length;
    int start = 0;
    int i = 0;
    int reject_subcode = 0x00;
    int ret = 0x00;

    // check header: start[0-1], client[2], type[3-4]
    if ((unsigned char)buf[0] != 0xff && (unsigned char)buf[1] != 0xff)
    {
        printf("check_packet - Start of packet ID not 0xffff: buf[0]: %02x  buf[1]: %02x\n",
            (unsigned char)buf[0], (unsigned char)buf[1]);
        invalid_packet = 0x10;
    }
    
    if ((unsigned char)buf[2] != 0x0a)
    {
        printf("check_packet - Client ID not 0x0a\n: buf[2]: %02x\n", (unsigned char)buf[2]);
        invalid_packet = 0x10;
    }
    
    if ((unsigned char)buf[3] != 0xff &&
        ((unsigned char)buf[4] != 0xf2 || (unsigned char)buf[4] != 0xf3))
    {
        printf("check_packet - Packet type not ACK nor REJECT 0xfff1: buf[3]: %02x  buf[4]: %02x\n",
            (unsigned char)buf[3], (unsigned char)buf[4]);
        invalid_packet = 0x10;

    }
    else
    {
        if ((unsigned char)buf[4] == 0xf2)
        {
            printf("check_packet - Packet type: ACK\n");
            ack_packet = 1;
            reject_subcode = 0x00;
        }
        if ((unsigned char)buf[4] == 0xf3)
        {
            //printf("check_packet - Packet type: REJECT\n");
            invalid_packet = 0x10;
            //printf("check_packet - setting reject_packet after Packet type: REJECT\n");
            reject_packet = 1;
        }
    }

    // check ACK header: seg[5]
    if (ack_packet && (unsigned char)buf[5] != segment_number)
    {
        printf("check_packet - ACK packet segment not %02x buf[5]: %02x\n",
            segment_number, (unsigned char)buf[5]);
        invalid_packet = 0x10;
    }
    
    // check end id[2]
    if (ack_packet && (unsigned char)buf[6] != 0xff &&
        (unsigned char)buf[6] != 0xff)
    {
        printf("End of Packet Id not 0xffff: buf[6]: %02x\n",
            (unsigned char)buf[6]);
        invalid_packet = 0x10;
    }

    // check REJECT header: subcode[5-6]
    if (reject_packet && ((unsigned char)buf[5] != 0xff &&
        ((unsigned char)buf[6] < 0xf4) || (unsigned char)buf[6] > 0xf7))
    {
        printf("check_packet - Invalid Reject Sub-code: buf[5]: %02x buf[6]: %02x\n",
            (unsigned char)buf[5], (unsigned char)buf[6]);
        invalid_packet = 0x10;

    }
    else if (reject_packet && (unsigned char)buf[5] == 0xff &&
        ((unsigned char)buf[6] > 0xf43) || (unsigned char)buf[6] < 0xf8)
    {
        // check sub codes
        if ((unsigned char)buf[6] == 0xf4)
        {
            //printf(" Reject Packet Sub-code: Out of sequence segment\n");
            reject_subcode = 0x04;
        }
        if ((unsigned char)buf[6] == 0xf5)
        {
            //printf(" Reject Packet Sub-code: Length misatch\n");
            reject_subcode = 0x05;
        }
        if ((unsigned char)buf[6] == 0xf6)
        {
            //printf(" Reject Packet Sub-code: End of packet missing\n");
            reject_subcode = 0x06;
        }
        if ((unsigned char)buf[6] == 0xf7)
        {
            //printf(" Reject Packet Sub-code: Duplicate packet\n");
            reject_subcode = 0x07;
        }
    }
    ret = invalid_packet | reject_subcode;

    return(ret);
}

/*
 * DATA packet structure
 *      start id:       0xFFFF
 *      client id:      0x0a        // for example
 *      Pkt type:       0xFFF1
 *      segment:        0x01        // ex: for 1st segment
 *      data length:    0xFF        // for 255 data bytes
 *      payload:        0xNN bytes  // using "dd" for data
 *      end id:         0xFFFF
 */
static void make_data_packet(int client_id, int segment_number,
    int payload, char message[])
{
    int i;
    
    // make a DATA packet
    message[0] = 0xff; // packet start id
    message[1] = 0xff;
    message[2] = client_id; // client id
    message[3] = 0xff; // packet type = data
    message[4] = 0xf1; 
    message[5] = segment_number; // seg no
    message[6] = payload; // data length 
    for (i=7; i<(7 + payload);i++) {
        message[i] = 0xdd;
    }
    message[7 + payload] = 0xff; // packet end
    message[7 + payload + 1] = 0xff;
    
    // store [7 + payload + 1] for end-id corruption
    end_id_index = 7 + payload + 1;
}

void sighdlr()
{
    struct tm tm;
    time_t now;

    //printf("sighdlr called - s: %d\n", s);
    now = time( NULL );
    localtime_r( &now, &tm );
    printf("sighdlr - %02d:%02d:%02d\n", tm.tm_hour, tm.tm_min, tm.tm_sec );
}

/*
 *  Inject errors per Assignment 1 requirements
 *      1- out of sequence:
 *         if to send segment 1, change segment to 2
 *      2- missing end of packet id:
 *         if to send segment 3, corrupt end id
 *      3- duplicate packet:
 *         if to send segment 4, change segment to 3
 *      4- length field mismatch:
 *         if to resend segment 4, change length to ff from 64
 */
void inject_error(int segment_number) {
    printf("------------------------------------------------\n");
    if (segment_number == 0x01 && seq_error == 0)
    {
        // change segment number field to 2
        printf("Create Out Of Sequence condition\n");
        message[5] = 0x02;
        seq_error = 1;
    }
    /*
    if (segment_number == 0x02 && seq_error != 1)
    {
        // change length from 0xff
        message[6] = 0xf0;
    }
    */
    else if (segment_number == 0x03 && end_error == 0)
    {
        // missing end of packet id
        printf("Create Missing End Of Packet ID condition\n");
        message[end_id_index] = 0x00;
        end_error = 1;
    }
    else if (segment_number == 0x04 && dup_err == 0)
    {
        // duplicate packet
        printf("Create Duplicate Packet condition\n");
        message[5] = 0x03;
        dup_err = 1;
    }
    else if (segment_number == 0x04 && dup_err != 0)
    {
        // length field value is greater that actual payload
        printf("Create Length Mismatch condition\n");
        message[6] = 0xff;
        length_err = 1;
    }
}

int main(void)
{
    struct sockaddr_in si_other;
    int i, slen=sizeof(si_other);
    char cmd[BUFLEN];
    int ret = 0x00;
    int start;
    int send_retry = 0;

    // ack_timer setup
    signal( SIGALRM, sighdlr );
    struct itimerval itv;
    struct tm tm;
    time_t now;
    itv.it_value.tv_sec = TIMEOUT;
    itv.it_value.tv_usec = 0;
    itv.it_interval.tv_sec = 0;
    itv.it_interval.tv_usec = 0;

    // get socket
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
 
    /*
     * get users input:
     *      g: send 5 good packets
     *      b: send 1 good and 4 bad
     *      n: exit
     */
    memset(cmd,'\0', 1);
    printf("Send packets to server?: (g/b/n) ");
    gets(cmd);
    if (strcmp((const char *)cmd, "n") == 0)
    {
        printf("Terminating client\n");
        exit(0);
    }
    else if (strcmp((const char *)cmd, "g") == 0)
    {
        printf("Sending 5 Good packets..\n");
    }
    else if (strcmp((const char *)cmd, "b") == 0)
    {
        printf("Sending 1 Good  and 4 Bad packets..\n");
        printf("=======================================\n");
    }
    
    while(1)
    {
        if (segment_number > 0x04) {
            printf("Stop sending packets.\n");
            break;
        }

        // make a DATA packet
        memset(message,'\0', BUFLEN);
	    make_data_packet(client_id, segment_number, TWENTYTHREEBYTES, message);
	    
	    // inject packet errors
	    if (strcmp((const char *)cmd, "b") == 0) {
	        inject_error(segment_number);
	    }

	    // send
	    printf("Sending packet segment: %02x\n", message[5]);
	    print_header(message, (TWENTYTHREEBYTES + 9), "Data Packet:\n");
	    if (sendto(s, message, BUFLEN , 0 , (struct sockaddr *) &si_other, slen)==-1)
        {
            die("sendto()");
        }

        //receive a reply and print it
        //clear the buffer by filling null, it might have previously received data
        memset(buf,'\0', REJECTBUFLEN);

        // start itimer
        setitimer( ITIMER_REAL, &itv, NULL );
        
        //try to receive some data, this is a blocking call
        printf("waiting for reply...\n");
        if (recvfrom(s, buf, REJECTBUFLEN, 0, (struct sockaddr *) &si_other, &slen) == -1)
        {
            die("recvfrom()");
        }
    
        // print reply packet
	    print_header(buf, REJECTBUFLEN, "Reply Packet:");
	    
	    // if empty reply buf, retry 3 times
	    if ((unsigned char)buf[0] == 0x00)
	    {
	        printf("ACK timed out...\n");
	        if (send_retry < SENDRETRYS)
	        {
	            printf("Re-send packet with segment: %d\n", segment_number);
	            send_retry++;
	            continue;
	   
	        } else {
	            printf("Exceded re-send limit. Exiting\n");
	            break;
	        }
	    }

	    // check the reply packet:
	    //      0x1N => invalid packet
	    //      0x0N => valid packet ack or reject.
	    ret = check_packet(buf);
	    //printf("check_packet ret: %02x  &0x10: %02x\n", ret, (ret & 0x10));

	    if ((ret & 0x10) == 0x10)
	    {
	        //printf("post check_packet - Invalid Replay packet\n");
	    }
	 
	    if ((ret & 0x0f) == 0x00)
	    {
	        //printf("post check_packet - ACK Packet\n");
	    }
	    else
	    {
	        //printf("post check_packet - REJECT Packet\n");
	    }
	    
	    if ((ret & 0x0f) == 0x04)
	    {
	        printf("Error - REJECT Packet: out of sequence\n");
	        //printf("post check_packet - current segment_number: %02x\n", segment_number);
	        
	        // don't increment segment number
	        continue;
	    }
	    else if ((ret & 0x0f) == 0x05)
        {
	        printf("Error - REJECT Packet: length mismatch\n");
	    }
	    else if ((ret & 0x0f) == 0x06)
	    {
	        printf("Error - REJECT Packet: end of packet missing\n");
	    }
	    else if ((ret & 0x0f) == 0x07)
	    {
	        printf("Error - REJECT Packet: duplicate packet\n");
	        
	        // don't increment segment number
	        continue;
	    }

	    // increment the segment number
	    segment_number++;

    }
 
    close(s);
    return 0;
}
