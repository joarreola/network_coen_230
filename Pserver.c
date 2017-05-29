/*
    udp server
*/

#include<stdio.h> //printf
#include<string.h> //memset
#include<stdlib.h> //exit(0);
#include<arpa/inet.h>
#include<sys/socket.h>
 
#define BUFLEN 264  //BUFFER Length
#define DATAPKTHEADER 7
#define ACCESSHEADER 14
#define ACKBUFLEN 14
#define REJECTBUFLEN 14
#define PORT 8888   //The port on which to listen for incoming data
#define EXIT 0xff

// globals
char buf[BUFLEN];
char resp_buf[REJECTBUFLEN];
int next_segment_number = 0x00;
int prev_segment_number = 0x00;
char received_segments[10];
int seg_index = 0;
int packets_received = 0;
char buff[1024];
char* lines[1024];
char subscriber[3][6];

void die(char *s)
{
    perror(s);
    exit(1);
}

void print_header(char buf[], int header_length, char *title)
{
    int start = 0;
    int i;

    printf("%s: ", title);
    for (i=0; i < header_length; i++)
    {
        printf((i<start)?"   ":"%02x%c", (unsigned char)buf[i],((i+1)&15)?' ':'\n');
    }
    printf("\n");
}

/*
 * START OF FOR ACCESS PACKET ONLY
 * Access permission is checked by the
 * subscriber phone number and the technology per the
 * Verification-Database.txt file:
 *
 *      408-554-6805 04 1   paid
 *      408-666-8821 03 0   not paid
 *      408-680-8821 02 1   paid
 *
 *      HEX           Technology
 *      0xF3847F35      04          for case: tech mismatch - 3
 *      0xF3959E15      03          for case: not paid - 1
 *      0xF397C0F5      02          for case: paid - 0
 */
void access_check() {

    // unpack the lines[] entries
    //  408-554-6805 04 1
    //  408-666-8821 03 0
    //  408-680-8821 02 1
    printf("\n");
    int number_not_found = 1;
    int i;
    for (i=0;i<3;i++) {
        char num[6];
    
        // number in subscriber[i][0-3]
        num[0] = (unsigned char)subscriber[i][0];
        num[1] = (unsigned char)subscriber[i][1];
        num[2] = (unsigned char)subscriber[i][2];
        num[3] = (unsigned char)subscriber[i][3];
        num[4] = (unsigned char)subscriber[i][4];
        num[5] = (unsigned char)subscriber[i][5];
      //  int n;
      //  for (n=0;n<4;n++) {
            //printf("access_check - num[%d]: %02x\n", n, (unsigned char)num[n]);
     //   }

        // check if number exist in file
        if ((unsigned char)buf[8] == (unsigned char)num[0] && 
            (unsigned char)buf[9] == (unsigned char)num[1] &&
            (unsigned char)buf[10] == (unsigned char)num[2] &&
            (unsigned char)buf[11] == (unsigned char)num[3])
        {
            number_not_found = 0;

            // check paid field and tech field
            if ((unsigned char)num[5] == 1 &&
                (unsigned char)num[4] == (unsigned char)buf[7])
            {
                // Good subscriber
                printf("access_check - ACCESS GRANTED - good subscriber.\n");
                resp_buf[3] = 0xff;
	            resp_buf[4] = 0xfb;
            }
            
            else if ((unsigned char)num[5] == 0)
            {
                // Not paid
                printf("access_check - ACCESS DENIED - not paid.\n");
                resp_buf[3] = 0xff;
	            resp_buf[4] = 0xf9;
            }
            
            else if ((unsigned char)num[5] == 1 &&
                (unsigned char)num[4] != (unsigned char)buf[7])
            {
                // tech mismatch
                printf("access_check - ACCESS DENIED - technology mismatch.\n");
                resp_buf[3] = 0xff;
	            resp_buf[4] = 0xf8; 
            }
        }
    }
    
    // check for number not found
    if (number_not_found) {
        printf("access_check - ACCESS DENIED - number not found.\n");
        resp_buf[3] = 0xff;
	       resp_buf[4] = 0xfa;
    }
}

/*
 * Check packet structure
 *      start id:       0xFFFF
 *      client id:      0x0a    // for example
 *      Pkt types:
 *          DATA:       0xFFF1
 *          ACK:        0xFFF2
 *          REJECT:     0xFFF3
 *          ACCESS:     0xFFF8
 *          EXIT:       0xFFFF
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
 *      For ACCESS AC_OK Type:
 *          rcvd segment:   0x01    // ex: for 1st segment
 *          length:         0x05
 *          technology:     0x02    // for 2 G
 *          phone number:   0xFFFFFFFF // in hex
 *          end id:         0xFFFF
 */
static int check_packet(char buf[], char resp_buf[])
{
    int invalid_packet = 0;
    int data_packet = 0;
    int access_packet = 0;
    int length;
    int start = 0;
    int i = 0;
    int reject_code = 0x00;
    int cmp_segment;
    int already_received = 0;
    int verified_length = 0x00;

    // for end ID checking, do only for a DATA packet
    length = (unsigned char)buf[6];
    int end_first = length + 7;
    int end_second = length + 7 + 1;

    // compute actual payload length
    // needed only for data packet
    i = 7;
    while ( 1 )
    {
        if (i > BUFLEN) { break; }
        
        if ((unsigned char)buf[i] == 0xff && (unsigned char)buf[i + 1] == 0xff)
        {
            break;
        } else {
            verified_length++;
        }
        i++;
    }
    
    // check if valid length (< 264 -9)
    // reset end_first and end_second
    // needed only for a DATA packet
    if (verified_length <= (BUFLEN - 9)) {
        end_first = verified_length + 7;
        end_second = verified_length + 7 + 1;
    }
    
    /*
     * DO FOR BOTH DATA AND ACCESS PACKETS
     */
    // check header: start[0-1], client[2], type[3-4]
    // check start id
    if ((unsigned char)buf[0] != 0xff && (unsigned char)buf[1] != 0xff)
    {
        printf("Error - Start of packet ID not 0xffff: buf[0]: %02x  buf[1]: %02x\n",
            (unsigned char)buf[0], (unsigned char)buf[1]);
        invalid_packet= 1;
    }
    // check client id 
    if ((unsigned char)buf[2] != 0x0a)
    {
        printf("Error - Client ID not 0x0a\n: buf[2]: %02x\n", (unsigned char)buf[2]);
        invalid_packet = 1;
    }
    // check if it is EXIT packet
    if ((unsigned char)buf[3] == 0xff && (unsigned char)buf[4] == EXIT)
    {
        printf("Exit Packet type\n");

        return(EXIT);
    }
    
    // check packet type
    if ((unsigned char)buf[3] != 0xff && (unsigned char)buf[4] != 0xf1)
    {
        printf("Error - Packet type not DATA 0xfff1: buf[3]: %02x  buf[4]: %02x\n",
            (unsigned char)buf[3], (unsigned char)buf[4]);

        invalid_packet = 1;
        
        goto PACK_RESP_BUF;

    } else if ((unsigned char)buf[3] == 0xff && (unsigned char)buf[4] == 0xf1) {

        data_packet = 1;

    } else if ((unsigned char)buf[3] == 0xff && (unsigned char)buf[4] == 0xf8) {
        printf("Packet type: ACCESS\n");
        print_header(buf, ACCESSHEADER, "Access Packet Header");
        access_packet = 1;
        
        // check access fields, using Verification_Database.txt, in access_check()
        access_check();
        
        goto PACK_RESP_BUF;
    }

    /*
     * START OF FOR DATA PACKET ONLY
     */
    // have a good data packet header, so far
    // check segment in received_segments
    for (i=0; i<seg_index; i++)
    {
        if (received_segments[i] == (unsigned char)buf[5])
        {
            //printf("Packet already received: segment: %02x\n", (unsigned char)buf[5]);
            already_received = 1;
        }
    }
    
    // check DATA header: seg[5], length[6], payload[length[6]]
    // need to detect out of sequence
    if (prev_segment_number == next_segment_number) { cmp_segment = 0x00; }
    else { cmp_segment = next_segment_number; }
    
    // check out of sequence packet
    if (data_packet && ((unsigned char)buf[5] != cmp_segment) && already_received == 0)
    {
        printf("REJECT PACKET\n");
        printf("Error - Out of sequence Data packet segment: buf[5]: %02x expected: %02x\n",
            (unsigned char)buf[5], cmp_segment);
        reject_code = 0xf4;
    }
    else
    {
        prev_segment_number = buf[5];
        next_segment_number = buf[5] + 1;
    }

    // detect end of packet or length mismatch or duplicate packet
    // assume that the end of packet id is valid
    if (data_packet && (unsigned char)buf[end_first] != 0xff ||
        (unsigned char)buf[end_second] != 0xff)
    {
        printf("REJECT PACKET\n");
        printf("Error - End of Packet Id not 0xffff: buf[6]: %02x buf[end_first]: %02x buf[end_second]: %02x\n",
            (unsigned char)buf[6], (unsigned char)buf[end_first], (unsigned char)buf[end_second]);
        reject_code = 0xf6;
    }
    else if (data_packet && (unsigned char)buf[6] != verified_length)
    {
        printf("REJECT PACKET\n");
        printf("Error - Detected length mismatch: length field: %02x verified length: %02x\n",
            (unsigned char)buf[6], verified_length);
        reject_code = 0xf5;
    }
    else if (data_packet && reject_code == 0x00 && already_received)
    {
        printf("REJECT PACKET\n");
        printf("Error - Duplicate Packet: segment: %02x\n", (unsigned char)buf[5]);
        reject_code = 0xf7;
    }
    
    if (data_packet && reject_code != 0xf4)
    {
        // add to the received_segments[]
        received_segments[seg_index++] = (unsigned char)buf[5];
    }

PACK_RESP_BUF:
    // compose resp_buf
    if (invalid_packet | reject_code)
    {
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
    } else if (data_packet) {
        // ACK packet
        resp_buf[0] = 0xff;     // packet start id
	    resp_buf[1] = 0xff;
	    resp_buf[2] = buf[2];   // client id
	    resp_buf[3] = 0xff;     // packet type: ACK
	    resp_buf[4] = 0xf2; 
	    resp_buf[5] = buf[5];   // seg no
	    resp_buf[6] = 0xff;     // packet end
	    resp_buf[7] = 0xff;
    }  else if (access_packet) {
        resp_buf[0] = 0xff;     // packet start id
	    resp_buf[1] = 0xff;
	    resp_buf[2] = buf[2];   // client id
	    //resp_buf[3] = 0xff;     // acc_OK, not paid, not exist
	    //resp_buf[4] = 0xfb; 
	    resp_buf[5] = buf[5];   // seg no
	    resp_buf[6] = 0x05;     // length of tech + subscriber number
	    resp_buf[7] = buf[7];   // technology
	    resp_buf[8] = buf[8];   // subscriber number
	    resp_buf[9] = buf[9];
	    resp_buf[10] = buf[10];
	    resp_buf[11] = buf[11];
	    resp_buf[12] = 0xff;    // end id
	    resp_buf[13] = 0xff;
    }

    return(invalid_packet | reject_code);
}

/*
 * Read lines in filename. Convert phone number to same format as
 * sent by the client. Compose an array of arrays with number, tech,
 * and paid data for each line.
 */
static void read_file(char * filename) {
    FILE *fp;

    fp = fopen(filename, "r");
    int i;
    
    for(i=0;i<=2;i++){        
        fgets(buff,sizeof(buff),fp);
        //
        char *buffcopy = malloc(strlen(buff) + 1);
        if(buffcopy == NULL) {fprintf(stderr, "out of memory\n"); exit(1); }
        strcpy(buffcopy, buff);
        lines[i] = buffcopy;
    }

    fclose(fp);
    
    // unpack
    for (i=0;i<3;i++) {

        // extract fields
        char *num = strtok(lines[i], "    ");
        char *tech = strtok(NULL, "    ");
        char *paid = strtok(NULL, "    ");

        // convert 408-554-6805 to 4085546805
        char *num_1 = strtok(num, "-");
        char *num_2 = strtok(NULL, "-");
        char *num_3 = strtok(NULL, "-");
        strcat(num_2, num_3);
        strcat(num_1, num_2);
        //printf("-- read_file -- num_1: %s\n", num_1);
        
    
        // convert 4085546805 to hex
        int num_int = atoi(num_1);
        //printf("-- read_file -- num_int: %x\n", num_int);
        
        char num_array[4];
        strncpy(&num_array[0], (char *)&num_int, 8);
        
        // stuff a subscriber array of arrays to use in check_packet
        subscriber[i][0] = num_array[3];
        subscriber[i][1] = num_array[2];
        subscriber[i][2] = num_array[1];
        subscriber[i][3] = num_array[0];
        subscriber[i][4] = atoi(tech);
        subscriber[i][5] = atoi(paid);
    }
}

void reset_server() {
    packets_received = 0;
    memset(received_segments,'\0', 10);
    next_segment_number = 0x00;
    prev_segment_number = 0x00;
    seg_index = 0;
}

int main(void)
{
    struct sockaddr_in si_me, si_other;
     
    int s, i, slen = sizeof(si_other) , recv_len;
    int start = 0;
    char cmd[1];
    int packet_length = 0;

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
    
    // reset received_segments
    memset(received_segments,'\0', 10);
    
    //keep listening for data
    memset(cmd,'\0', 1);
    
    // read Verification_Database.txt file
    //  408-554-6805 04 1
    //  408-666-8821 03 0
    //  408-680-8821 02 1
    read_file("Verification_Database.txt");

    while(1)
    {

        printf("\nWaiting for data from client ...\n");
        printf("------------------------------------------------\n");
        fflush(stdout);
         
        //try to receive some data
        memset(buf,'\0', BUFLEN);
        if ((recv_len = recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen)) == -1)
        {
            die("recvfrom()");
        }
         
        // print details of the client/peer and DATA packet header (to before payload)
        //printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
        if (strcmp(inet_ntoa(si_other.sin_addr), "127.0.0.1") != 0 &&
            ntohs(si_other.sin_port) != PORT)
        {
            continue;
        }
        //print_header(buf, ACCESSHEADER, "Packet Header");
	    
	    // count as a received packet
	    packets_received++;

	    // inspect the packet
	    memset(resp_buf,'\0', REJECTBUFLEN);
	    int ret = check_packet(buf, resp_buf);
	   
	    if (ret == EXIT) {
	        printf("RESETING SERVER STATE.\n");
	        reset_server();
	        
	        goto NO_REPLAY;
	    }
	    
	    if (ret != 0)
	    {
	        packet_length = REJECTBUFLEN;
	        //print_header(resp_buf, REJECTBUFLEN, "REJECT PACKET");
	        //printf("REJECT PACKET\n");
	    } else {
	        packet_length = ACKBUFLEN;
	        //print_header(resp_buf, ACKBUFLEN, "ACK PACKET");
	        printf("ACK PACKET\n");
	    }

/*	    if (strcmp((const char *)cmd, "y") == 0 &&
*	            (
*	                (unsigned char)resp_buf[5] == 0x00 || (unsigned char)resp_buf[7] == 0x00
*	           )
*	       )
*	   {
*	        printf("Sleeping 10 seconds before ACK for segment 0...\n");
*	        sleep(10);
*	    }
*/	    
       // now reply to the client with the resp_buf (ACK or REJECT)
        if (sendto(s, resp_buf, packet_length , 0, (struct sockaddr*) &si_other, slen) == -1)
        {
           die("sendto()");
        }


NO_REPLAY:
        printf("\t");
    }
 
    close(s);
    return 0;
}
