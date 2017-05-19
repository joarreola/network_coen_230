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
#include <pthread.h>

#define SERVER "127.0.0.1"
#define BUFLEN 109  //Max length of buffer was 512
#define PORT 8888   //The port on which to send data
#define SENDRETRYS 3
#define DATAPKTHEADER 7
#define ACKBUFLEN 8
#define REJECTBUFLEN 14
#define TIMEOUT 3
#define TENBYTES 10
#define TWENTYTHREEBYTES 23
#define FOURTEENBYTES 14
#define EXIT 0xff

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
struct sockaddr_in si_other;
int slen=sizeof(si_other);
pthread_t thread;
char sub_number[4];
int technology;

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
 *              ACK:        0xFFF2
 *              REJECT:     0xFFF3
 *          ACCESS ACK_OK: 0xFFb
 *          EXIT:       0xFFFF
 *      For DATA Type:
 *          sent segment:   0x01    // ex: for 1st segment
 *          data length:    0xFF    // for 255 data bytes
 *          payload:        0xNN bytes // using "dd" for data
 *      For DATA ACK Type:
 *          rcvd segment:   0x01    // ex: for 1st segment
 *      For DATA REJECT Type:
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
 *          phone number:   0xFFFFFFFF // 3 numbers
 *      end id:         0xFFFF
 */
static int check_packet(char buf[])
{
    int invalid_packet = 0x00;
    int data_ack_packet = 0;
    int access_ack_packet = 0;
    int data_reject_packet = 0;
    int access_reject_packet = 0;
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
            data_ack_packet = 1;
            reject_subcode = 0x00;
        }
        else if ((unsigned char)buf[4] == 0xf6)
        {
            printf("check_packet - Packet type: ACCESS ACK_OK\n");
            access_ack_packet = 1;
            reject_subcode = 0x00;
        }

        if ((unsigned char)buf[4] == 0xf3)
        {
            //printf("check_packet - Packet type: REJECT\n");
            invalid_packet = 0x10;
            //printf("check_packet - setting data_reject_packet after Packet type: REJECT\n");
            data_reject_packet = 1;
        }
    }

    /*
     * START OF DATA PACKET ONLY
     */
    // check ACK header: seg[5]
    if (data_ack_packet && (unsigned char)buf[5] != segment_number)
    {
        printf("check_packet - ACK packet segment not %02x buf[5]: %02x\n",
            segment_number, (unsigned char)buf[5]);
        invalid_packet = 0x10;
    }
    
    // check end id[2]
    if (data_ack_packet && (unsigned char)buf[6] != 0xff &&
        (unsigned char)buf[6] != 0xff)
    {
        printf("End of Packet Id not 0xffff: buf[6]: %02x\n",
            (unsigned char)buf[6]);
        invalid_packet = 0x10;
    }

    // check REJECT header: subcode[5-6]
    if (data_reject_packet && ((unsigned char)buf[5] != 0xff &&
        ((unsigned char)buf[6] < 0xf4) || (unsigned char)buf[6] > 0xf7))
    {
        printf("check_packet - Invalid Reject Sub-code: buf[5]: %02x buf[6]: %02x\n",
            (unsigned char)buf[5], (unsigned char)buf[6]);
        invalid_packet = 0x10;

    }
    else if (data_reject_packet && (unsigned char)buf[5] == 0xff &&
        ((unsigned char)buf[6] > 0xf3) || (unsigned char)buf[6] < 0xf8)
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
    goto END;
    /*
     * END OF DATA PACKET ONLY
     */


    /*
     * START OF ACCESS ACK_OK PACKET ONLY
     */
    // check ACK header: seg[5]
    if (access_ack_packet && (unsigned char)buf[5] != segment_number)
    {
        printf("check_packet - ACK packet segment not %02x buf[5]: %02x\n",
            segment_number, (unsigned char)buf[5]);
        invalid_packet = 0x10;
    }
    
    // check length is 0x05
    if (access_ack_packet && (unsigned char)buf[6] != 0x05)
    {
        printf("Length is not  0x05: buf[6]: %02x\n",
            (unsigned char)buf[6]);
        invalid_packet = 0x10;
    }

    // check technology: 0x02 for 2G
    if (access_ack_packet && (unsigned char)buf[7] != 0x05)
    {
        printf("Technology is not  0x02: buf[7]: %02x\n",
            (unsigned char)buf[7]);
        invalid_packet = 0x10;
    }
    
    // check subscriber number: 0xffffffff
    if (access_ack_packet &&
        (
            (unsigned char)buf[8] != 0xFF &&
            (unsigned char)buf[9] != 0xFF &&
            (unsigned char)buf[10] != 0xFF &&
            (unsigned char)buf[11] != 0xFF)
        )
    {
        printf("Subscriber number is not  0xFF: buf[8]: %02x\n",
            (unsigned char)buf[8]);
        invalid_packet = 0x10;
    }
   /*
    * END OF DATA PACKET ONLY
    */

END:
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

/*
 * ACCESS packet structure
 *      start id:       0xFFFF
 *      client id:      0x0a        // for example
 *      acc_per:        0xFFF8
 *      segment:        0x01        // ex: for 2nd segment
 *      data length:    0x05        // 
 *      technology:
 *          2G:         02
 *          3G:         03
 *          4G:         04
 *          5G:         05
 *      subscriber #:   4294967295  // 4-bytes: hex of decimal number
 *      end id:         0xFFFF
 */
static void make_access_packet(int client_id, int segment_number,
    int technology, char sub_number[], char message[])
{
    
    // make an ACCESS packet
    message[0] = 0xff; // packet start id
    message[1] = 0xff;
    message[2] = client_id; // client id
    message[3] = 0xFF;  // acc_per packet type
    message[4] = 0xF8;
    message[5] = segment_number; // seg no
    message[6] = 0x05;      // length
    message[7] = technology;  // technology
    message[8] = sub_number[0];      // number
    message[9] = sub_number[1];
    message[10] = sub_number[2];
    message[11] = sub_number[3];
    message[12] = 0xFF; // end id
    message[13] = 0xFF;
}

/*
 * Called by setitimer when count is down to 0
 *  setitimer( ITIMER_REAL, &itv, NULL );
 *
 *  See the timer setup:
 *      // ack_timer setup
 *      signal( SIGALRM, sighdlr ); <<<<<<<
 *      struct itimerval itv;
 *      struct tm tm;
 *      time_t now;
 *      itv.it_value.tv_sec = TIMEOUT;
 *      itv.it_value.tv_usec = 0;
 *      itv.it_interval.tv_sec = 0;
 *      itv.it_interval.tv_usec = 0;
 *
 */
void sighdlr()
{
    struct tm tm;
    time_t now;

    now = time( NULL );
    localtime_r( &now, &tm );
    pthread_cancel(thread);
}

/*
 * Runs in a pthread. Thread will be killed by signal handler
 * if still alive when timer count expires.
 */
void *dowork()
{
    //try to receive some data, this is a blocking call
    printf("waiting for reply...\n");
    if (recvfrom(s, buf, REJECTBUFLEN, 0, (struct sockaddr *) &si_other, &slen) == -1)
    {
        die("recvfrom()");
    }
}

/*
 *  Inject errors per Assignment 1 requirements, to a DATA packet
 *      1- out of sequence:
 *         if to send segment 1, change segment to 2
 *      2- missing end of packet id:
 *         if to send segment 3, corrupt end id
 *      3- duplicate packet:
 *         if to send segment 4, change segment to 3
 *      4- length field mismatch:
 *         if to resend segment 4, change length to ff from 64
 */
void inject_data_error(int segment_number) {
    printf("------------------------------------------------\n");
    if (segment_number == 0x01 && seq_error == 0)
    {
        // change segment number field to 2
        printf("Create Out Of Sequence condition\n");
        message[5] = 0x02;
        seq_error = 1;
    }
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

/*
 * Reset these vars when we send an EXIT packet to the server
 */
void reset_client() {
    segment_number = 0x00;
    seq_error = 0;
    dup_err = 0;
    end_error = 0;
    length_err = 0;
    end_id_index = 0;
}

int main(void)
{
    //struct sockaddr_in si_other;
    int i;
    //int slen=sizeof(si_other);
    char cmd[1];
    char access[1];
    int ret = 0x00;
    int start;
    int send_retry = 0;
    char *thread_data;
    int stop_on;
    int access_packet = 0;

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
     *      a: show the Access Menu
     *          0: good subscriber
     *          1: Subscriber has not payed
     *          2: Subscriber number not found
     *          3: Technology mismatch
     *      n: exit
     */
    memset(cmd,'\0', 1);
    memset(access,'\0', 1);
    printf("Send packets to server?: (g/b/a/n) ");
    printf("\n\tg: 5 good packets\n\tb: 1 good 4 bad packets\n\ta: access menu\n\tn: exit client\n\t");

    gets(cmd);
    
    // parse cmd
    if (strcmp((const char *)cmd, "n") == 0)
    {
        printf("Terminating client\n");
        exit(0);
    }
    else if (strcmp((const char *)cmd, "g") == 0)
    {
        printf("Sending 5 Good packets..\n");
        stop_on = 0x04;
    }
    else if (strcmp((const char *)cmd, "b") == 0)
    {
        printf("Sending 1 Good and 4 Bad packets..\n");
        stop_on = 0x04;
    }
    else if (strcmp((const char *)cmd, "a") == 0)
    {
        printf("\tAccess Menu: (0/1/2/3) \n");
        
        printf("\t\t0: Good Subscriber\n\t\t1: Subscriber has not payed\n\t\t2: Subscriber number not found\n\t\t3: Technology mismatch\n\t\t");
        
        gets(access);
        
        stop_on = 0x00;
        access_packet = 1;
    }

    /*
     * THIS IS THE START OF A SESSION.
     * THE SESSION ENDS WHEN THE EXIT PACKET IS SENT
     */
NEW_SESSION:
    while(1)
    {
        // sleep
        sleep(2);

        // 0x04 for DATA, 0x00 for ACCESS
        if (segment_number > stop_on)
        {
            printf("Stop sending packets.\n");
            break;
        }
        

        if (strcmp((const char *)cmd, "g") == 0 || strcmp((const char *)cmd, "b") == 0)
        {
            stop_on = 0x04;

            // make a DATA packet
            memset(message,'\0', BUFLEN);
	        make_data_packet(client_id, segment_number, TWENTYTHREEBYTES, message);
	    
	        // inject packet errors
	        if (strcmp((const char *)cmd, "b") == 0)
	        {
	            inject_data_error(segment_number);
	        }
	        
	        printf("------------------------------------------------\n");
	        printf("Sending packet segment: %02x\n", message[5]);
	        print_header(message, (TWENTYTHREEBYTES + 9), "Data Packet:\n");
        }
        else
        {
            stop_on = 0x00;
            printf("------------------------------------------------\n");
            if (strcmp((const char *)access, "0") == 0)
            {
                // Good Subscriber
                // 408-680-8821 - paid
                printf("ACCESS - good subscriber case\n");
                technology = 02;
	            sub_number[0] = 0xF3;
                sub_number[1] = 0x97;
                sub_number[2] = 0xC0;
                sub_number[3] = 0xF5;
            }
	        else if (strcmp((const char *)access, "1") == 0)
	        {
	            // Subscriber has not payed
	            // 408-666-8821 - not paid
	            printf("ACCESS - Subscriber not paid case\n");
	            technology = 03;
	            sub_number[0] = 0xF3;
                sub_number[1] = 0x95;
                sub_number[2] = 0x9E;
                sub_number[3] = 0x15;
	        }
	        else if (strcmp((const char *)access, "2") == 0)
	        {
	            // Subscriber number not found
	            // 408-554-9999 - paid
	            printf("ACCESS - Subscriber number not found case\n");
	            technology = 04;
	            sub_number[0] = 0xF3;
                sub_number[1] = 0x84;
                sub_number[2] = 0x8B;
                sub_number[3] = 0xAF;
	        }
	        else if (strcmp((const char *)access, "3") == 0)
	        {
	            //  Technology mismatch
	            // 408-554-6805 - paid
	            printf("ACCESS - Acc_Perm due to technology mismatch case\n");
                technology = 02;
	            sub_number[0] = 0xF3;
                sub_number[1] = 0x84;
                sub_number[2] = 0x7F;
                sub_number[3] = 0x35;
	        }
	        
	        // make an ACCESS packet
            memset(message,'\0', BUFLEN);

	        make_access_packet(client_id, segment_number, technology,
	            sub_number, message);

            printf("------------------------------------------------\n");
	        printf("Sending packet segment: %02x\n", message[5]);
	        print_header(message, FOURTEENBYTES, "Access Packet:\n");
        }

	    // send the packet: DATA or ACCESS
	    if (sendto(s, message, BUFLEN , 0 , (struct sockaddr *) &si_other, slen)==-1)
        {
            die("sendto()");
        }

        //receive a reply and print it
        //clear the buffer by filling null, it might have previously received data
        memset(buf,'\0', REJECTBUFLEN);

        /*
         * This is the start of the ack_timer implementation
         *  1. call setitimer() which is setup to call sighdlr() when TIMEOUT expires.
         *     setitimer() does not block as the timer counts, execution immediately
         *     continues to the pthread_create() call
         *  2. pthread_create() creates a thread that calls dowork() in the new thread.
         *     dowork() itself makes the recvfrom() blocking call. Excecution in the
         *     new thread does not continue until recvfrom() returns. pthread_create()
         *     returns immediately.
         *  3. pthreadblock_join() waits until the new thread is done on its own or
         *     is killed.
         */
        // start itimer
        setitimer( ITIMER_REAL, &itv, NULL );
        
        // call recvfrom() in dowork()
        printf("-pre pthread_create\n");
        if(pthread_create(&thread, NULL, dowork, NULL) != 0)
        {
            die("pthread_create()");
        }

        //If the target thread was canceled, then PTHREAD_CANCELED is placed in *retval.
        void *retval;
        pthread_join(thread, &retval);
        //printf("-post pthread_join - retval: %d\n", (int)retval);
        printf("-post pthread_join\n");
 
        /*
         * we don't get to here until the new thread exits
         */
        // print reply packet
	    print_header(buf, REJECTBUFLEN, "Reply Packet:");
	    
	    /*
	     * if empty reply buf, retry 3 times. exit session
	     * if no ACK packet after 3 tries
	     */
	    if ((unsigned char)buf[0] == 0x00)
	    {
	        printf("ACK timed out...\n");
	        if (send_retry < SENDRETRYS)
	        {
	            printf("Re-send packet with segment: %d\n", segment_number);
	            send_retry++;
	            continue;
	   
	        } else {
	            printf("Server does not respond\n");
	            break;
	        }
	    }

        /*
         * we're here because we got an ACK packet
         */
	    // check the reply packet:
	    //      0x1N => invalid packet
	    //      0x0N => valid packet ack or reject.
	    ret = check_packet(buf);
	    //printf("check_packet ret: %02x  &0x10: %02x\n", ret, (ret & 0x10));

        // will remove this code later
	    if ((ret & 0x10) == 0x10)
	    {
	        //printf("post check_packet - Invalid Replay packet\n");
	    }
	 
	    if ((ret & 0x0f) == 0x00)
	    {
	        //printf("post check_packet - ACK Packet\n");
	        
	        // check access codes
	        if ((unsigned char)buf[3] == 0xff &&
	            (unsigned char)buf[4] == 0xfb)
	        {
	            printf("ACCESS REPLAY: Access_OK\n");
	        }
	        else if ((unsigned char)buf[3] == 0xff &&
	            (unsigned char)buf[4] == 0xf9)
	        {
	            printf("ACCESS REPLAY: not paid\n");
	        }
	        else if ((unsigned char)buf[3] == 0xff &&
	            (unsigned char)buf[4] == 0xf8)
	        {
	            printf("ACCESS REPLAY: technology mismatch\n");
	        }
	        else if ((unsigned char)buf[3] == 0xff &&
	            (unsigned char)buf[4] == 0xfa)
	        {
	            printf("ACCESS REPLAY: number not found\n");
	        }
	    }
	    else
	    {
	        //printf("post check_packet - REJECT Packet\n");
	    }
	    
	    /*
	     * this is where we report the REJECT errors
	     */
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
    
    /*
     * THIS IS THE END OF A SESSION.
     * WE SEND THE EXIT PACKET TO LET THE
     * SERVER KNOW TO RESET ITS STATE FOR
     * A POSSIBLE NEW SESSION.
     */

    // send a final EXIT packet to reset the server
    memset(message,'\0', BUFLEN);
    segment_number = 0x00;
    make_data_packet(client_id, segment_number, TWENTYTHREEBYTES, message);
    message[5] = segment_number;
    message[4] = EXIT;
    printf("sending exit packet...\n");
    if (sendto(s, message, BUFLEN , 0 , (struct sockaddr *) &si_other, slen)==-1)
    {
        die("sendto()");
    }
    
    /*
     * Ask the user if a new session should be started, or
     * if to exit the client.
     */
    printf("\nNew Session?: (g/b/a/n) ");
    gets(cmd);
    if (strcmp((const char *)cmd, "n") == 0)
    {
        printf("Terminating client\n");
        
        exit(0);
    }
    else if (strcmp((const char *)cmd, "g") == 0)
    {
        printf("Sending 5 Good packets..\n");
        reset_client();

        goto NEW_SESSION;
    }
    else if (strcmp((const char *)cmd, "b") == 0)
    {
        printf("Sending 1 Good  and 4 Bad packets..\n");
        reset_client();

        goto NEW_SESSION;
    }
    else if (strcmp((const char *)cmd, "a") == 0)
    {
        printf("\tAccess Menu: (0/1/2/3) \n");
        
        printf("\t\t0: Good Subscriber\n\t\t1: Subscriber has not payed\n\t\t2: Subscriber number not found\n\t\t3: Technology mismatch\n\t\t");
        
        gets(access);
        
        goto NEW_SESSION;
    }

    close(s);
    return 0;
}
