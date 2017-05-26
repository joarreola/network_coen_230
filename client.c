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
int send_retry = 0;
int good_packet = 0;
struct sockaddr_in si_other;
int slen=sizeof(si_other);
pthread_t thread;
char sub_number[4];
int technology;
char cmd[1];
char access_in[1];
char bad[3];
char bad_temp[3];
char seg[1];
int stop_on;
int access_packet = 0;
int bad_packet = 0;

// functions
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
            printf("check_packet - Packet type: DATA ACK\n");
            data_ack_packet = 1;
            reject_subcode = 0x00;
        }
        else if ((unsigned char)buf[4] >= 0xf8 && (unsigned char)buf[4] <= 0xfb)
        {
            printf("check_packet - Packet type: ACCESS\n");
            access_ack_packet = 1;
            reject_subcode = 0x00;

            goto ACCESS_PACKET;
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
            printf(" Reject Packet Sub-code: Out of sequence segment\n");
            reject_subcode = 0x04;
        }
        if ((unsigned char)buf[6] == 0xf5)
        {
            printf(" Reject Packet Sub-code: Length misatch\n");
            reject_subcode = 0x05;
        }
        if ((unsigned char)buf[6] == 0xf6)
        {
            printf(" Reject Packet Sub-code: End of packet missing\n");
            reject_subcode = 0x06;
        }
        if ((unsigned char)buf[6] == 0xf7)
        {
            printf(" Reject Packet Sub-code: Duplicate packet\n");
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
ACCESS_PACKET:

    if (access_ack_packet && (unsigned char)buf[4] == 0xfb)
    {
        printf("check_packet - ACCESS ACK packet: Good Subscriber\n");
        invalid_packet = 0x10;
    }
    
    if (access_ack_packet && (unsigned char)buf[4] == 0xfa)
    {
        printf("check_packet - ACCESS ACK packet: Subscriber not found\n");
        invalid_packet = 0x10;
    }
    
    // check length is 0x05
    if (access_ack_packet && (unsigned char)buf[4] == 0xf9)
    {
        printf("check_packet - ACCESS ACK packet: Subscriber has not paid\n");
        invalid_packet = 0x10;
    }

    // check technology: 0x02 for 2G
    if (access_ack_packet && (unsigned char)buf[4] == 0xf8)
    {
        printf("check_packet - ACCESS ACK packet: Subscriber has permission issues\n");
        invalid_packet = 0x10;
    }
/*
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
*/
   /*
    * END OF ACCESS PACKET ONLY
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
 *  Inject errors per Assignment 1 requirements to a DATA packet
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
 * Call this if using the bad-menu user interface
 *
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
void inject_data_error_menu(char bad[]) {
    printf("- inject_data_error - bad: %s\n", bad);

    char *c = strtok(bad, " ");
    char *s = strtok(NULL, " ");
    int condition = atoi(c);
    int segment = atoi(s);
    printf("- inject_data_error - condition: %d segment: %d\n", condition, segment);

    printf("------------------------------------------------\n");

    if (condition == 0)
    {
        // send a good packet
        printf("Good packet with segment: %d\n", segment);
        message[5] = segment; 
        good_packet = 1;
    }

    else if (condition == 1)
    {
        // change segment number field to 2
        printf("Create Out Of Sequence condition with segment: %d\n", segment);
        message[5] = segment;
        seq_error = 1;
    }
    else if (condition == 2)
    {
        // missing end of packet id
        printf("Create Missing End Of Packet ID condition with segment: %d\n", segment);
        message[5] = segment;
        message[end_id_index] = 0x00;
        end_error = 1;
    }
    else if (condition == 3)
    {
        // duplicate packet
        printf("Create Duplicate Packet condition with segment: %d\n", segment);
        message[5] = segment;
        dup_err = 1;
    }
    else if (condition == 4)
    {
        // length field value is greater that actual payload
        printf("Create Length Mismatch condition with segment: %d\n", segment);
        message[5] = segment;
        message[6] = 0xff;
        length_err = 1;
    }
    
}

void inject_access_error(char access[]) {
    
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
    send_retry = 0;
    good_packet = 0;
}

/*
 * Send an exit packet to reset the sever state
 */
void send_exit() {
    memset(message,'\0', BUFLEN);
    segment_number = 0x00;
    make_data_packet(client_id, segment_number, TWENTYTHREEBYTES, message);
    message[5] = segment_number;
    message[4] = EXIT;
    
    // keep server state to do the out of sequence case
    printf("sending exit packet...\n");
    if (sendto(s, message, BUFLEN , 0 , (struct sockaddr *) &si_other, slen) ==-1)
    {
        die("sendto()");
    }
}

/*
 * get users input:
 *      g: send 5 good packets automatically
 *
 *      b: send 1 good and 4 bad
 *  or
 *      b: show bad packets Menu: enter option, then segment number
 *          0: good single packet
 *              seg: segment number
 *          1: Out Of Sequence condition
 *              seg: segment number
 *          2: Missing End Of Packet ID condition
 *              seg: segment number
 *          3: Duplicate Packet condition
 *              seg: segment number
 *          4: Length Mismatch condition
 *              seg: segment number
 *
 *      a: show the Access Menu
 *          0: good subscriber
 *          1: Subscriber has not payed
 *          2: Subscriber number not found
 *          3: Technology mismatch
 *
 *      n: exit
 */
void top_menu() {
    
    memset(cmd,'\0', 1);
    memset(access_in,'\0', 1);
    memset(bad,'\0', 3);
    memset(bad_temp,'\0', 3);
    
    printf("Send packets to server?: (g/b/a/n) ");
    printf("\n\tg: 5 good packets\n\tb: bad packets menu\n\ta: access menu\n\tn: exit client\n\t");

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
        printf("Sending 1 Good and 4 bad packets..\n");
        //printf("\tBad Menu: (0/1/2/3/4) (segment) \n");
        //printf("\t\t0: good single packet\n\t\t1: Out Of Sequence\n\t\t2: Missing End Of Packet ID\n\t\t3: Duplicate Packet\n\t\t4: Length Mismatch\n\t\t");
        //gets(bad);

        //stop_on = 0x00;
        stop_on = 0x04;
        bad_packet = 1;
    }
    else if (strcmp((const char *)cmd, "a") == 0)
    {
        printf("\tAccess Menu: (0/1/2/3) \n");
        
        printf("\t\t0: Good Subscriber\n\t\t1: Subscriber has not payed\n\t\t2: Subscriber number not found\n\t\t3: Technology mismatch\n\t\t");
        
        gets(access_in);
        
        stop_on = 0x00;
        access_packet = 1;
    }
}

/*
 * Ask the user if a new session should be started, or
 * if to terminate the client.
 */
int bottom_menu() {
 
    if (access_packet) {
        goto ACCESS;
    }
    printf("\nNew Session?: (g/b/a/n) ");
    segment_number = 0;
    gets(cmd);
    
    if (strcmp((const char *)cmd, "n") == 0)
    {
        printf("Terminating client\n");
        send_exit();
    
        return(0);
        
    }
    else if (strcmp((const char *)cmd, "g") == 0)
    {
        printf("Sending 5 Good packets..\n");
        reset_client();
        send_exit();

        return(1);
    }
    else if (strcmp((const char *)cmd, "b") == 0)
    {
        printf("Sending 1 Good  and 4 Bad packets..\n");
        reset_client();
        send_exit();

        //printf("\tBad Menu: (0/1/2/3/4) (segment) \n");
        //printf("\t\t0: good single packet\n\t\t1: Out Of Sequence\n\t\t2: Missing End Of Packet ID\n\t\t3: Duplicate Packet\n\t\t4: Length Mismatch\n\t\t");
        //gets(bad);

        /* for bad menu
        stop_on = 0x00;
        //bad_packet = 1;
        printf("length_err: %d seq_error: %d good_packet: %d\n",
            length_err, seq_error,good_packet);
        if (length_err) {
            reset_client();
            send_exit();
            seq_error = 0;
            good_packet = 0;
            length_err = 1;
        }
        */

        return(1);
    }
    else if (strcmp((const char *)cmd, "a") == 0)
    {
        
ACCESS:
        printf("\tAccess Menu: (0/1/2/3/4) \n");
        
        printf("\t\t0: Good Subscriber\n\t\t1: Subscriber has not payed\n\t\t2: Subscriber number not found\n\t\t3: Technology mismatch\n\t\t4: Exit access menu\n\t\t");
        
        gets(access_in);
        
        reset_client();
        send_exit();
        if (strcmp((const char *)access_in, "4") == 0) {
            access_packet = 0;
            segment_number = 2;
        }
        return(1);
    }
}


/*
 * - Control loop is implemented in the main function after taking in
 *    user input:
 *
 *      - check if segment_number is above the stop_on value. 0 for cmd a and b, 4 for g.
 *        break out of the loop if so.
 *
 *      - if cmd g: create a data packet via make_data_packet(), goto send packet
 *      - if cmd b: create a data packet via make_data_packet(), parse bad
 *        menu input, go to send packet
 *      - if cmd a: create an access packet via make_access_packet(), parse
 *        access menu input, go to send packet
 *
 *      - send the packet
 *
 *      - the recvfrom() will be called in a separate pthread. Setup:
 *
 *          - call setitimer() to tick for 3 seconds. It sends an alarm signal
 *              to the sighdlr() function
 *          - create the pthread with a dowork function argument
 *          - recvfrom() call is made in the dowork() function
 *          - when the sighdlr() function receives the alarm signal from setitimer,
 *              it calls pthread_cancel() to kill the pthread
 *          - programm execution will continue after the pthread_join() call
 *          - Call sequence:
 *
 *              setitimer() -> sends alarm signal to sighdlr after 3sec
 *                          sighdlr() kills pthread if still alive
 *              pthread_create(..dowork..) -> recvfrom() called from dowork()
 *              pthread_join <- wait for pthread to exit
 *              ... program exec continues here ...
 *
 *
 *      - Implement the ACK timed out mechanism. Retry max of 3. Go to to
 *        of loop on each.
 *      
 *      - Inspect the reply packet via check_packet()
 *
 *      - increment segment_number
 *  
 * - Request user input as done before entering the loop. Add client and server
 *   code as needed. Re-enter the contol loop is requested by user.
 *
 */
int main(void)
{
    int i;
    int ret = 0x00;
    int start;
    char *thread_data;

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
 
    // get initial user input
    top_menu();

    /*
     * THIS IS THE START OF A SESSION.
     * THE SESSION ENDS WHEN THE EXIT PACKET IS SENT
     */
NEW_SESSION:

    while(1)
    {
        // sleep
        sleep(2);

        // 0x04 for DATA, 0x00 for ACCESS, 0x00 for BAD
        if (segment_number > stop_on)
        {
            printf("Stop sending packets.\n");
            break;
        }
        

        if (strcmp((const char *)cmd, "g") == 0)
        {
            stop_on = 0x04;

            // make a DATA packet
            memset(message,'\0', BUFLEN);
	        make_data_packet(client_id, segment_number, TWENTYTHREEBYTES, message);
	        
	        printf("------------------------------------------------\n");
	        printf("Sending packet segment: %02x\n", message[5]);
	        print_header(message, (TWENTYTHREEBYTES + 9), "Data Packet:\n");
        }
        else if (strcmp((const char *)cmd, "b") == 0)
        {
            //stop_on = 0x00;
            stop_on = 0x04;

            // bad-menu
            // validate bad[3] input: N-space-N. size of 3
            //if (!bad[1]) {
            //    printf("Error: Missing segment portion. Aborting client.\n");
            //    
            //    exit(1);
            //}
            // make a DATA packet
            memset(message,'\0', BUFLEN);
	        make_data_packet(client_id, segment_number, TWENTYTHREEBYTES, message);
	    
	        // bad menu?
	        // inject packet errors per bad: (condition) (segment)
	        if (send_retry) {
	            bad[0] = bad_temp[0];
	            bad[1] = bad_temp[1];
	            bad[2] = bad_temp[2];
	        }
	        else if (send_retry == 0) {
	            bad_temp[0] = bad[0];
	            bad_temp[1] = bad[1];
	            bad_temp[2] = bad[2];
	        }
	        // bad menu
	        //printf("bad before inject_data_error - bad: %s\n", bad_temp);
            inject_data_error(segment_number);
	        
	        printf("------------------------------------------------\n");
	        printf("Sending packet segment: %02x\n", message[5]);
	        print_header(message, (TWENTYTHREEBYTES + 9), "Data Packet:\n");
        }
        else
        {
            stop_on = 0x00;
            printf("------------------------------------------------\n");
    
            // inject_access_error sets segment_number based on access
            inject_access_error(access_in);
	        
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
        if(pthread_create(&thread, NULL, dowork, NULL) != 0)
        {
            die("pthread_create()");
        }

        //If the target thread was canceled, then PTHREAD_CANCELED is placed in *retval.
        void *retval;
        pthread_join(thread, &retval);

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
	            printf("\n\nServer does not respond\n");
	            break;
	        }
	    }

	    // check the reply packet:
	    //      0x1N => invalid packet
	    //      0x0N => valid packet ack or reject.
	    ret = check_packet(buf);
	    
        /*
         * this is where we report the REJECT errors
         * Comment out if re-implementing the bad-menu UI
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

    // another sessions?
    if (bottom_menu()) {
    
        goto NEW_SESSION;
    }

    close(s);
    return 0;
}
