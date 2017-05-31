How to compile:
•	Open two terminals, one for server and one for client.  Go to the path where you store the Pserver.c, Pclient.c, and Verification_Database.txt.
•	On the server terminal, issue the compiling command:
        # gcc Pserver.c –o server.out
•	On the client terminal, issue the compiling command:
        # gcc –pthread Pclient.c –o client.out

How to run the test:
	Start on the server terminal:
		# ./server.out
	Then go to the client terminal:
		# ./client.out

    On the client side, you will see a top menu asking for user input/choice of 
    1.	g:  For Good packet option.  This will send 5 good packets to the server.
    2.	b:  For the one good and 4 bad packets option.  This will send one good and 4 bad packets to the server.  The 4 bad packets are a) out of sequence, b) end of packet missing, c) duplicate packet, d) length mismatch.
    3.	a:  For Access permission option.  
            This will bring up the 2nd menu with the choice of the access types: 
                0: good subscriber
                1: Subscriber has not paid
                2: Subscriber number not found
                3: Subscriber Technology mismatch	
                n: Exit the access menu
    n.	Exit/terminate/disconnect.

    On the server side, you will see the “Waiting for data from client…” message.  The server will keep listening for data from client and replay accordingly:
    •	Send “ACK PACKET” message if it’s a good packet
    •	Send “REJECT PACKET” message with sub-code if it’s a reject packet
    •	Send “ACK PACKET” and “ACCESS” packet type message with permission – Granted or Denied – after checking the received packet with a pre-defined text file named “Verification_Database.txt”
    •	Do ctrl-C to terminate the server.  Then choose any of the options on the client side to test the “ack_timer” per assignment 1.  The client will keep trying to send the packet every 3 seconds but get time out and after three try, will get a message “Server does not respond.”


 * - Control loop is implemented in the main function after taking in
 *    user input:
 *
 *      - check if segment_number is above the stop_on value. 0 for cmd a and b, 4 for g.
 *        break out of the loop if so.
 *
 *      - if cmd g: create 5 good data packet via make_data_packet(), goto send packet
 *      - if cmd b: create 1 good and 5 bad data packet via make_data_packet(), goto send packet
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
 *      - Implement the ACK timed out mechanism. Retry max of 3. 
 *      - Inspect the reply packet via check_packet()
 *
 *      - increment segment_number
 *  
 * - Read user input before entering the loop. Add client and server
 *   code as needed. Re-enter the control loop if requested by user.
 */
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
	     * if empty reply buf, retry 3 times. exit session if no ACK packet after 3 tries
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
	            printf("\n\nServer does not respond.\n");
	            break;
	        }
	    }

	    // check the reply packet:
	    ret = check_packet(buf);

	    
