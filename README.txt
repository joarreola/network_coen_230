How to compile:
•	Open two terminals, one for server and one for client.  
	Go to the path where you store the Pserver.c, Pclient.c, and 
	Verification_Database.txt.
•	On the server terminal, issue the compiling command:
        # gcc -w –o server.out Pserver.c
•	On the client terminal, issue the compiling command:
        # gcc -w –pthread –o client.out Pclient.c

How to run the test:
	Start on the server terminal:
		# ./server.out
	Then go to the client terminal:
		# ./client.out

    On the client side, you will see a top menu asking for user input/choice of 
    1.	g:  For Good packet option.  This will send 5 good packets to the server.
    2.	b:  For the one good and four bad packets option.  This will send one good and 4 bad packets to the server.  The 4 bad packets are a) out of sequence, b) end of packet missing, c) duplicate packet, d) length mismatch.
    3.	a:  For Access permission option.  
            This will bring up the 2nd menu with the choice of the access types: 
                0: good subscriber
                1: Subscriber has not paid
                2: Subscriber number not found
                3: Subscriber Technology mismatch	
                n: Exit the access menu
    4.	n:  Exit/terminate/disconnect.

    On the server side, you will see the “Waiting for data from client…” message.  The server will keep listening for data from client and reply accordingly:
    •	Send “ACK PACKET” message if it’s a good packet
    •	Send “REJECT PACKET” message with sub-code if it’s a reject packet
    •	Send “ACK PACKET” and “ACCESS” packet type message with permission – Granted or Denied – after checking the received packet with a pre-defined text file named “Verification_Database.txt”
    •	Do ctrl-C to terminate the server.  Then choose any of the options on the client side to test the “ack_timer” per assignment 1.  
        The client will keep trying to send the packet every 3 seconds but get time out and after three try, will get a message “Server does not respond.”

Detail description on how the code works:

On Client side:
Start with a while loop in main() function after taking in user input: 
•	Check if segment_number is above the stop_on value: 0 for cmd a; 4 for g and b;  break out of the loop if so.
 	- If cmd g: create 5 good data packet via make_data_packet(), goto send packet
    - If cmd b: create 1 good and 4 bad data packet via make_data_packet(), goto send packet
    - If cmd a: create an access packet via make_access_packet(), parse access menu input, go to send packet

•	Send the packet
•	Call setitimer() to tick for 3 seconds. It sends an alarm signal to the sighdlr() function when the TIMOUT expires.  
    setitimer() does not block as the timer counts, execution immediately continues to the pthread_create() call.
•	pthread_create() creates a thread that calls dowork() in the new thread.  
    dowork() itself makes the recvfrom() blocking call.  
    Excecution in the original thread does not continue until recvfrom() returns.  pthread_create() returns immediately.
•	When the sighdlr() function receives the alarm signal from setitimer, it calls pthread_cancel() to kill the pthread.
•	Programm execution will continue after the pthread_join() call.
 
•	Implement the ACK timed out mechanism. Retry max of 3 times. If no reply after 3 times, print out msg “server not response.”

•	Inspect the reply packet (from server) via check_reply_packet()
•	Increment the segment_number.
 
•	Re-enter the while loop if requested by user for a new session.

On the Server side:
Start with the while loop in main() function to keep listening to data from client:
•	Check the received packet from client via check_received_packet() function and reply accordingly:
o	ACK packet for Data packet
o	REJECT with Reject sub-code
o	If ACCESS packet, call access_check() function to check for access_permission using the pre-defined text file name “Verification_Database.txt”.
•	Increment packets_received value.
•	Keep listening in while loop until receive terminate signal.
 
