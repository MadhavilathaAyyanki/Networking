

Execution process of the python program:
* In order to run the program with the input directory file that has the user information, the file has to be placed in a specific path and that path has to be provided to the respective file name. 
* After providing the path, user selection is required and both sender and receiver input names are to be provided as asked by the program and gets the user information automatically like hostname, ip address and port. 
* Connection will be established between the sender and the receiver once after the contacts have been selected using the socket libraries that are available in python where one of the users accepts and connects with the other user. 
* Once the connection is established, the client i.e., the user who sends a message first and the other user will be the server and vice-versa. 
Ensuring that per-to-peer connection is established, based on four phases that are mentioned as: Diffie Hellman Key Exchange algorithm, CHAP authentication, Text message and finally ACK or NACK when there is an error like CRC check or HMAC verification. 
* User A sends his username in the message body and also his public key to User B and receives it.

Note: From this phase, both CRC and hmac_val in the PDU will be validated and respective NACK message will be sent if it fails.
For testing NACK, please go to the file (Networking_Code.py) and find message_crc_val == crc (in place of crc, please provide a dummy value (say any number from 0 to 10), so that the comparison will fail and NACK message will be sent.

* The server which is User B in our case, sends a PDU challenge, then User A sends a response back to User A and hmac value will also be validated. 
* Server sends again challenge to Client and the process is repeated.
* Sever sends acknowledgement  ack  to client if the values of crc and hmac are matched.
* Sever sends  nack  to client if the values of crc and hmac are not matched.
* Once acknowledgement  ack  has been received, user can send message and if  nack  is received, the connection terminates only if there is a timeout for more than 25 secs. 
* If validation is successful, client can send message (eg. hello) to the server and the server sends a  ack  response to the client. 
* The same process continues till one of the user tries to close the connection or a socket. 

