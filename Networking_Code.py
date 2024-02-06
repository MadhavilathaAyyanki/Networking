import sys
import json
import base64
import zlib
import datetime
import select
import socket
import sys

from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Cipher import AES
from DiffieHellman_Keys_class import DiffieHellman
from Cryptodome.Hash import SHA256, HMAC
            
#This is the server class - which is has the functionality responsible for sending and receiving the messages to Client/another user.                 
class server_socket_conn(object):
    def func_ser(self,serv,raw_message):                   #server recives the connection here and the message
        rcv_m = (serv.recv(1024)).decode('utf-8')               # Receving the data from the connection established with the client using recv function in socket library    

        if not rcv_m:                                           # If not data is available then printing corresponding message to the user.
            False                         
        else:  
            #Using json loads to convert the message 
            dt_msg= json.loads(rcv_m)    
            # Using message decoding function to get the decoded data which was received.                         
            dt_dd_msg=message_generation().msg_decoding(dt_msg['header']['msg_type'],dt_msg)  
            
            # If the received message is text type, then send back the Ack message
            if dt_dd_msg['header']['msg_type']=='text':                  
                # serv_recv=message_generation().msg_ack('ack',raw_message)                   
                # serv_recv=(json.dumps(serv_recv)).encode('utf-8')   
                # serv_recv=message_generation().msg_ack('ack',raw_message)                   
                serv_recv=(json.dumps(message_generation().msg_ack('ack',raw_message))).encode('utf-8')
                conn.send(serv_recv)                              
            else:
                if True:
                    serv_recv=(json.dumps(dt_dd_msg)).encode('utf-8')              
                    conn.send(serv_recv)

            print(dt_dd_msg)     

#Creating a client class which has the functionality for sending and receiving the messages to Server.                 
class socket_conn_cli(object):
    def func_cli(self,cli_conn):
        #msg_client= message_generation().msg_text('text',cli_msg) 
        msg_client= message_generation().msg_tx_fn('text',raw_message)  
        msg_client_bytes=(json.dumps(msg_client)).encode('utf-8')  

        cli_conn.send(msg_client_bytes)  

        # Using Recv function to receive the incoming data from the user and decoding it
        cl_ms=(cli_conn.recv(1024)).decode('utf-8')         
        print("Received message is: ",cl_ms)    
        if not cl_ms:  #If there is no data received, then print the error message.
            print("Received no data")
            
class message_generation(object):  
      
    def user1_dh_message(self,user1_dh_message):                          
        pk_user1,Amy, pk_user2=Encrypt_Decrypt_KeyGeneration().diffiehellman()
        # Adding pub_key_user1 and username1 to 'message'
        user1_dh_message['message']={'key': pk_user1} 
        user1_dh_message['message']={'username': Amy} 
        user1_dh_message['header']['msg_type']='dh_1'
        user1_dh_message['header']['timestamp']=UTC_val
        user1_dh_message=message_generation._msg_crc(self,user1_dh_message) 
        SecureDataLogging().logg(user1_dh_message)
        return user1_dh_message

    # creating a dh2 message with required alues to be assigned in the message
    def _user2_message_dh2(self,msg_dh2):                         
        pk_user1,Alex, pk_user2=Encrypt_Decrypt_KeyGeneration().diffiehellman()
        msg_dh2['header']['timestamp']=UTC_val
        msg_dh2['header']['msg_type']='dh_2'
        msg_dh2['message']={'key': pk_user2}     
        msg_dh2=message_generation._msg_crc(self,msg_dh2) 
        SecureDataLogging().logg(msg_dh2) 
        return msg_dh2            
    
    #Creating a message with proper values in it with respect to message_type 'hello'
    def hello_message(self,message_hello):            
        message_hello['header']['timestamp']=UTC_val 
           
        message_hello['message']=None
        
        del message_hello['header']['crc'] 
        message_hello['header']['msg_type']='hello'
        message_hello=message_generation._msg_crc(self,message_hello) 
        message_hello=Encrypt_Decrypt_KeyGeneration().hmac_key_gen(self,message_hello)     
        
        SecureDataLogging().logg(message_hello)
        return message_hello               #Returns corresponding message
    
    #This function is used to create a message w.rt message_type 'challenge1'
    def msg_chall1(self,message_chall1):  
        message_chall1['message']=None                      
        del message_chall1['header']['crc'] 
        message_chall1['header']['msg_type']='chall'    
        # message_chall1,chap=Encrypt_Decrypt_KeyGeneration().keyGeneration_for_challenge(self,message_chall1)    
        message_chall1=Encrypt_Decrypt_KeyGeneration().keyGeneration_for_challenge(self,message_chall1)
        message_chall1=message_generation.crc_message(self,message_chall1) 
        SecureDataLogging().logg(message_chall1)
        return message_chall1       
    
    #This function is used to create a message w.rt message_type 'response1'
    def _msg_rsp1(self,resp_msg):           
        del resp_msg['header']['crc']  

        resp_msg['message']=None
        resp_msg['header']['msg_type']='resp'   
        
        resp_msg=Encrypt_Decrypt_KeyGeneration().keyGeneration_for_response(self,resp_msg)
        resp_msg=message_generation.crc_message(self,resp_msg)
     
    #This function is used to create cyclic redundency check values for input message, updates the value and returns the message.  
    def _msg_crc(self,crc_message):                     
        #after getting the message file the parameter needs to be dumped  for getting and updating the crc value
        crc_message_bytes=(json.dumps(crc_message)).encode('utf-8')   
        crc=zlib.crc32(crc_message_bytes) 
        crc_message['header']['crc']=crc               
        SecureDataLogging().logg(crc_message)
        return crc_message
    
    #Responsible for creating a message by doing updates/deletes with proper values in it with respect to message_type 'text' 
    def msg_tx_fn(self,message_ty,message_tt):                      
        inp_msg= input()
        del message_tt['header']['crc']
        message_tt['message']=inp_msg
        message_tt['header']['timestamp']=UTC_val  
        message_tt['header']['msg_type']=message_ty           
                      
        message_tt=Encrypt_Decrypt_KeyGeneration().hmac_key_gen(message_tt)
        message= base64.b64encode(str(message_tt['message']).encode('utf-8')).decode('utf-8')   
        message_tt['message']=message      
        message_tt=message_generation._msg_crc(self,message_tt)                                          
        SecureDataLogging().logg(message_tt)
        return message_tt  
    
    #Mainly used for encoding the text message and check crc for it.
    def msg_decoding(self,msg_type,msg_dcd):     
        if msg_type.__eq__('text'):
            msg_crc_val=msg_dcd['header']['crc']
            del msg_dcd['header']['crc']
            actual_crc=zlib.crc32((json.dumps(msg_dcd)).encode('utf-8'))
            msg_dcd['message']= (base64.b64decode(msg_dcd['message'])).decode('utf-8')
          
            if msg_crc_val == actual_crc:            

                msg_dcd['header']['crc']=actual_crc
                msg_dcd['header']['timestamp']=UTC_val 
                print("crc validation check successful") 
            else:
                
                msg_dcd=message_generation.msg_nack(self,'nack',msg_dcd)
            Encrypt_Decrypt_KeyGeneration().st_msg_de_fn(msg_dcd)            #Calling the decryption which validates the hmac value received in the message format from another user.
            SecureDataLogging().logg(msg_dcd)

            return msg_dcd
        return msg_dcd 
    
    #Responsible for creating a message with proper values in it with respect to message_type 'ack', this triggers when a message is received successfully.
    def msg_ack(self,message_type,message_ack):            
        message_ack['message']='None'
        del message_ack['header']['crc']
        message_ack['header']['timestamp']=UTC_val
        message_ack['header']['msg_type']=message_type   
        message_ack=Encrypt_Decrypt_KeyGeneration().hmac_key_gen(message_ack)
        message_ack=message_generation._msg_crc(self,message_ack) 
        SecureDataLogging().logg(message_ack)
        return message_ack
    
    #Responsible for creating a message with proper values in it with respect to message_type 'nack', this triggers when a CRC value in the message is invalid and also when hmac value validation failed.
    def msg_nack(self,message_type,message_nack):
        message_nack['message']='None' 
        message_nack['header']['timestamp']=UTC_val         
        message_nack['header']['msg_type']=message_type   
        message_nack=Encrypt_Decrypt_KeyGeneration().hmac_key_gen(message_nack)
        message_nack=message_generation._msg_crc(self,message_nack)
        SecureDataLogging().logg(message_nack)
        return message_nack
    
#Creating a class to Log all the data message in a log file in always append mode.
class SecureDataLogging(object):
    def logg(self,message):
        # log file creation and mode is set to append
        with open('/home/ayyankid/h-drive/Networking_Code/Networking_Code/std_output.log', 'a+') as item:  
            item.write('\n')
            # Adding Text message heading before loading the message if the type is text.
            if message['header']['msg_type']=='text':    
                item.write('Text message:')
                item.write('\n')
            
            # Adding Text message heading before loading the message if the type is ack.
            elif message['header']['msg_type']=='nack':
                item.write('Nack message:')
                item.write('\n')

            # Adding Text message heading before loading the message if the type is ack.
            elif message['header']['msg_type']=='ack':
                item.write('Ack message:')
                item.write('\n')

            item.write(json.dumps(message))
            item.write('\n')
            item.close()          
  
class Encrypt_Decrypt_KeyGeneration(object):
    def keyGeneration_for_response(self,message):
        chap_secret=SHA256.new()
        return message, chap_secret
    
    def keyGeneration_for_challenge(self,message):
        chap_secret=SHA256.new()
        return message, chap_secret
 
    def diffiehellman(self):                           #Responsible for getting the A user's Public_key bytes, user name and B user's Public key in bytes
        FirstObj = DiffieHellman()
        First_public_key=FirstObj.public_key_bytes
        Second_public_key=FirstObj.public_key_bytes

        return First_public_key,user1_nm, Second_public_key
    
    # Hhis function will generate the DiffieHellman Shared secret and uses it in generating the hash value with an iv factor etc using HMAC(SHA256) technique value.
    def Hmac(self,message):     
        DH =DiffieHellman()
        prime_value,private_key,public_key,shared_secret= DH.init_function()
        #Get the user's public key bytes(32) as DH returns a fixed length shared secret of 32 byte
        DH_PKBytes=str(DH.generating_diffiehellman_shared_secret(public_key)).encode('utf-8')  

    
        _bytes_user=str(rpass).encode('utf-8')
        if True:
            val_hmac = HMAC.new(_bytes_user, DH_PKBytes, digestmod = SHA256)
            _key_encrypt = val_hmac.digest() 
            val_of_hash = SHA256.new()
            val_of_hash.update(_key_encrypt)
            if True:
                _key_iv = val_of_hash.digest()[:16] 
                val_of_hash.update(_key_iv)
                key_val_of_hmac = val_of_hash.digest()
                val_of_hash.update(key_val_of_hmac)
                if True:
                    msg_body=message['message'] 
                    val_cp = AES.new(_key_encrypt, AES.MODE_CBC, _key_iv)                 
    
        

        ct_bytes = val_cp.encrypt(pad(str(msg_body).encode('utf-8'), AES.block_size))        
        ct_HMAC = HMAC.new(key_val_of_hmac, ct_bytes, digestmod = SHA256)  
        ct_hash = ct_HMAC.digest()   # Get the bytes digest
        return ct_hash,_key_iv,DH_PKBytes,DH_PKBytes,_key_encrypt,ct_bytes,msg_body,key_val_of_hmac
        
    #Responsible for generating a hmac value for the given DiffieHellman shared key, user secret and data(body) to be hashed and place it in the message    
    def hmac_key_gen(self,message):                  
        DH =DiffieHellman()
        ct_hash,_key_iv,DHSK,DH_PKBytes,_key_encrypt,ct_bytes,msg_body,key_val_of_hmac=Encrypt_Decrypt_KeyGeneration().Hmac(message)
        hmac_val=base64.b64encode(str(msg_body).encode('utf-8')).decode('utf-8')
        # hmac_hex = binascii.hexlify(ct_by)
        # print("this is hmac key gen", type(hmac_hex))
        # hmac_val = hmac_hex.decode('utf-8') + str(ct_hs)
        message['security']['hmac']['hmac_val']=hmac_val                     #Updating the hmac val inside the Message
        return message
    
    # Function for decrypting the received HMAC value in the Message and validating HMAC value
    def st_msg_de_fn(self,message):   
        hs_ciphtt,ivkey,DHSK,DH_PKBytes,encrykey,ciptxt_byt,msg,hm_kv=Encrypt_Decrypt_KeyGeneration().Hmac(message)
       
        _de_cip = AES.new(encrykey, AES.MODE_CBC, ivkey)               
        txt_plaiin = unpad(_de_cip.decrypt(ciptxt_byt), AES.block_size)     
                                       
        hmac_chk = HMAC.new(key = hm_kv, msg = ciptxt_byt, digestmod = SHA256)
        print('plain text is: ', txt_plaiin)    
        try:
            hmac_chk.verify(hs_ciphtt)       #function for matching the received HMAC value with the hashed cipher text 
            print('HMAC check is complete and the result is positive')
        except Exception:             # Any exception will be caught and it returns a nack message.
            print('Failed HMAC Validation, so nack message will be sent')

            _msg_nack=message_generation().msg_nack(self,'nack',message)
            return _msg_nack
     
if __name__ == '__main__':
       
    diffiehellman_message={'header': {'msg_type': '', 'crc':'','timestamp':''}, 'message':{'key':'','username':''}}  #Initialse the Message which have to be passed to DH message from user1 and DH message from user2 functions
    
    raw_message = {'header': {'msg_type': '', 'crc':'','timestamp':''}, 'message':'','security':{'hmac': {'hamc_type': 'SHA256', 'hmac_val':''},'enc_type': 'AES256CBC'}} #Initialise RAW Message dictionary format to be passed to all other functions which follows the CHAP methodology and then Text and Ack messages.
    UTC_val=str(datetime.datetime.utcnow()) #Generating UTC timestamp using datetime.utcnow() function  
    
    with open('/home/ayyankid/h-drive/Networking_Code/Networking_Code/directory.json','r') as item:   #Reading the user's details from a directory file in a json format as mentioned in the requirement (path of the file will be varying accordingly)
        chrs_streip_rmv=''.join(e.strip() for e in item)
    
    usr_tb_list=eval(chrs_streip_rmv) 
    
    usr_lst=list(usr_tb_list)  
    print("The List of users in the directory are: ", usr_lst)

    user1_nm=input("Enter the first username: ") 

    # Selecting the user's Host and port, password for the values in user directory file.
    for m in range(4):                                  
        for users in usr_lst[m]: 
            if usr_lst[m]['username'] == user1_nm:
                lhost = usr_lst[m]['ip']
                lport = int(usr_lst[m]['port'])
    print(lhost," - LOCAL_HOST")
    print(lport, " - LOCAL_PORT")
                
    user2_nm=input("Enter the other username: ")       
    for m in range(4):                                   
        for users in usr_lst[m]: 
            if usr_lst[m]['username'] == user2_nm:
                rhost = usr_lst[m]['ip']
                rpass = usr_lst[m]['password']
                rport = int(usr_lst[m]['port'])
    print(rhost," - REMOTE_HOST" )
    print(rport," - REMOTE_PORT")
                
    socket_conn = socket.socket(socket.AF_INET,socket.SOCK_STREAM)    #Socket creation using the socket.socket library for the server
    
    socket_conn.bind((lhost,lport))         #Binding the Server socket to the respective HOST and LOCAL PORT
  
    print('Socket bind complete')
    socket_conn.settimeout(25)
    socket_conn.listen(5)                                             #It makes sure that it is listening to one incoming connection
    socket_conn.setblocking(False)                         #Setting the blocking to False, so that it will always allow
    rl = [socket_conn, sys.stdin]                             #Adding the server socket and sys.stdin into a read list
    
    while 1 == 1:
        # seting the Time out for the connection to close after 25 seconds
        r, w, e = select.select(rl, [], [], 25)    #Selecting the readable list accordingly. Select mainly used for pipes/pushpes, monitoring sockets and open files until they become readable or writable, or a communication error occurs.
       
        for read_conn in r:                                                                      #if read list is in server socket list, then accept the connection from server
            if read_conn == socket_conn:
                conn, addr = socket_conn.accept()
                rl.append(conn)         
            elif read_conn == sys.stdin:                                #if read list is in sys.stdin (standard input) list, then create client socket and call the connect function from client
                client_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)    
                client_sock.connect((rhost,rport))            #To establish connection between server and client
                client_socket_conn_obj = socket_conn_cli()
                client_socket_conn_obj.func_cli(client_sock)   
            else:
                try:
                    server_socket_conn_obj=server_socket_conn()
                    server_socket_conn_obj.func_ser(read_conn,raw_message)
                except socket.error as e:
                    rl.remove(read_conn)
                    
        if not (w or r or e):
            print("\nNo input provided from the party...so closing the connection!!\n")
            exit()
