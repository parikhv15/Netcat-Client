#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fstream>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>

using namespace std;

#define BUF_LEN 1024
#define HASHLEN 20
/** Warning: This is a very weak supplied shared key...as a result it is not
 * really something you'd ever want to use again :)
 */
static const char key[16] = { 0xfa, 0xe2, 0x01, 0xd3, 0xba, 0xa9,
                              0x9b, 0x28, 0x72, 0x61, 0x5c, 0xcc, 0x3f, 0x28, 0x17, 0x0e
                            };

/**
 * Structure to hold all relevant state
 **/
typedef struct nc_args
{
    struct sockaddr_in destaddr; //destination/server address
    unsigned short port; //destination/listen port
    unsigned short listen; //listen flag
    int n_bytes; //number of bytes to send
    int offset; //file offset
    int verbose; //verbose output info
    int message_mode; // retrieve input to send via command line
    char * message; // if message_mode is activated, this will store the message
    char * filename; //input/output file
} nc_args_t;


/**
 * usage(FILE * file) -> void
 *
 * Write the usage info for netcat_part to the give file pointer.
 */
void usage(FILE * file)
{
    fprintf(file,
            "netcat_part [OPTIONS]  dest_ip [file] \n"
            "\t -h           \t\t Print this help screen\n"
            "\t -v           \t\t Verbose output\n"
            "\t -m \"MSG\"   \t\t Send the message specified on the command line. \n"
            "                \t\t Warning: if you specify this option, you do not specify a file. \n"
            "\t -p port      \t\t Set the port to connect on (dflt: 6767)\n"
            "\t -n bytes     \t\t Number of bytes to send, defaults whole file\n"
            "\t -o offset    \t\t Offset into file to start sending\n"
            "\t -l           \t\t Listen on port instead of connecting and write output to file\n"
            "                \t\t and dest_ip refers to which ip to bind to (dflt: localhost)\n"
           );
}

/**
 * Given a pointer to a nc_args struct and the command line argument
 * info, set all the arguments for nc_args to function use getopt()
 * procedure.
 *
 * Return:
 *     void, but nc_args will have return results
 **/
void parse_args(nc_args_t * nc_args, int argc, char * argv[])
{
    int ch;
    struct hostent * hostinfo;
    //set defaults
    nc_args->n_bytes = 0;
    nc_args->offset = 0;
    nc_args->listen = 0;
    nc_args->port = 6767;
    nc_args->verbose = 0;
    nc_args->message_mode = 0;

    while ((ch = getopt(argc, argv, "lm:hvp:n:o:")) != -1)
    {
        switch (ch)
        {
        case 'h': //help
            usage(stdout);
            exit(0);
            break;
        case 'l': //listen
            nc_args->listen = 1;
            break;
        case 'p': //port
            nc_args->port = atoi(optarg);
            break;
        case 'o'://offset
            nc_args->offset = atoi(optarg);
            break;
        case 'n'://bytes
            nc_args->n_bytes = atoi(optarg);
            break;
        case 'v':
            nc_args->verbose = 1;
            break;
        case 'm':
            nc_args->message_mode = 1;
            nc_args->message = (char*)malloc(strlen(optarg)+1);
            strncpy(nc_args->message, optarg, strlen(optarg)+1);
            break;
        default:
            fprintf(stderr,"ERROR: Unknown option '-%c'\n",ch);
            usage(stdout);
            exit(1);
        }
    }
    argc -= optind;
    argv += optind;

    if (argc < 2 && nc_args->message_mode == 0)
    {
        fprintf(stderr, "ERROR: Require ip and file\n");
        usage(stderr);
        exit(1);
    }
    else if (argc != 1 && nc_args->message_mode == 1)
    {
        fprintf(stderr, "ERROR: Require ip send/recv from when in message mode\n");
        usage(stderr);
        exit(1);
    }

    if(!(hostinfo = gethostbyname(argv[0])))
    {
        fprintf(stderr,"ERROR: Invalid host name %s",argv[0]);
        usage(stderr);
        exit(1);
    }

    nc_args->destaddr.sin_family = hostinfo->h_addrtype;
    bcopy((char *) hostinfo->h_addr,
          (char *) &(nc_args->destaddr.sin_addr.s_addr),
          hostinfo->h_length);

    nc_args->destaddr.sin_port = htons(nc_args->port);

    /* Save file name if not in message mode */
    if (nc_args->message_mode == 0)
    {
        nc_args->filename = (char*)malloc(strlen(argv[1])+1);
        strncpy(nc_args->filename,argv[1],strlen(argv[1])+1);
    }
    return;
}


/**
 * Function Name: netcatServer
 * Arguements   : struct nc_args_t, char * input
 * Return type  : void
 * Description  : function to create netcat server.
 *
 *
 **/

void netcatServer(nc_args_t nc_args,char *input)
{

    char *clntDigest, *servDigest;
    unsigned int temp = 0;
    char *msg = (char*)malloc((BUF_LEN-HASHLEN)*sizeof(char));
    ofstream outputFile;
    int recvdBytes, isDataGood=0;
    struct sockaddr_in clientAddr;
    unsigned int clientAddrLength, hashlen, totalBytesRcvd=0;
    int servSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if(servSocket<0)
    {
        fprintf(stderr, "ERROR: Server socket could not be created.\n");
        exit(1);
    }

    if((bind(servSocket, (struct sockaddr*)&nc_args.destaddr, sizeof(nc_args.destaddr)))<0)
    {
        fprintf(stderr, "ERROR: The port is busy. Please try connecting to another port.\n");
        exit(1);
    }

    if((listen(servSocket, 5))<0)
    {
        fprintf(stderr, "ERROR: Some error occurred while listening to connections.\n");
        exit(1);
    }
    else
    {
        if(nc_args.verbose)
        {
            cout << "Waiting for client to Connect..." << endl;
        }

    }
    clientAddrLength = sizeof(clientAddr);

    unsigned int clientSocket = accept(servSocket, (struct sockaddr*)&clientAddr, &clientAddrLength);

    if(clientSocket < 0)
    {
        fprintf(stderr, "ERROR: Some error occurred while connecting to the client.\n");
        exit(1);
    }

    outputFile.open(nc_args.filename, ios::trunc|ios::binary);

    while((recvdBytes=recv(clientSocket, input, BUF_LEN-1,0)))
    {

        input[recvdBytes]='\0';

        clntDigest=(char*)malloc((HASHLEN+1) * sizeof(char));
        memcpy(clntDigest,  &input[strlen(input)-HASHLEN], HASHLEN);
        clntDigest[HASHLEN]='\0';

        memcpy(msg, input, strlen(input)-HASHLEN);
        msg[strlen(input)-HASHLEN]='\0';


        servDigest=(char *)malloc((HASHLEN+1) * sizeof(char));

        HMAC(EVP_sha1(),key,16,(unsigned char*)msg,strlen(msg),(unsigned char*)servDigest,&hashlen);
        temp = strlen(servDigest);

        if(strlen(servDigest) < hashlen)
        {
            while (temp < hashlen)
            {
                servDigest[temp] = (char) (temp+1);
                temp++;
            }
        }
        servDigest[HASHLEN]='\0';

        if(strcmp(clntDigest,servDigest)==0)
        {
            isDataGood=1;
            totalBytesRcvd+=recvdBytes-hashlen;
            outputFile << msg;
            outputFile.flush();
        }
        else
        {
            isDataGood=0;
            fprintf(stderr,"Data has been tampered!!.\n");
            if( remove(nc_args.filename) != 0 )
            fprintf(stderr,"Error deleting file.\n");
            break;
        }
        memset(input, 0, BUF_LEN);
        memset(clntDigest, 0, HASHLEN);
    }
    close(clientSocket);
    close(servSocket);
    outputFile.close();

    if(recvdBytes<0 || isDataGood==0)
    {
        fprintf(stderr, "ERROR: Some error occurred while receiving data from the client.\n");
        exit(1);
    }
    else
    {
            cout << "Received: " << totalBytesRcvd << " bytes" <<endl;
    }
}


/**
 * Function Name: netcatClient
 * Arguements   : struct nc_args_t
 * Return type  : void
 * Description  : function to create netcat server. Depending upon the command line arguements,
                  either data from a file or command line is sent to server.
 **/


void netcatClient(nc_args_t nc_args)
{
    int t = 0, numOfBytes=0;
    char *inputStr, *clntDigest, *msg;
    unsigned int hashlen=0;
    int bytesSent, totalbytesSent;
    int clntSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    int i=0, j=0;
    int msgLenghth=0;

    if(clntSock < 0)
    {
        fprintf(stderr, "ERROR: Socket could not be created.\n");
        exit(1);
    }


    if(connect(clntSock, (struct sockaddr*) &nc_args.destaddr, sizeof(nc_args.destaddr)) < 0)
    {
        fprintf(stderr, "ERROR: Server is not running. Connection to server was not established.\n");
        exit(1);
    }
    else
    {
        if(nc_args.verbose)
        {
            cout<<"Connected to the server..."<<endl;
        }
    }

    switch(nc_args.message_mode)
    {
        /*For message mode*/
        case 1 :
                inputStr = nc_args.message;
                numOfBytes = strlen(inputStr);
                totalbytesSent = 0;
                clntDigest=(char *)malloc(sizeof(char)*HASHLEN+1);
                msgLenghth=strlen(inputStr);
                msg = (char*)malloc(BUF_LEN * sizeof(char)); //temporary messagge buffer
                while(totalbytesSent < msgLenghth)
                {
                    while(inputStr[i]!='\0' && j<BUF_LEN-HASHLEN-1)
                    {
                        msg[j] = inputStr[i];
                        i++;
                        j++;
                    }
                    msg[j] = '\0';
                    j=0;
                    HMAC(EVP_sha1(),key,16,(unsigned char*)msg,strlen(msg),(unsigned char*)clntDigest,&hashlen);
                    clntDigest[HASHLEN]='\0';

                    strcat(msg,clntDigest);
                    bytesSent = send(clntSock,msg, strlen(msg), 0);
                    totalbytesSent = totalbytesSent+bytesSent-HASHLEN;
                }
                break;

    /*For sending file*/
        case 0 :
                unsigned int temp = 0;
                ifstream filetoSend(nc_args.filename, ios::binary);
                totalbytesSent = 0;

                filetoSend.seekg (0, filetoSend.end);
                int sizeOfFile = filetoSend.tellg();
                filetoSend.seekg (0, filetoSend.beg);

                clntDigest = (char *)malloc(sizeof(char)*(HASHLEN+1));
                inputStr = (char*) malloc(BUF_LEN*sizeof(char));

                /*Setting number of bytes and offset based on the values of -n and -o*/
                if(nc_args.n_bytes==0 && nc_args.offset==0)
                {
                    numOfBytes=sizeOfFile;
                }
                else if(nc_args.n_bytes>0 && nc_args.offset==0)
                {
                    numOfBytes=nc_args.n_bytes;
                }
                else if(nc_args.n_bytes>0 && nc_args.offset>0)
                {
                    filetoSend.seekg(nc_args.offset,ios::beg);
                    if(sizeOfFile<nc_args.offset)
                    {
                        fprintf(stderr,"ERROR: Invalid offset.\n");
                        filetoSend.close();
                        exit(1);
                    }
                    numOfBytes=nc_args.n_bytes;
                }
                else if(nc_args.n_bytes==0 && nc_args.offset>0)
                {
                    if(sizeOfFile<nc_args.offset)
                    {
                        fprintf(stderr,"ERROR: Invalid offset.\n");
                        filetoSend.close();
                        exit(1);
                    }
                    filetoSend.seekg(nc_args.offset, ios::beg);
                    numOfBytes=sizeOfFile - nc_args.offset;
                }

                /*Copying the contents of the file into the temporary buffer inputStr*/
                while(totalbytesSent<sizeOfFile && totalbytesSent<numOfBytes)
                {
                    memset(inputStr,0,BUF_LEN);
                    while(filetoSend.good() && t<BUF_LEN-HASHLEN-1 && t < numOfBytes-totalbytesSent)
                    {

                        if(!filetoSend.eof())
                        {
                            inputStr[t]=filetoSend.get();
                            t++;
                        }
                        else
                        {
                            t--;
                            break;
                        }
                    }
                    inputStr[t]='\0';
                    t=0;

                    /*Generating digest*/
                    HMAC(EVP_sha1(),key,16,(unsigned char*)inputStr,strlen(inputStr),(unsigned char*)clntDigest,&hashlen);
                    temp = strlen(clntDigest);

                    if(strlen(clntDigest) < hashlen)
                    {
                        while (temp < hashlen)
                        {
                            clntDigest[temp] = (char) (temp+1);
                            temp++;
                        }
                    }
                    clntDigest[HASHLEN]='\0';
                    strcat(inputStr,clntDigest);
                    bytesSent = send(clntSock,inputStr,strlen(inputStr), 0 );
                    totalbytesSent=totalbytesSent+bytesSent-HASHLEN;

                    if(filetoSend.eof())
                    {
                        break;
                    }
                }
                filetoSend.close();
                break;
    }
    close(clntSock);

    if(bytesSent<0)
    {
        fprintf(stderr, "ERROR: Data transmission failed.\n");
        exit(1);
    }
    else if(totalbytesSent < numOfBytes)
    {
        fprintf(stderr, "ERROR: Data transmission failed.\n");
        exit(1);
    }
    else
    {
        cout << "Data sent successfully!! " << totalbytesSent << " bytes sent."<<endl;
    }
}

int main(int argc, char * argv[])
{
    nc_args_t nc_args;
    char input[BUF_LEN];

    parse_args(&nc_args, argc, argv);

    if(nc_args.listen==1)
    {
        //call server
        netcatServer(nc_args,input);
    }
    else
    {
        //call client
        netcatClient(nc_args);
    }
}
