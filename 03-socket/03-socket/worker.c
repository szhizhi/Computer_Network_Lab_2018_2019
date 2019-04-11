#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

typedef struct send_message{
  int filename_length;
  char locate[32];
  int start;
  int end;
} send_message;

int main(int argc, char * argv[])
{
  int s, cs;
  struct sockaddr_in master, worker;
  

  // create socket
  if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    perror("Create socket failed");
    return -1;
  }
  printf("Socket created!\n");

  // prepare the sockaddr_in structure
  worker.sin_family = AF_INET;
  worker.sin_addr.s_addr = INADDR_ANY;
  worker.sin_port = htons(12345);
     
  // bind
  if (bind(s,(struct sockaddr *)&worker, sizeof(worker)) < 0)
  {
    perror("bind failed");
    return -1;
  }
  printf("Bind done!\n");

  // listen
  listen(s, 3);
  printf ( "Waiting for incoming connectionos...\n" );
	
  // accept connection from an incoming client
  int c = sizeof(struct sockaddr_in);
  if ((cs = accept(s, (struct sockaddr *)&master, (socklen_t *)&c)) < 0)
  {
    perror("accept failed");
    return -1;
  }
  printf("Connection accepted!\n");
  
  // receive a message from master
  int msg_len = 0;
  send_message send_msg;

  while ((msg_len = recv(cs, (char*) &send_msg, sizeof(send_msg), 0)) > 0)
  {
    int i;
    char a;
    int count[26];
    FILE* file = fopen(send_msg.locate, "r");

    for(i = 0; i < 26; i++)
      count[i] = 0;
    
    fseek (file, send_msg.start, SEEK_SET);
    
    for (i = 0; i <= send_msg.end - send_msg.start && (a = fgetc(file)) != EOF; i++ )
    {
      if ( a >= 'a' && a <= 'z' )
        count[a - 'a']++;
      if ( a >= 'A' && a <= 'Z' )
        count[a - 'A']++;
    }

    write(cs, (char*) count, 104);
  }
  
  if (msg_len == 0)
    printf("Client disconnected!\n");
  else 
  { // msg_len < 0
    perror("Recv failed");
    return -1;
  }
     
  return 0;
}
