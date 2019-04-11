#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>

#define MAX_WORKER  16
#define MAX_IP_SIZE 16


typedef struct send_message{
  int filename_length;
  char locate[32];
  int start;
  int end;
} send_message;

char ip[MAX_WORKER][MAX_IP_SIZE];

int s[MAX_WORKER];

int recv_msg[MAX_WORKER][26];
send_message send_msg[MAX_WORKER];

struct sockaddr_in worker[MAX_WORKER];

void* submit_request(void* request)
{
  int i = * (int*)request;
  printf("Now, thread[%d] starts to work!\n", i);

  // send message
  if (send(s[i], (char*) &send_msg[i], sizeof(send_msg[i]), 0) < 0) 
    printf("send failed");

  // recv message
  if (recv(s[i], (char*) recv_msg[i], sizeof(recv_msg[i]), 0) < 0)
    printf ("recv failed!\n");
}

int main(int argc, char *argv[])
{
  int i, j, k;
  int num_worker;
  pthread_t thread[MAX_WORKER];

  if(argc < 2)
  {
    printf("Please enter the file name\n");
    return 0;
  }

  memset(ip, 0, MAX_WORKER * MAX_IP_SIZE);

  // read ip
  num_worker = 0;
  FILE * conf_file;
  if( (conf_file = fopen("workers.conf", "r"))==NULL )
  {
    printf("Open workers.conf failed!\n");
    exit(1);
  }

  char str[MAX_WORKER * MAX_IP_SIZE];
  fread(str, MAX_WORKER * MAX_IP_SIZE, 1, conf_file);

  for(i = 0, k = 0; i < MAX_WORKER; i++)
  {
    if( (str[k] != 10 || str[k] != '.') && (str[k] < '0' || str[k] > '9'))
      break;
    else
      for(j = 0; j < MAX_IP_SIZE; j++, k++)
      {
        if(str[k] == 10)
        {
          ip[i][j] = 0;
          k++;
          break;
        }
        else
          ip[i][j] = str[k];
      }
  }
  num_worker = i;
  printf("Reading workers.conf succeeds, nworkers = %d!\n", num_worker);

  // create socket
  for(i = 0; i < num_worker; i++)
    if( (s[i] = socket(AF_INET, SOCK_STREAM, 0)) < 0 )
    {
      perror("Create socket failed");
      return -1;
    }

  printf("Socket created!\n");

  // connect to workers
  for(i = 0; i < num_worker; i++)
  {
    worker[i].sin_addr.s_addr = inet_addr(ip[i]);
    worker[i].sin_family = AF_INET;
    worker[i].sin_port = htons(12345);

    if (connect(s[i], (struct sockaddr *)&worker[i], sizeof(worker[i])) < 0)
    {
      perror("connect failed");
      return 1;
    }
  }
  printf("Connected!\n");

  // count the total num
  FILE *txt;
  int total_num = 0;

  if ( !(txt = fopen(argv[1], "r")) )
  {
    printf ( "Open war_and_peace.txt failed!\n" );
    return 1;
  }

  while( (fgetc(txt)) != EOF )
    total_num++;

  fclose(txt);
  
  // submit request
  int thread_id[MAX_WORKER];
  for(i = 0; i < MAX_WORKER; i++)
    thread_id[i] = i;

  for(i = 0; i < num_worker; i++)
  {
    send_msg[i].filename_length = (int) strlen(argv[1]);

    memset(send_msg[i].locate, 0, sizeof(send_msg[i].locate));
    strcat(send_msg[i].locate, "./");
    strcat(send_msg[i].locate, argv[1]);

    send_msg[i].start = (i == 0)?  0 : total_num/3 * i + 1;
    send_msg[i].end   = (i == num_worker - 1)? total_num : total_num/3 * (i + 1);

    int *t = thread_id +i;
    if( pthread_create(&thread[i], NULL, submit_request, (void*) t) != 0)
    {
      printf("Can't create thread[%d]\n", i);
      return 1;
    }
  }

  for(i = 0; i < num_worker; i++)
    pthread_join(thread[i],NULL);

  printf("Send & Recv succeed!\n");

  // print result
  for(i = 0; i < 26; ++i)
  {
    int count = 0;

    for(j = 0; j < num_worker; j++)
      count += recv_msg[j][i];

    printf ("%c: %d\n", 'a' + i, count);
  }


  for(i = 0; i < num_worker; i++)
    close(s[i]);

  return 0;	
}
