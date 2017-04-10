#ifndef __MIIO_H
#define __MIIO_H

struct dispatcher_data
{
	struct pollfd pollfds[MAX_POLL_FDS];
	int count_pollfds;
};

typedef struct Node
{
	char key[MAX_KEY_LEN];
	int fd[MAX_CLIENT_LEN];
	struct Node *next;
}Node;

typedef struct Node LinkList;

#define SERVER_IP	"127.0.0.1"
#define MIOT_SERVER_PORT	54322
#define DISPATCHER_SERVER_PORT	54320

#define POLL_TIMEOUT			(100)	/* 100ms */
#define MAX_POLL_FDS			50
#define MAX_CLIENT_NUM		20

#define MAX_KEY_NUM			100
#define MAX_KEY_LEN			30
#define KEY_NUM_INDEX		0

int  dispatch_client_init(void);
int  dispatch_server_init(void);
int dispatcher_listen_handler(int listenfd);
int register_event(int fd,  char *key);
int unregister_event(int fd,  char *key);
int send_to_miot(char *msg);

#endif