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

typedef struct ID_Node
{
	int new_id;
	int old_id;
	int fd;
	struct ID_Node *next;
}ID_Node;

typedef struct Node LinkList;
typedef struct ID_Node IDLinkList;

#define SERVER_IP	"127.0.0.1"
#define MIOT_SERVER_PORT	54322
#define DISPATCHER_SERVER_PORT	54320

#define POLL_TIMEOUT			(100)	/* 100ms */
#define MAX_POLL_FDS			50
#define MAX_CLIENT_NUM		20

#define MAX_KEY_NUM			100
#define MAX_KEY_LEN			30
#define KEY_NUM_INDEX		0

#define MIN_ID_NUM			5000
#define MAX_ID_NUM			1000000

int  miot_client_init(void);
int  dispatch_server_init(void);
int dispatcher_listen_handler(int listenfd);
int dispatcher_recv_handler_one(int sockfd, char *msg, int msg_len, int flag);

int dispatcher_recv_handler(int sockfd, int flag);
int miot_msg_handler(char *msg);
int client_msg_handler(char *msg);
int send_to_register_client(char *msg);
int upload_msg_handler(char *msg, int old_id, int fd);

Node *init_key_list(void);
int register_event(int fd,  char *key, int key_len);
int unregister_event(int fd,  char *key, int key_len);
void print_registered_event(void);

ID_Node *init_id_list(void);
int send_to_register_client(char *msg);
int send_ack_to_client(char *msg, int id);
void print_id_list(void);

#endif