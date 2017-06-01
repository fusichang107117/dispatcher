#ifndef __MIIO_H
#define __MIIO_H

#define SERVER_IP	"127.0.0.1"
#define MIOT_SERVER_PORT	54322
#define DISPATCHER_SERVER_PORT	54320

#define POLL_TIMEOUT			100	/* 100ms */
#define MAX_CLIENT_NUM		20
#define MAX_POLL_FDS			(MAX_CLIENT_NUM + 3)
#define MAX_BUF			4096
#define TIMER_INTERVAL		3000	/* 3s */

#define MAX_KEY_NUM			100
#define MAX_KEY_LEN			32
#define KEY_NUM_INDEX		0

#define MAX_ID_NUM			2147483647

#define VERSION			"1.0"

struct dispatcher_data
{
	struct pollfd pollfds[MAX_POLL_FDS];
	int count_pollfds;
};

typedef struct Node
{
	char key[MAX_KEY_LEN];
	int fd[MAX_CLIENT_NUM];
	struct Node *next;
}Node;

typedef struct ID_Node
{
	int new_id;
	int old_id;
	int fd;
	struct ID_Node *next;
}ID_Node;

typedef enum
{
	LOG_ERROR = 0,
	LOG_WARNING,
	LOG_INFO,
	LOG_DEBUG,
	LOG_VERBOSE,
	LOG_LEVEL_MAX = LOG_VERBOSE
} log_level_t;

typedef struct Node LinkList;
typedef struct ID_Node IDLinkList;


Node *init_key_list(void);
void free_key_list(void);

ID_Node *init_id_list(void);
void free_id_list(void);

int  miot_connect_init(void);
int  dispatch_server_init(void);

int dispatcher_listen_handler(int listenfd);
int dispatcher_recv_handler(int sockfd, int flag);
int dispatcher_recv_handler_one(int sockfd, char *msg, int msg_len, int flag);

int miot_msg_handler(char *msg, int msg_len);
int client_msg_handler(char *msg, int len, int sockfd);

int timer_setup(void);
void timer_handler(int fd);
int timer_start(int fd, int first_expire, int interval);

int record_id_map(int old_id, int new_id, int fd);
void update_id_map(int fd);

int get_event_last_node(const char *key, int key_len, Node **pNode);
int register_event(int fd,  const char *key, int key_len);
int unregister_fd_from_Node(Node *pNode, int fd);
int unregister_event(int fd,  const char *key, int key_len);
void unregister_fd(int fd);
int delete_fd_from_dispathcer(int sockfd);
void print_registered_event(void);

int send_to_register_client(char *msg, int msg_len);
int send_ack_to_client(char *msg);

void logfile_init(char *filename);
void log_printf(log_level_t level, const char *fmt, ...);

void print_id_list(void);
#endif
