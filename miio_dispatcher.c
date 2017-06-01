#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <sys/timerfd.h>
#include <assert.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdarg.h>
#include "json-c/json.h"
#include "miio_json.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include "miio_dispatcher.h"

FILE *log_file;
log_level_t g_loglevel = LOG_DEBUG;

int miot_fd, dispatch_listenfd, timer_fd;
struct dispatcher_data dispatcher;
LinkList *key_list = NULL;
IDLinkList *id_list = NULL;

static struct option options[] = {
	{"help",	no_argument,		NULL, 'h'},
	{"version",	no_argument,		NULL, 'v'},
	{"loglevel",    required_argument,      NULL, 'l'},
	{"logfile",	required_argument,      NULL, 'L'},
	{"daemonize",	no_argument,		NULL, 'D'},
	{NULL,		0,			0,	0}
};

static void sighandler(int sig)
{
	free_key_list();
	free_id_list();

	if (miot_fd >0) {
		close(miot_fd);
	}
	if(dispatch_listenfd > 0)
		close(dispatch_listenfd);

	log_printf(LOG_ERROR, "miio_dispatcher will be exit\n");
	exit(-1);
}

int main(int argc, char *argv[])
{
	int n = 0;
	int daemonize = 0;

	log_file = stdout;

	while (n >= 0) {
		n = getopt_long(argc, argv, "hDvl:L:", options, NULL);
		if (n < 0)
			continue;
		switch (n) {
			case 'D':
				daemonize = 1;
				break;
			case 'l':
				g_loglevel = atoi(optarg);
				if (g_loglevel > LOG_LEVEL_MAX)
					g_loglevel = LOG_LEVEL_MAX;
				log_printf(LOG_INFO, "Set log level to: %d\n", g_loglevel);
				break;
			case 'L':
				logfile_init(optarg);
				break;
			case 'v':
				fprintf(stdout, "%s\n", VERSION);
				exit(1);
			case 'h':
			default:
				fprintf(stderr, "Usage: %s\n"
				"\t[-D --daemonize]\n"
				"\t[-l --loglevel=<level>] set loglevel (0-4), bigger = more verbose\n"
				"\t[-L --logfile=file] output log into file instead of stdout\n"
				"\t[-h --help]\n"
				, argv[0]);
				exit(1);
		}
	}

	signal(SIGINT, sighandler);
	signal(SIGPIPE, SIG_IGN);

	miot_fd = miot_connect_init();
	dispatch_listenfd = dispatch_server_init();

	if (miot_fd <= 0 || dispatch_listenfd <=0) {
		log_printf(LOG_ERROR, "create socket error\n");
		return -1;
	}

	key_list = init_key_list();
	id_list =  init_id_list();
	if (key_list == NULL || id_list == NULL) {
		return -1;
	}

	memset(&dispatcher, 0, sizeof(dispatcher));

	dispatcher.pollfds[dispatcher.count_pollfds].fd = miot_fd;
	dispatcher.pollfds[dispatcher.count_pollfds].events = POLLIN;
	log_printf(LOG_INFO, "miot client fd: %d\n", dispatcher.pollfds[dispatcher.count_pollfds].fd);
	dispatcher.count_pollfds++;

	dispatcher.pollfds[dispatcher.count_pollfds].fd = dispatch_listenfd;
	dispatcher.pollfds[dispatcher.count_pollfds].events = POLLIN;
	log_printf(LOG_INFO, "dispatcher listen fd: %d\n", dispatcher.pollfds[dispatcher.count_pollfds].fd);
	dispatcher.count_pollfds++;

	/* timer */
	timer_fd = timer_setup();
	assert(timer_fd > 0);
	timer_start(timer_fd, TIMER_INTERVAL, TIMER_INTERVAL);
	dispatcher.pollfds[dispatcher.count_pollfds].fd = timer_fd;
	dispatcher.pollfds[dispatcher.count_pollfds].events = POLLIN;
	log_printf(LOG_INFO, "timer fd: %d\n", dispatcher.pollfds[dispatcher.count_pollfds].fd);
	dispatcher.count_pollfds++;

	if (daemonize)
		if (daemon(0, 1) < 0)
			log_printf(LOG_WARNING, "daemonize fail: %m\n");
	n = 0;

	while (n >= 0) {
		int i;
		n = poll(dispatcher.pollfds, dispatcher.count_pollfds, POLL_TIMEOUT);
		if (n <= 0) {
			continue;
		}

		for (i = 0; i < dispatcher.count_pollfds && n > 0; i++) {
			if (dispatcher.pollfds[i].revents & (POLLNVAL | POLLHUP | POLLERR)) {
				int j = i;
				log_printf(LOG_DEBUG, "dispatcher.pollfds[i].revents: %08x, %d\n",dispatcher.pollfds[i].revents, dispatcher.pollfds[i].fd);
				if (dispatcher.pollfds[i].fd == miot_fd) {
					close(miot_fd);
					dispatcher.pollfds[i].fd = -1;
					miot_fd = -1;
					continue;
				}
				if (dispatcher.pollfds[i].fd == dispatch_listenfd) {
					continue;
				}
				delete_fd_from_dispathcer(dispatcher.pollfds[i].fd);
				n--;
			} else if (dispatcher.pollfds[i].revents & POLLIN) {
				if (dispatcher.pollfds[i].fd == timer_fd)
					timer_handler(timer_fd);
				else if (dispatcher.pollfds[i].fd == miot_fd)
					dispatcher_recv_handler(miot_fd, 0);
				else if (dispatcher.pollfds[i].fd == dispatch_listenfd)
					dispatcher_listen_handler(dispatch_listenfd);
				else
					dispatcher_recv_handler(dispatcher.pollfds[i].fd, 1);
				n--;
			}
		}
	}
	return 0;
}

int  miot_connect_init(void)
{
	int miot_fd;
	struct sockaddr_in servaddr;

	miot_fd = socket(AF_INET, SOCK_STREAM, 0);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(SERVER_IP);
	servaddr.sin_port = htons(MIOT_SERVER_PORT);

	if (connect(miot_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
		log_printf(LOG_ERROR, "Connect to server error: %s:%d\n", SERVER_IP, MIOT_SERVER_PORT);
		return -1;
	}
	return miot_fd;
}

int  dispatch_server_init(void)
{
	struct sockaddr_in serveraddr;
	int dispatch_listenfd;
	int ret = -1, on = 1;

	dispatch_listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (dispatch_listenfd < 0) {
		log_printf(LOG_ERROR, "Create ot server socket error: %s\n",
			   strerror(errno));
		return -1;
	}

	if ((ret = setsockopt(dispatch_listenfd, SOL_SOCKET, SO_REUSEADDR,
				  (char *) &on, sizeof(on))) < 0) {
		log_printf(LOG_ERROR, "OT server setsockopt(SO_REUSEADDR): %m");
		close(dispatch_listenfd);
		return ret;
	}

	if (ioctl(dispatch_listenfd, FIONBIO, (char *)&on) < 0) {
		log_printf(LOG_ERROR, "ioctl FIONBIO failed: %m");
		close(dispatch_listenfd);
		return -1;
	}

	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(DISPATCHER_SERVER_PORT);
	serveraddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(dispatch_listenfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
		log_printf(LOG_ERROR, "Socket bind port (%d) error: %s\n",
			   DISPATCHER_SERVER_PORT, strerror(errno));
		close(dispatch_listenfd);
		return -1;
	}

	if (listen(dispatch_listenfd, 32) == -1) {
		perror("listen");
		return -1;
	}
	return dispatch_listenfd;
}

void timer_handler(int fd)
{
	uint64_t exp = 0;

	/* just read out the "events" in fd, otherwise poll will keep
	 * reporting POLLIN */
	read(fd, &exp, sizeof(uint64_t));

	if (miot_fd <= 0) {
		miot_fd = miot_connect_init();
		dispatcher.pollfds[0].fd = miot_fd;
	}
}

/*
*listen connect from client
*/
int dispatcher_listen_handler(int listenfd)
{
	int newfd;
	struct sockaddr_storage other_addr;
	socklen_t sin_size = sizeof(struct sockaddr_storage);

	while (1) {
		newfd = accept(listenfd, (struct sockaddr *)&other_addr, &sin_size);
		if (newfd <= 0) {
			break;
		}
		 //add into poll 
		if (dispatcher.count_pollfds >= MAX_POLL_FDS) {
			log_printf(LOG_ERROR, "too many sockets to track\n");
			return -1;
		}

		dispatcher.pollfds[dispatcher.count_pollfds].fd = newfd;
		dispatcher.pollfds[dispatcher.count_pollfds].events = POLLIN;
		log_printf(LOG_INFO, "OT agent listen accept sockfd: %d\n",
			   dispatcher.pollfds[dispatcher.count_pollfds].fd);
		dispatcher.count_pollfds++;
	}
	return 0;
}

/**
*handler messages from miot
**/
int miot_msg_handler(char *msg, int msg_len)
{
	int ret = -1;

	if (json_verify_method(msg, "method") == 0) {
		/* It's a command msg */
		//log_printf(LOG_DEBUG, "cloud/mobile cmd: %s,len: %d\n", msg, msg_len);
		ret = send_to_register_client(msg, msg_len);
	} else {
		/* It's a report ACK msg */
		//log_printf(LOG_DEBUG, "cloud ack: %s, len: %d\n", msg, msg_len);
		ret = send_ack_to_client(msg);
	}
	return ret;
}

int get_newid(void)
{
	static int id=1;

	if (id >= MAX_ID_NUM)
		id = 1;
	return id++;
}

/*
*upload info or ack
*parse msg, if id exist, means this msg need ack, should linked to list.
*so repleace old id with new id,record the corresponding relationship
	new_id:		old_id, fd
*if id is not exist,means ack no need, just send to miot
*/
int client_msg_handler(char *msg, int len, int sockfd)
{
	int ret, old_id;
	int fd = miot_fd;

	//log_printf(LOG_DEBUG,"msg is %s, len is %d\n", msg, len);
	if (json_verify_method(msg, "method") == 0 ) {
		struct json_object *save_obj, *new_obj, *tmp_obj;
		const char *str,*key;

		save_obj = json_tokener_parse(msg);
		json_object_object_get_ex(save_obj, "method", &new_obj);
		if (!json_object_is_type(new_obj, json_type_string)) {
			json_object_put(save_obj);
			return -1;
		}
		str = json_object_get_string(new_obj);
		if (memcmp(str, "register", strlen("register")) == 0) {
			json_object_object_get_ex(save_obj, "key", &tmp_obj);
			if (json_object_is_type(tmp_obj, json_type_string)) {
				key = json_object_get_string(tmp_obj);
				log_printf(LOG_DEBUG, "register key: %s, fd: %d\n", key, sockfd);
				register_event(sockfd, key, strlen(key));
				ret = 0;
			}
		} else if (memcmp(str, "unregister", strlen("unregister")) == 0) {
			json_object_object_get_ex(save_obj, "key", &tmp_obj);
			if (json_object_is_type(tmp_obj, json_type_string)) {
				int key_len;
				key = json_object_get_string(tmp_obj);
				key_len = strlen(key);
				if (key_len == 0) {
					log_printf(LOG_DEBUG, "unregister all,fd: %d\n", sockfd);
					unregister_fd(sockfd);
				} else {
					log_printf(LOG_DEBUG, "unregister key: %s, fd: %d\n", key, sockfd);
					unregister_event(sockfd, key, strlen(key));
				}
				ret = 0;
			}
		} else if (json_verify_get_int(msg, "id", &old_id) == 0 ) {
			int msg_len;
			char *newmsg;
			int new_id = get_newid();
			/* replace with new id */
			json_object_object_del(save_obj, "id");
			json_object_object_add(save_obj, "id", json_object_new_int(new_id));
			newmsg = (char *)json_object_to_json_string_ext(save_obj, JSON_C_TO_STRING_PLAIN);
			msg_len = strlen(newmsg);
			log_printf(LOG_DEBUG, "newmsg  id %d, len %d\n", new_id, msg_len);
			record_id_map(old_id, new_id, sockfd);
			ret = send(fd, newmsg, msg_len, 0);
		} else {
			ret = send(fd, msg, len, 0);
		}
		json_object_put(save_obj);
	} else {
		//ack, just send to miot
		ret = send(fd, msg, len, 0);
	}
	return ret;
}
/* In some cases, we might receive several accumulated json RPC, we need to split these json.
 * E.g.:
 *   {"count":1,"stack":"sometext"}{"count":2,"stack":"sometext"}{"count":3,"stack":"sometext"}
 *
 * return the length we've consumed, -1 on error
 */
int dispatcher_recv_handler_one(int sockfd, char *msg, int msg_len, int flag)
{
	struct json_tokener *tok;
	struct json_object *json;
	int ret = 0;

	log_printf(LOG_DEBUG, "%s: sockfd: %d, msg: %.*s, length: %d bytes\n",
		(flag == 0 ? "miot" : "client"), sockfd, msg_len, msg, msg_len);
	if (json_verify(msg) < 0)
		return -1;

	/* split json if multiple */
	tok = json_tokener_new();
	while (msg_len > 0) {
		char *tmpstr;
		int tmplen;

		json = json_tokener_parse_ex(tok, msg, msg_len);
		if (json == NULL) {
			log_printf(LOG_WARNING, "token parse error msg: %.*s, length: %d bytes\n",
				    msg_len, msg, msg_len);
			json_tokener_free(tok);
			return ret;
		}

		tmplen = tok->char_offset;
		tmpstr = malloc(tmplen + 10);
		if (tmpstr == NULL) {
			log_printf(LOG_ERROR, "malloc error\n");
			json_tokener_free(tok);
			json_object_put(json);
			return -1;
		}
		memcpy(tmpstr, msg, tmplen);
		tmpstr[tmplen] = '\0';

		if (flag == 1)
			client_msg_handler((char *)tmpstr, tmplen, sockfd);
		else
			miot_msg_handler((char *)tmpstr, tmplen);

		free(tmpstr);
		json_object_put(json);
		ret += tok->char_offset;
		msg += tok->char_offset;
		msg_len -= tok->char_offset;
	}
	json_tokener_free(tok);
	return ret;
}

/*
*receive msgs from miot or clientfd, and split to one msg
*flag = 0 means from miot
*flag = 1 means from clientfd
*/
int dispatcher_recv_handler(int sockfd, int flag)
{
	char buf[MAX_BUF];
	ssize_t count;
	int left_len = 0;
	int ret = 0;
	bool first_read = true;

	memset(buf, 0, MAX_BUF);
	while (1) {
		count = recv(sockfd, buf + left_len, sizeof(buf) - left_len, MSG_DONTWAIT);
		if (count < 0) {
			return -1;
		}

		if (count == 0) {
			if (first_read && flag == 0) {
				log_printf(LOG_ERROR, "miot_fd :%d is closed, will be reconnect\n", sockfd);
				close(sockfd);
				dispatcher.pollfds[0].fd = -1;
				miot_fd = -1;
			} else if (first_read && flag == 1) {
				log_printf(LOG_ERROR, "sockfd :%d occurs error, delete from dispatcher\n", sockfd);
				delete_fd_from_dispathcer(sockfd);
			}
			if (left_len) {
				buf[left_len] = '\0';
				log_printf(LOG_WARNING, "remain str: %s\n",buf);
			}
			return 0;
		}
		first_read = false;
		ret = dispatcher_recv_handler_one(sockfd, buf, count + left_len, flag);
		if (ret < 0) {
			log_printf(LOG_ERROR, "dispatcher_recv_handler_one errors:%d\n", ret);
			return -1;
		}

		left_len = count + left_len - ret;
		memmove(buf, buf + ret, left_len);
	}
	return 0;
}

int timer_setup(void)
{
	int fd;

	fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (fd < 0) {
		perror("timerfd_create");
		return fd;
	}

	return fd;
}

int timer_start(int fd, int first_expire, int interval)
{
	struct itimerspec new_value;

	new_value.it_value.tv_sec = first_expire / 1000;
	new_value.it_value.tv_nsec = first_expire % 1000 * 1000000;

	new_value.it_interval.tv_sec = interval / 1000;
	new_value.it_interval.tv_nsec = interval % 1000 * 1000000;

	if (timerfd_settime(fd, 0, &new_value, NULL) == -1) {
		perror("timerfd_settime");
		return -1;
	}

	return 0;
}

Node *init_key_list(void)
{
	LinkList *pHead = NULL;

	pHead = (LinkList *)malloc(sizeof(LinkList));
	if (pHead == NULL) {
		log_printf(LOG_ERROR, "init_key_list ERROR\n") ;
		return NULL;
	}

	memset(pHead, 0, sizeof(LinkList));
	pHead->next = NULL;

	return pHead;
}

void free_key_list(void)
{
	LinkList *p = key_list;
	LinkList *q;

	while(p) {
		q = p;
		p = p->next;
		free(q);
	}
}

ID_Node *init_id_list(void)
{
	IDLinkList *pHead = NULL;

	pHead = (IDLinkList *)malloc(sizeof(IDLinkList));
	if (pHead == NULL) {
		log_printf(LOG_ERROR, "init_id_list ERROR\n") ;
		return NULL;
	}
	memset(pHead, 0, sizeof(IDLinkList));
	pHead->next = NULL;

	return pHead;
}

void free_id_list(void)
{
	IDLinkList *p = id_list;
	IDLinkList *q;

	while(p) {
		q = p;
		p = p->next;
		free(q);
	}
}

/**
 * judge if key is match, if match, return 1 and the pointer of last node
 */
int get_event_last_node(const char *key, int key_len, Node **pNode)
{
	int ret = 0;
	Node *p = key_list;

	while(p->next) {
		if (memcmp(p->next->key, key, key_len) == 0) {
			ret = 1;
			break;
		}
		p = p->next;
	}
	*pNode = p;
	return ret;
}
/**
 * register the interesting event with fd
 * key: interested event;
 */
int register_event(int fd,  const char *key, int key_len)
{
	int i, key_found = 0;
	Node *pHead = key_list;
	Node *p , *q;

	if (key_len > MAX_KEY_LEN || key_len <= 0) {
		log_printf(LOG_ERROR, "key length is error (%d/1~%d)\n", key_len, MAX_KEY_LEN);
		return -1;
	}

	 if (pHead->fd[KEY_NUM_INDEX] >= MAX_KEY_NUM) {
		log_printf(LOG_ERROR, "key is full, please unregister first\n");
		return -1;
	}

	key_found = get_event_last_node(key, key_len, &p);
	if (key_found == 1) {
		q = p->next;
		for (i = 0; i < MAX_CLIENT_NUM && q->fd[i]; i++) {
			if (q->fd[i] == fd) {
				log_printf(LOG_WARNING, "fd %d is already registered with key \"%s\"\n", q->fd[i], q->key);
				return 1;
			}
		}
		if (i == MAX_CLIENT_NUM) {
			log_printf(LOG_ERROR, "fd is full with key \"%s\", please unregister first\n", key);
			return -1;
		}
		q->fd[i] = fd;
	} else {
		q = (Node *)malloc(sizeof(Node));
		if (q == NULL) {
			return -1;
		}
		memset(q, 0, sizeof(LinkList));
		q->next = NULL;
		q->fd[0] = fd;	
		memcpy(q->key, key, key_len);

		p->next = q;
		pHead->fd[KEY_NUM_INDEX] += 1;
	}
	return 1;
}

int delete_fd_from_dispathcer(int sockfd)
{
	int i;

	unregister_fd(sockfd);
	update_id_map(sockfd);

	for (i = 0; i < dispatcher.count_pollfds; i++) {
		if (dispatcher.pollfds[i].fd == sockfd)
			break;
	}

	if (i == dispatcher.count_pollfds) return -1;

	close(dispatcher.pollfds[i].fd);
	while (i < dispatcher.count_pollfds - 1 && dispatcher.pollfds[i].fd) {
		dispatcher.pollfds[i] = dispatcher.pollfds[i + 1];
		i++;
	}
	dispatcher.pollfds[i].fd = -1;
	dispatcher.count_pollfds--;
	return 0;
}

/**
 * unregister fd from specific Node(event)
 */
int unregister_fd_from_Node(Node *pNode, int fd)
{
	int i, fd_found = 0, ret = -1;
	Node *q = pNode;

	for (i = 0; i < MAX_CLIENT_NUM && q->fd[i]; i++) {
		if (fd == q->fd[i]) {
			fd_found = 1;
			break;
		}
	}

	if (fd_found == 1) {
		ret = 0;
		while(i < MAX_CLIENT_NUM - 1 && q->fd[i]) {
			q->fd[i] = q->fd[i + 1];
			i++;
		}
		q->fd[i] = 0;
		/*the key just has one fd, free it*/
		if (q->fd[0] == 0) {
			free(q);
			ret = 1;
		}
	}
	return ret;
}

/**
 * unregister the interesting event with fd
 * key: interesting event;
 */
int unregister_event(int fd,  const char *key, int key_len)
{
	int key_found = 0;
	int ret = -1;
	Node *p, *q;

	key_found = get_event_last_node(key, key_len, &p);
	if (key_found == 0) {
		log_printf(LOG_ERROR, "Key not found: %s\n", key);
		return ret;
	}

	q = p->next->next;
	ret = unregister_fd_from_Node(p->next, fd);
	if (ret == 1)
		p->next = q;
	else if (ret < 0)
		log_printf(LOG_ERROR, "fd %d not found with the key %s\n", fd, key);
	return ret;
}

/**
 * unregister all interesting event with fd
 */
void unregister_fd(int fd)
{
	Node *p = key_list;
	Node *q;
	int free;
	log_printf(LOG_DEBUG, "unregister_fd :%d\n", fd);
	while(p->next) {
		q = p->next->next;
		free = unregister_fd_from_Node(p->next, fd);
		if (free == 1) {
			p->next = q;
		} else {
			p = p->next;
		}
	}
}

void print_registered_event(void)
{
	Node *p = key_list->next;
	int i = 0;

	log_printf(LOG_DEBUG, "==========start===========\n");
	while(p) {
		log_printf(LOG_DEBUG, "%s\n", p->key);
		for (i = 0; i < MAX_CLIENT_NUM && p->fd[i]; i++) {
			log_printf(LOG_DEBUG, "%d, \n", p->fd[i]);
		}
		log_printf(LOG_DEBUG, "\n");
		p = p->next;
	}
	log_printf(LOG_DEBUG,"===========end==========\n");
}

int send_to_register_client(char *msg, int msg_len)
{
	int ret =-1, key_found = 0;
	char *key;
	Node *p, *q;
	struct json_object *parse, *tmp_obj;

	parse = json_tokener_parse(msg);

	json_object_object_get_ex(parse, "method", &tmp_obj);
	if (!json_object_is_type(tmp_obj, json_type_string)) {
		log_printf(LOG_ERROR, "method not string\n");
		json_object_put(parse);
		return ret;
	} else {
		key = (char *)json_object_get_string(tmp_obj);
	}

	key_found = get_event_last_node(key, strlen(key), &p);
	if (key_found == 1) {
		int i = 0;
		q = p->next;
		while (i < MAX_CLIENT_NUM && q->fd[i]) {
			ret = send(q->fd[i], msg, msg_len, 0);
			log_printf(LOG_INFO,"send to registered fd: %d, send %d bytes\n",  q->fd[i], ret);
			i++;
		}
	} else {
		log_printf(LOG_WARNING,"no sockfd is registered with this method, msg is %s\n",  msg);
	}
	json_object_put(parse);
	return ret;
}
/*
*record the id map
*/
int record_id_map(int old_id, int new_id, int fd)
{
	ID_Node *pHead = id_list;
	ID_Node *p = id_list;
	ID_Node *tmp;

	while (p->next) {
		p = p->next;
	}

	tmp = (ID_Node *)malloc(sizeof(ID_Node));
	if (tmp == NULL) {
		return -1;
	}
	tmp->next = NULL;
	tmp->new_id = new_id;
	tmp->old_id = old_id;
	tmp->fd = fd;

	p->next = tmp;
	pHead->new_id += 1;
	return 0;
}

/*
*remove invaild id
*/
void update_id_map(int fd)
{
	ID_Node *pHead = id_list;
	ID_Node *p = id_list;
	ID_Node *q;

	while (p->next) {
		if (p->next->fd == fd) {
			q = p->next;
			p->next = q->next;
			free(q);
			pHead->new_id -= 1;
		} else {
			p = p->next;
		}
	}
}

int send_ack_to_client(char *msg)
{
	ID_Node *p = id_list;
	ID_Node  *q;
	int id, found = 0;
	int ret = -1;

	if (json_verify_get_int(msg, "id", &id) != 0) {
		return -1;
	}

	while (p->next) {
		if (p->next->new_id == id) {
			found = 1;
			break;
		}
		p = p->next;
	}

	if (found == 1) {
		int old_id, fd, msg_len;
		char *newmsg;
		struct json_object *parse;

		//get old id and fd
		q = p->next;
		p->next = q-> next;
		old_id = q->old_id;
		fd = q->fd;
		free(q);

		parse = json_tokener_parse(msg);
		/* replace with new id */
		json_object_object_del(parse, "id");
		json_object_object_add(parse, "id", json_object_new_int(old_id));
		newmsg = (char *)json_object_to_json_string_ext(parse, JSON_C_TO_STRING_PLAIN);
		msg_len = strlen(newmsg);

		ret = send(fd, newmsg, msg_len, 0);
		log_printf(LOG_INFO, "send ack to fd:%d, id is %d, length %d bytes\n", fd,  old_id, msg_len);
		json_object_put(parse);
	} else {
		log_printf(LOG_WARNING, "id %d not found\n",  id);
	}
	return ret;
}



void print_id_list(void)
{
	ID_Node *p = id_list->next;
	int i = 0;

	log_printf(LOG_INFO, "=====================\n");
	while(p) {
		log_printf(LOG_INFO, "%d:	%d,	%d\n", p->new_id, p->old_id, p->fd);
		p = p->next;
	}
	log_printf(LOG_INFO, "=====================\n");
}

void logfile_init(char *filename)
{
	FILE *fp;

	fp = fopen(filename, "a");
	if (fp == NULL) {
		log_printf(LOG_ERROR, "can't open %s: %m\n", filename);
		return;
	}

	log_file = fp;
}

void log_printf(log_level_t level, const char *fmt, ...)
{
	char buf[80];
	time_t now;
	va_list ap;
	struct tm *p;
	char *slevel;

	if (stdout == NULL)
		return;

	if (level <= g_loglevel) {
		switch (level) {
		case LOG_ERROR   : slevel = "[ERROR]"; break;
		case LOG_WARNING : slevel = "[WARNING]"; break;
		case LOG_INFO    : slevel = "[INFO]"; break;
		case LOG_DEBUG   : slevel = "[DEBUG]"; break;
		case LOG_VERBOSE : slevel = "[VERBOSE]"; break;
		default          : slevel = "[UNKNOWN]"; break;
		}

		now = time(NULL);
		p = localtime(&now);
		strftime(buf, 80, "[%Y%m%d %H:%M:%S]", p);

		va_start(ap, fmt);
		fprintf(log_file, "%s %s ", buf, slevel);
		vfprintf(log_file, fmt, ap);
		va_end(ap);
		fflush(log_file);
	}
}