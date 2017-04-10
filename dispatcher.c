#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>	
#include <sys/socket.h>
#include "json-c/json.h"
#include <netinet/in.h>
#include <arpa/inet.h>


struct dispatcher_data dispatcher;
LinkList *key_list = NULL;

int main(int argc, char const *argv[])
{
	int n = 0;
	int miot_fd, dispatch_listenfd;

	miot_fd = dispatch_client_init();
	dispatch_listenfd = dispatch_server_init();

	if (miot_fd <= 0 || dispatch_listenfd <=0) {
		printf("create socket error\n");
		return -1;
	}

	key_list= init_list();
	if (key_list == NULL) {
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

	while (n >= 0) {
		int i;
		n = poll(dispatcher.pollfds, dispatcher.count_pollfds, POLL_TIMEOUT);
		if (n <= 0) {
			continue;
		}

		for (i = 0; i < dispatcher.count_pollfds && n > 0; i++) {
			if (dispatcher.pollfds[i].revents & POLLIN) {
				if (dispatcher.pollfds[i].fd == miot_fd)
					ispatcher_recv_handler(miot_fd, 0);		
				else if (dispatcher.pollfds[i].fd == dispatch_listenfd)
					dispatcher_listen_handler(dispatcher_listenfd);
				else
					ispatcher_recv_handler(dispatcher.pollfds[i].fd, 1);
				n--;
			} else if (miio.pollfds[i].revents & POLLOUT) {
				n--;
			} else if (miio.pollfds[i].revents & (POLLNVAL | POLLHUP | POLLERR)) {
				n--;
			}
		}
	}
	return 0;
}

int  miot_client_init(void)
{
	int miot_fd;
	struct sockaddr_in servaddr;

	miot_fd = socket(AF_INET, SOCK_STREAM, 0);

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = inet_addr(SERVER_IP);
	servaddr.sin_port = htons(SERVER_PORT);

	if (connect(miot_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
		printf("Connect to server error: %s:%d\n", SERVER_IP, SERVER_PORT);
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
			   OT_SERVER_PORT, strerror(errno));
		close(ot_agent_listenfd);
		return -1;
	}

	if (listen(dispatch_listenfd, 32) == -1) {
		perror("listen");
		return -1;
	}

	return dispatch_listenfd;	
}



static int dispatcher_listen_handler(int listenfd)
{

	/*
		listen client and add to pollfd
	*/

/*	int newfd;
	struct sockaddr_storage other_addr;
	socklen_t sin_size = sizeof(struct sockaddr_storage);

	while (1) {
		newfd = accept(listenfd, (struct sockaddr *)&other_addr, &sin_size);
		if (newfd < 0) {
			if (errno == EWOULDBLOCK || errno == EAGAIN) {
				break;
			} else {
				perror("accept");
				log_printf(LOG_ERROR, "%s, %d: accept error, listenfd: %d.\n",
					   __FILE__, __LINE__, listenfd);
				break;
			}
		}

		 //add into poll 
		if (dispatcher.count_pollfds >= MAX_POLL_FDS) {
			log_printf(LOG_ERROR, "%s, %d: too many sockets to track\n", __FILE__, __LINE__);
			return -1;
		}

		dispatcher.pollfds[dispatcher.count_pollfds].fd = newfd;
		dispatcher.pollfds[dispatcher.count_pollfds].events = POLLIN;
		log_printf(LOG_INFO, "OT agent listen accept sockfd: %d\n",
			   dispatcher.pollfds[dispatcher.count_pollfds].fd);
		dispatcher.count_pollfds++;
	}

	return 0;*/
}

int miot_msg_handler(int sockfd)
{
	/*

	parse method

	send the msg to the client which is interested
	
	so need to find the interested fd.
	
	*/
}


static int msg_dispatcher(const char *msg, int len, int sockfd)
{
	char ackbuf[OT_MAX_PAYLOAD];
	int ret = -1, id = 0;
	bool sendack = false;
	memset(ackbuf, 0, sizeof(ackbuf));
	log_printf(LOG_DEBUG, "%s, msg: %s, strlen: %d, len: %d\n", __func__, msg, (int)strlen(msg), len);

	//get id
	ret = json_verify_get_int(msg, "id", &id);
	if (ret < 0) {
		return ret;
	}

	if (json_verify_method_value(msg, "method", "deleteVideo", json_type_string) == 0) {
		log_printf(LOG_DEBUG, "Got deleteVideo...\n");
	}
	if (sendack)
		ret = general_send_one(sockfd, ackbuf, strlen(ackbuf));

	return ret;
}

/* In some cases, we might receive several accumulated json RPC, we need to split these json.
 * E.g.:
 *   {"count":1,"stack":"sometext"}{"count":2,"stack":"sometext"}{"count":3,"stack":"sometext"}
 *
 * return the length we've consumed, -1 on error
 */
static int dispatcher_recv_handler_one(int sockfd, char *msg, int msg_len, int flag)
{
	struct json_tokener *tok;
	struct json_object *json;
	int ret = 0;

	log_printf(LOG_DEBUG, "%s(), sockfd: %d, msg: %.*s, length: %d bytes\n",
		   __func__, sockfd, msg_len, msg, msg_len);
	if (json_verify(msg) < 0)
		return -1;

	/* split json if multiple */
	tok = json_tokener_new();
	while (msg_len > 0) {
		char *tmpstr;
		int tmplen;

		json = json_tokener_parse_ex(tok, msg, msg_len);
		if (json == NULL) {
			log_printf(LOG_WARNING, "%s(), token parse error msg: %.*s, length: %d bytes\n",
				   __func__, msg_len, msg, msg_len);
			json_tokener_free(tok);
			return ret;
		}

		tmplen = tok->char_offset;
		tmpstr = malloc(tmplen + 1);
		if (tmpstr == NULL) {
			log_printf(LOG_WARNING, "%s(), malloc error\n", __func__);
			json_tokener_free(tok);
			json_object_put(json);
			return -1;
		}
		memcpy(tmpstr, msg, tmplen);
		tmpstr[tmplen] = '\0';

		if (flag == 1)
			client_msg_handler((const char *)tmpstr, tmplen, sockfd);
		else
			miot_msg_handler((const char *)tmpstr, tmplen, sockfd);

		free(tmpstr);
		json_object_put(json);
		ret += tok->char_offset;
		msg += tok->char_offset;
		msg_len -= tok->char_offset;
	}

	json_tokener_free(tok);

	return ret;
}

int dispatcher_recv_handler(int sockfd, int flag)
{
	/*

	parse method

	switch(method)
	case register:
		register_event(fd,  method);
	case unregister:
		unregister_event(fd,  method);
	default:
		transmit_to_miot(msg);

	*/
	char buf[BUFFER_MAX];
	ssize_t count;
	int left_len = 0;
	int ret = 0;

	while (true) {
		count = recv(sockfd, buf + left_len, sizeof(buf) - left_len, MSG_DONTWAIT);
		if (count < 0) {
			return -1;
		}

		if (count == 0) {
			if (left_len) {
				buf[left_len] = '\0';
				log_printf(LOG_WARNING, "%s() remain str: %s\n", __func__, buf);
			}
			return 0;
		}

		ret = dispatcher_recv_handler_one(sockfd, buf, count + left_len, flag);
		if (ret < 0) {
			log_printf(LOG_WARNING, "%s_one() return -1\n", __func__);
			return -1;
		}

		left_len = count + left_len - ret;
		memmove(buf, buf + ret, left_len);
	}

	return 0;
}

/* Check if @fd in @clientfds */
static bool check_clientfds(int fd)
{
	int i;
	for (i = 2; i < dispatcher.client_count - 2; i++) {
		if (dispatcher.clientfds[i] == -1)
			return false;
		else if (dispatcher.clientfds[i] == fd)
			return true;
	}
	return false;
}

Node *init_list(void)
{
	LinkList *pHead = NULL;

	pHead = (LinkList *)malloc(sizeof(LinkList));
	if (pHead == NULL) {
		printf("ERROR\n") ;
		return NULL;
	}
	
	memset(pHead, 0, sizeof(LinkList));
	pHead->next = NULL;

	return pHead;
}

int register_event(int fd,  char *key, int key_len)
{
	int found = 0;
	int i;
	Node *pHead = key_list;
	Node *p = key_list;
	Node *q = key_list->next;
	Node *tmp;

	if (key_len > MAX_KEY_LEN) {
		return -1;
	}

	while (q) {
		if (memcmp(q->key, key, key_len) == 0) {
			found = 1;
			break;
		}
		q = q->next;
		p = p->next;
	}

	if (found == 1) {
		for (i = 0; i < MAX_CLIENT_NUM && q->fd[i]; i++) {
			if (q->fd[i] == fd) {
				printf("fd %d is already registered with key \"%s\"\n", q->fd[i], q->key);
				return 1;
			}
		}
		if (i == MAX_CLIENT_NUM) {
			printf("fd is full with key \"%s\", please unregister first\n", key);
			return -1;
		}
		q->fd[i] = fd;
	} else if (pHead->fd[KEY_NUM_INDEX] >= MAX_KEY_NUM) {
		printf("key is full, please unregister first\n");
		return -1;
	} else {
		tmp = (Node *)malloc(sizeof(Node));
		if (tmp == NULL) {
			return -1;
		}
		memset(tmp, 0, sizeof(LinkList));
		tmp->next = NULL;
		tmp->fd[0] = fd;	
		memcpy(tmp->key, key, key_len);

		p->next = tmp;
		pHead->fd[KEY_NUM_INDEX] += 1;
	}
	return 1;
}

int unregister_event(int fd,  char *key, int key_len)
{
	int key_found = 0, fd_found = 0;
	int i, j;
	int ret = -1;
	Node *p = key_list;
	Node *q = key_list->next;

	while(q) {
		if (memcmp(q->key, key, key_len) == 0) {
			key_found = 1;
			break;
		}
		q = q->next;
		p = p->next;
	}

	if (key_found == 0) {
		printf("Key not found\n");
		return ret;
	}

	for (i = 0; i < MAX_CLIENT_NUM && q->fd[i]; i++) {
		if (fd == q->fd[i]) {
			fd_found = 1;
			if (i == 0 && q->fd[1] == 0) {
				p->next = q->next;
				free(q);
				break;
			}
			for (j = i + 1; j < MAX_CLIENT_NUM && q->fd[j]; i++, j++)
				q->fd[i] = q->fd[j];
			q->fd[j-1] = 0;
			break;
		}
	}
	if (fd_found == 0) {
		printf("fd not found with the key\n");
		return ret;
	}
	ret = 0;
	return ret;
}

void print_registered_event(void)
{
	Node *p = key_list->next;
	int i = 0;

	printf("=====================\n");
	while(p) {
		printf("%s\t", p->key);
		for (i = 0; i < MAX_CLIENT_NUM && p->fd[i]; i++) {
			printf("%d, ", p->fd[i]);
		}
		printf("\n");
		p = p->next;
	}
	printf("=====================\n");
}