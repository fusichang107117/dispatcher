#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CLIENT_NUM		3
#define MAX_KEY_NUM			2
#define MAX_KEY_LEN			30
#define KEY_NUM_INDEX		0
#define MIN_ID_NUM			5000
#define MAX_ID_NUM			1000000

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

typedef struct Node LinkList;
typedef struct ID_Node IDLinkList;

LinkList *key_list = NULL;
IDLinkList *id_list = NULL;

Node *init_key_list(void);
int register_event(int fd,  char *key, int key_len);
int unregister_event(int fd,  char *key, int key_len);
void print_registered_event(void);

ID_Node *init_id_list(void);
int send_to_register_client(char *msg);
int send_ack_to_client(char *msg, int id);
void print_id_list(void);

void test_regiter(void);
void test_id(void);

int new_id = MIN_ID_NUM;


int main(int argc, char const *argv[])
{
	/* code */
	key_list= init_key_list();
	id_list = init_id_list();

	test_id();

//	unregister_event(fd1, key_a, strlen(key_a));
//	print_registered_event();

	return 0;
}

void test_regiter(void)
{
	int fd1 = 1001;
	int fd2 = 1002;
	int fd3 = 1003;
	int fd4 = 1004;
	char *key_a = "key-a";
	char *key_b = "key-b";
	char *key_c = "key-c";
	char *key_d = "key-d";

	register_event(fd1, key_a, strlen(key_a));
	print_registered_event();
	register_event(fd2, key_a, strlen(key_a));
	print_registered_event();
	register_event(fd3, key_a, strlen(key_a));
	print_registered_event();

	//register_event(fd2, key_b, strlen(key_b));
	//print_registered_event();
	unregister_event(fd2, key_a, strlen(key_a));
	print_registered_event();

	register_event(fd2, key_a, strlen(key_a));
	print_registered_event();

	unregister_event(fd2, key_b, strlen(key_a));
	print_registered_event();

	send_to_register_client(key_a);
}

void test_id(void)
{
	char *msg = "hello";
	int fd1 = 1001;
	int fd2 = 1002;
	int fd3 = 1003;
	int fd4 = 1004;

	int id1 = 1;
	int id2 = 2;
	int id3 = 3;
	int id4 = 4;

	upload_msg_handler(msg, id1, fd1);
	print_id_list();

	upload_msg_handler(msg, id2, fd1);
	print_id_list();

	upload_msg_handler(msg, id1, fd2);
	print_id_list();

	send_ack_to_client(msg, 5000);
	print_id_list();

}

Node *init_key_list(void)
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

ID_Node *init_id_list(void)
{
	IDLinkList *pHead = NULL;

	pHead = (IDLinkList *)malloc(sizeof(IDLinkList));
	if (pHead == NULL) {
		printf("ERROR\n") ;
		return NULL;
	}
	memset(pHead, 0, sizeof(IDLinkList));
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

int send_to_register_client(char *msg)
{
	char *key = msg;
	int key_len = strlen(msg);
	int key_found = 0;
	int i, ret = -1;
	Node *p = key_list->next;

	while(p) {
		if (memcmp(p->key, key, key_len) == 0) {
			key_found = 1;
			break;
		}
		p = p->next;
	}

	if (key_found == 1) {
		for (i = 0; i < MAX_CLIENT_NUM && p->fd[i]; i++) {
			printf("send to registered fd :%d\n",  p->fd[i]);
			//ret = send(p->fd[i], msg, strlen(msg), 0);
		}
	}
	return ret;
}

int upload_msg_handler(char *msg, int old_id, int fd)
{
	ID_Node *pHead = id_list;
	ID_Node *p = id_list;
	ID_Node *q = id_list->next;
	ID_Node *tmp;

	while (q) {
		q = q->next;
		p = p->next;
	}

	tmp = (ID_Node *)malloc(sizeof(ID_Node));
	if (tmp == NULL) {
		return -1;
	}
	memset(tmp, 0, sizeof(ID_Node));
	tmp->next = NULL;
	tmp->new_id = new_id++;
	tmp->old_id = old_id;
	tmp->fd = fd;

	p->next = tmp;
	pHead->new_id += 1;
	return 0;
}

int send_ack_to_client(char *msg, int id)
{
	ID_Node *pHead = id_list;
	ID_Node *p = id_list;
	ID_Node *q = id_list->next;
	ID_Node *tmp;
	int found = 0;
	int ret = -1;

	while (q) {
		if (q->new_id == id) {
			found = 1;
			break;
		}
		q = q->next;
		p = p->next;
	}

	if (found == 1) {
		//replace id
		//ret = send(q->fd, msg, strlen(msg), 0);
		p->next = q-> next;
		free(q);
	} else {
		printf("id %d not found\n",  id);
	}
	return ret;
}



void print_id_list(void)
{
	ID_Node *p = id_list->next;
	int i = 0;

	printf("=====================\n");
	while(p) {
		printf("%d:	%d,	%d\n", p->new_id, p->old_id, p->fd);
		p = p->next;
	}
	printf("=====================\n");
}
