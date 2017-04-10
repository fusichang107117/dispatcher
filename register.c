#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_CLIENT_NUM		3
#define MAX_KEY_NUM			2
#define MAX_KEY_LEN			30
#define KEY_NUM_INDEX		0

typedef struct Node
{
	char key[MAX_KEY_LEN];
	int fd[MAX_CLIENT_NUM];
	struct Node *next;
}Node;

typedef struct Node LinkList;
LinkList *key_list = NULL;

int register_event(int fd,  char *key, int key_len);
int unregister_event(int fd,  char *key, int key_len);
void print_registered_event(void);
Node *init_list(void);

int main(int argc, char const *argv[])
{
	/* code */
	int fd1 = 1001;
	int fd2 = 1002;
	int fd3 = 1003;
	int fd4 = 1004;
	char *key_a = "key-a";
	char *key_b = "key-b";
	char *key_c = "key-c";
	char *key_d = "key-d";


	key_list= init_list();

	register_event(fd1, key_a, strlen(key_a));
	print_registered_event();
	register_event(fd2, key_a, strlen(key_a));
	print_registered_event();
	register_event(fd3, key_a, strlen(key_a));
	print_registered_event();


	register_event(fd1, key_b, strlen(key_b));
	print_registered_event();
	register_event(fd2, key_b, strlen(key_b));
	print_registered_event();
	register_event(fd3, key_b, strlen(key_b));
	print_registered_event();

	//register_event(fd2, key_b, strlen(key_b));
	//print_registered_event();
	unregister_event(fd2, key_a, strlen(key_a));
	print_registered_event();

	register_event(fd2, key_a, strlen(key_a));
	print_registered_event();

	unregister_event(fd2, key_b, strlen(key_a));
	print_registered_event();

	register_event(fd3, key_c, strlen(key_c));
	print_registered_event();

//	unregister_event(fd1, key_a, strlen(key_a));
//	print_registered_event();

	return 0;
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