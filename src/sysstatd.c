#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "csapp.h"

#define MAX_ALLOC_ALLOWED 2

void read_requesthdrs(rio_t *rp);
int parse_uri(char *uri, char *filename, char *cgiargs);
void clienterror(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg);
void sendResponse(int fd, char *data, char *type, char *version, int size);
void *service(void *conn);

char *filePath;
pthread_mutex_t mutex;
char *allocatedBlocks[3];
int allocatedCount = 0;


int main(int argc, char **argv)
{
	pthread_t thread;
	struct addrinfo *in, *in2;
	struct addrinfo setup;
	int sockets[10];
	int numSockets = 0;

	if ((pthread_mutex_init(&mutex, NULL)) != 0)
	{
		printf("Error occured while initializing mutex: mutex\n");
		exit(EXIT_FAILURE);
	}

	memset(&setup, 0, sizeof(setup));

	//Fix this later
	if (argc < 2)
	{
		printf("Incorrect number of arguments");
	}

	setup.ai_flags = AI_PASSIVE | AI_NUMERICSERV | AI_ADDRCONFIG;
	setup.ai_protocol = IPPROTO_TCP;
	setup.ai_family = AF_INET6;
	setup.ai_socktype = SOCK_STREAM;

	char *port = argv[2];
	filePath = argv[4];

	if (getaddrinfo(NULL, port, &setup, &in) != 0)
	{
		printf("Error occured during getaddrinfo call\n");
		exit(EXIT_FAILURE);
	}

	char printed_addr[1024];
	for (in2 = in; in2 != NULL; in2 = in2->ai_next)
	{
		assert(in2->ai_protocol == IPPROTO_TCP);
		if (getnameinfo(in2->ai_addr, in2->ai_addrlen, printed_addr, sizeof(printed_addr), NULL, 0, NI_NUMERICHOST) != 0)
		{
			printf("Error occured during getnameinfo call\n");
			exit(EXIT_FAILURE);
		}

		int sock;
		if ((sock = socket(in2->ai_family, in2->ai_socktype, in2->ai_protocol)) == -1)
		{
			printf("Error occured during socket call\n");
			exit(EXIT_FAILURE);
		}

		//int opt = 1;
		struct timeval timeout;      
    	timeout.tv_sec = 6;
    	timeout.tv_usec = 0;
		setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

		int res = bind(sock, in2->ai_addr, in2->ai_addrlen);
		if (res == -1 && errno == EADDRINUSE)
		{
			close(sock);
			continue;
		}

		if (res == -1)
		{
			printf("Error occured during bind call\n");
			exit(EXIT_FAILURE);
		}

		if ((listen(sock, 10)) == -1)
		{
			printf("Error occured during listen call\n");
			exit(EXIT_FAILURE);
		}

		assert(numSockets < sizeof(sockets)/sizeof(sockets[0]));
		sockets[numSockets++] = sock;
	}

	freeaddrinfo(in);

	assert(numSockets == 1);

	struct sockaddr_storage storage;
	socklen_t storageLen = sizeof(storage);

	for(;;)
	{
		int *arg = malloc(sizeof(*arg));
		if (arg == NULL)
		{
			printf("Error allocating arg\n");
			exit(EXIT_FAILURE);
		}

		int fd;
		if ((fd = accept(sockets[0], (struct sockaddr *) &storage, &storageLen)) == -1)
		{
			printf("Error occured during accept call\n");
			exit(EXIT_FAILURE);
		}

		*arg = fd;

		char buf1[200];
		if (getnameinfo((struct sockaddr *) &storage, storageLen, buf1, sizeof(buf1),
			NULL, 0, 0))
		{
			strcpy(buf1, "???");
		}

		char buf2[100];
		(void) getnameinfo((struct sockaddr *) &storage, storageLen, buf2, sizeof(buf2),
			NULL, 0, NI_NUMERICHOST);
		printf("Connection from %s (%s)\n", buf1, buf2);

		pthread_create(&thread, NULL, service, arg);
	}

	return 0;
}

/**
 * Handles HTTP Requests that are sent from the client.
 *
 * Heavily based on the Tiny Server Implementation.
*/
void *service(void *conn)
{
	//Make sure we deallocate our file descriptor
	int fd = *((int *) conn);
	char buf[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE];
	char filename[MAXLINE], cgiargs[MAXLINE];

	rio_t rio;

	Rio_readinitb(&rio, fd);
	if (Rio_readlineb(&rio, buf, MAXLINE) <= 0)
	{
		close(fd);
		return NULL;
	}

	sscanf(buf, "%s %s %s", method, uri, version);

	if (strcasecmp(method, "GET"))
	{
		clienterror(fd, method, "501", "METHOD NOT ALLOWED", "METHOD NOW ALLOWED");
		close(fd);
		return NULL;
	}

	read_requesthdrs(&rio);

	parse_uri(uri, filename, cgiargs);

	char json[MAXLINE];
	
	if (strstr(uri, "junk") != NULL)
	{
	    clienterror(fd, method, "404", "NOT FOUND", version);
	    close(fd);
	    return NULL;
	}
	else if (strstr(uri, "/runloop") != NULL)
	{
		sendResponse(fd, "Started 15 second spin.", "text/html", version, strlen("Started 15 second spin."));
		time_t curTime = time(NULL);
		time_t endTime = curTime;
		while ((endTime - curTime) < 15)
		{
			endTime = time(NULL);
		}
	}
	else if (strstr(uri, "/allocanon") != NULL)
	{
		if (allocatedCount > MAX_ALLOC_ALLOWED)
		{
			sendResponse(fd, "Reached maximum of 3 blocks, request denied.", "text/html", version, strlen("Reached maximum of 6 blocks, request denied."));
			close(fd);
			return NULL;
		}
		else
		{
			char *block = mmap(0, 256000000, PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
			if (block == MAP_FAILED)
				printf("Error occured during mmap call\n");

			memset(block, '0', 256000000);
			allocatedBlocks[allocatedCount] = block;
			allocatedCount++;

			char msg[512];
			sprintf(msg, "Mapped and touched 256MB anonymous memory, now have %d blocks allocated in total.", allocatedCount);
			sendResponse(fd, msg, "text/html", version, strlen(msg));
		}
	}
	else if (strstr(uri, "/freeanon") != NULL)
	{
		if (allocatedCount == 0)
		{
			sendResponse(fd, "No blocks allocated.", "text/html", version, strlen("No blocks allocated."));
			close(fd);
			return NULL;
		}
		else
		{
			allocatedCount--;
			if (munmap(allocatedBlocks[allocatedCount], 256000000) != 0)
				printf("Error occured during munmap call\n");
			char msg[512];
			sprintf(msg, "Unmapped 256MB, %d blocks left.", allocatedCount);
			sendResponse(fd, msg, "text/html", version, strlen(msg));
		}
	}
	else if (strstr(uri, "/loadavg") != NULL || strstr(uri, "/loadavg?callback=") != NULL || (strstr(uri, "/loadavg?") != NULL && strstr(uri, "&callback=") != NULL))
	{
		FILE *file = fopen("/proc/loadavg", "r");
		if (file != NULL)
		{
			char loadAvgString[512];
			fgets(loadAvgString, sizeof(loadAvgString), file);
			fclose(file);

			char a1[20], a2[20], a3[20], numThreads[20];
			char *runThreads, *totalThreads;

			sscanf(loadAvgString, "%s %s %s %s", a1, a2, a3, numThreads);
			runThreads = strtok(numThreads, "/");
			totalThreads = strtok(NULL, " ");

			strcat(json, "{\"total_threads\": \"");
			strcat(json, totalThreads);
			strcat(json, "\", \"loadavg\": [\"");
			strcat(json, a1);
			strcat(json, "\", \"");
			strcat(json, a2);
			strcat(json, "\", \"");
			strcat(json, a3);
			strcat(json, "\"], \"");
			strcat(json, "running_threads\": \"");
			strcat(json, runThreads);
			strcat(json, "\"}");
		}
		char *callback;

		if (strstr(uri, "/loadavg?callback=") != NULL)
                  callback = strstr(uri, "?callback=");
                else
                  callback = strstr(uri, "&callback=");

		//		char *callback = strstr(uri, "?callback=");

		if (callback != NULL)
		{
			callback += 10;
			char *string = strtok(callback, "& ");

			char function[512];
			function[0] = '\0';

			strcat(function, string);
			strcat(function, "(");
			strcat(function, json);
			strcat(function, ")");
			
			sendResponse(fd, function, "application/javascript", version, strlen(function));
		}
		else
		{
			sendResponse(fd, json, "application/json", version, strlen(json));
		}
	}

	else if (strstr(uri, "/meminfo") != NULL || strstr(uri, "/meminfo?callback=") != NULL || (strstr(uri, "/meminfo?") != NULL && strstr(uri, "&callback=") != NULL))
	{
		FILE *file = fopen("/proc/meminfo", "r");
		strcat(json, "{");

		if (file != NULL)
		{
			char line[512];
			while (fgets(line, sizeof(line), file) != NULL)
			{
				char name[20];
				char size[20];

				sscanf(line, "%s %s", name, size);
				name[strlen(name) - 1] = '\0';

				//printf("%s: %s\n", name, size);
				strcat(json, "\"");
				strcat(json, name);
				strcat(json, "\": \"");
				strcat(json, size);
				strcat(json, "\", ");
			}

			json[strlen(json) - 2] = '\0';
			fclose(file);
			strcat(json, "}");
		}

		char *callback;
		if (strstr(uri, "/meminfo?callback=") != NULL)
		  callback = strstr(uri, "?callback=");
		else
		  callback = strstr(uri, "&callback=");

		if (callback != NULL)
		{
			callback += 10;
			char *string = strtok(callback, "& ");

			char function[512];
			function[0] = '\0';

			strcat(function, string);
			strcat(function, "(");
			strcat(function, json);
			strcat(function, ")");
			
			sendResponse(fd, function, "application/javascript", version, strlen(function));
		}
		else
		{
			sendResponse(fd, json, "application/json", version, strlen(json));
		}
	}

	//Provides all of the necessary functions for file serving
	else
	{
		if (strstr(filename, "..") != NULL)
	  	{
	  		clienterror(fd, method, "403", "Forbidden", "File pathname not allowed");
	    	return NULL;
	  	}

	  	char *type;
	  	if (strstr(filename, ".html") != NULL || strstr(filename, ".htm") != NULL)
	    	type = "text/html";
	  	else if (strstr(filename, ".gif") != NULL) 
	    	type = "image/gif";
		else if (strstr(filename, ".jpg") != NULL) 
		    type = "image/jpeg";
		else if (strstr(filename, ".js") != NULL) 
		    type = "application/javascript";
		else if (strstr(filename, ".css") != NULL) 
		    type = "text/css";
		else 
		    type = "text/plain";

		printf("\n%s\n", filename);

	  	FILE *file = fopen(filename, "r");
	 	if (file == NULL)
	    {
	      	clienterror(fd, method, "404", "NOT FOUND", "File Not Found");
	      	return NULL;
	    }

	  	fseek(file, 0, SEEK_END);
	  	int length = ftell(file);
	 	fseek(file, 0, SEEK_SET);
	  	char *data = (char *) malloc(length);

	  	fread(data, length, 1, file);

	  	printf("\n%s\n", data);
	  	sendResponse(fd, data, type, version, length);
	}

	close(fd);
	pthread_exit(NULL);
	//return NULL;
}

/*
 * Sends the necessary headers and data to the client
 *
*/
void sendResponse(int fd, char *data, char *type, char *version, int size)
{
	char buffer[MAXLINE];

	if (strcmp(version, "HTTP/1.1") == 0)
	{
		sprintf(buffer, "%s 100 Continue\r\n", version);
	}
	else
	{
		sprintf(buffer, "%s 200 OK\r\n", version);
	}
	
	Rio_writen(fd, buffer, strlen(buffer));
	printf("\n%s", buffer);
	sprintf(buffer, "Content-length: %d\r\n", size);

	Rio_writen(fd, buffer, strlen(buffer));
	printf("%s", buffer);	
	sprintf(buffer, "Content-type: %s\r\n\r\n", type);

	Rio_writen(fd, buffer, strlen(buffer));
	printf("%s", buffer);
	Rio_writen(fd, data, size);
	printf("%s", data);
}

/*
 * Returns an error message to the client
 * Borrowed from Tiny Server
 *
*/
void clienterror(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg) 
{
    char buf[MAXLINE], body[MAXBUF];

    /* Build the HTTP response body */
    sprintf(body, "<html><title>Web Server Error</title>");
    sprintf(body, "%s<body bgcolor=""ffffff"">\r\n", body);
    sprintf(body, "%s%s: %s\r\n", body, errnum, shortmsg);
    sprintf(body, "%s<p>%s: %s\r\n", body, longmsg, cause);
    sprintf(body, "%s<hr><em>Web Server/em>\r\n", body);

    /* Print the HTTP response */
    sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, shortmsg);
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "Content-type: text/html\r\n");
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "Content-length: %d\r\n\r\n", (int)strlen(body));
    Rio_writen(fd, buf, strlen(buf));
    Rio_writen(fd, body, strlen(body));
}

/*
 * Read the headers that are requested
 * Borrowed from Tiny Server
 *
*/
void read_requesthdrs(rio_t *rp) 
{
    char buf[MAXLINE];

    Rio_readlineb(rp, buf, MAXLINE);
    printf("%s", buf);

    while(strcmp(buf, "\r\n"))  //line:netp:readhdrs:checkterm
    {          
		Rio_readlineb(rp, buf, MAXLINE);
		printf("%s", buf);
    }

    return;
}

/*
 * Parse the uri that is sent by the user. This is used to only
 * gather the name of the file in our case.
 * Borrowed from Tiny Server
 * 
*/
int parse_uri(char *uri, char *filename, char *cgiargs) 
{
    char *ptr;

    if (!strstr(uri, "cgi-bin")) {  /* Static content */ //line:netp:parseuri:isstatic
	strcpy(cgiargs, "");                             //line:netp:parseuri:clearcgi
	strcpy(filename, ".");                           //line:netp:parseuri:beginconvert1
	strcat(filename, uri);                           //line:netp:parseuri:endconvert1
	if (uri[strlen(uri)-1] == '/')                   //line:netp:parseuri:slashcheck
	    strcat(filename, "home.html");               //line:netp:parseuri:appenddefault
	return 1;
    }
    else {  /* Dynamic content */                        //line:netp:parseuri:isdynamic
	ptr = index(uri, '?');                           //line:netp:parseuri:beginextract
	if (ptr) {
	    strcpy(cgiargs, ptr+1);
	    *ptr = '\0';
	}
	else 
	    strcpy(cgiargs, "");                         //line:netp:parseuri:endextract
	strcpy(filename, ".");                           //line:netp:parseuri:beginconvert2
	strcat(filename, uri);                           //line:netp:parseuri:endconvert2
	return 0;
    }
}