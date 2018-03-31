#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

void diep(char *str) {
    perror(str);
    exit(EXIT_FAILURE);
}

int main(void) {
    int sockfd;
    char buffer[512];
    struct hostent *he;
    struct sockaddr_in their_addr;

    if(!(he = gethostbyname("127.0.0.1")))
        perror("gethostbyname");

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        diep("socket");

    their_addr.sin_family = AF_INET;
    their_addr.sin_port = htons(9900);
    their_addr.sin_addr = *((struct in_addr *) he->h_addr);

    if(connect(sockfd, (struct sockaddr *) &their_addr, sizeof(struct sockaddr)) == -1)
        diep("connect");

    char *payload = "*2\r\n$4\r\nINFO\r\n$8\r\nABCDEFGH\r\n";

    int bytetime = 2;

    printf("[+] sending payload: ");
    for(unsigned int i = 0; i < strlen(payload); i += bytetime) {
        if(send(sockfd, payload + i, bytetime, 0) < 0)
            diep("send");

        printf(".");
        fflush(stdout);

        usleep(100000);
    }

    int length;

    if((length = recv(sockfd, buffer, 512, 0)) < 0)
        diep("recv");

    printf("%.*s\n", length, buffer);

    close(sockfd);

    return 0;
}
