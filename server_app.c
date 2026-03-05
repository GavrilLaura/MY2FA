/*SERVER APP - SERVERUL APLICATIEI*/
/*
->rol de server pentru utilizator (client_app) 
->rol de client pentru server_2fa 
*/
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>

#define PORT_APP 2909       //unde ascultam noi clientii
#define PORT_2FA 2908       //unde verificam codurile
#define IP_2FA "127.0.0.1"  //localhost - adresa serverului 2FA

void raspunde(void *arg);
void comunica_cu_server_2fa(char *comanda, char *raspuns_primit);

extern int errno;

typedef struct thData{
    int idThread;
    int cl;
} thData;

//functia de gestionare a thread ului
static void *treat(void *arg){
    struct thData tdL;
    tdL = *((struct thData*)arg);

    pthread_detach(pthread_self());

    raspunde((struct thData*)arg);

    close(tdL.cl);
    free(arg);
    return(NULL);
}

//criptare xor
#define XOR_KEY 'K'
void aplica_xor(char *msg, int len){
    for(int i = 0; i < len; ++i){
        msg[i] = msg[i] ^ XOR_KEY;
    }
}

//functia de gestionare a protocolului
void raspunde(void *arg){
    char buffer_client[1024]; 
    char raspuns_final[1024]; 
    char raspuns_2fa[1024];
    char comanda_2fa[1024];

    struct thData tdL;
    tdL = *((struct thData*)arg);

    //citim ce ne-a trimis browserul
    bzero(buffer_client, 1024);
    if(read(tdL.cl, buffer_client, 1024) <= 0) return;
    aplica_xor(buffer_client, 1024);

    printf("[thread %d] Date primite de la browser: %s\n", tdL.idThread, buffer_client);

    //despachetam mesajul
    char *utilizator = strtok(buffer_client, ":");
    char *aplicatie = strtok(NULL, ":");
    char *metoda_str = strtok(NULL, ":");
    char *parola_simpla = strtok(NULL, ":");
    int metoda = atoi(metoda_str);

    if(!utilizator || !aplicatie || !metoda_str || !parola_simpla) return;

    //verificare prima parola
    sprintf(comanda_2fa, "VERIF_CREDENTIALE %s %s %s", utilizator, aplicatie, parola_simpla);
    bzero(raspuns_2fa, 1024);
    comunica_cu_server_2fa(comanda_2fa, raspuns_2fa);

    if (strstr(raspuns_2fa, "LOGIN_FAILED") != NULL) {
        sprintf(raspuns_final, "EROARE: Parola incorecta sau utilizator negasit.");
        aplica_xor(raspuns_final, 1024);
        write(tdL.cl, raspuns_final, 1024);
        return;
    }

    printf("[thread %d] Utilizator: %s | Aplicatie: %s | Metoda: %d\n", tdL.idThread, utilizator, aplicatie, metoda);
    
    sprintf(comanda_2fa, "CHECK_USER %s %s dummy dummy", utilizator, aplicatie);
    bzero(raspuns_2fa, 1024);
    comunica_cu_server_2fa(comanda_2fa, raspuns_2fa);

    if (strstr(raspuns_2fa, "USER_NOT_FOUND") != NULL) {
        sprintf(raspuns_final, "EROARE: Utilizatorul nu exista pentru aceasta aplicatie.");
        aplica_xor(raspuns_final, 1024);
        write(tdL.cl, raspuns_final, 1024);
        return;
    }

    //analizam cererea si formam raspusul
    if(metoda == 1) {
        //metoda cod OTP
        sprintf(raspuns_final, "COD_OTP_REQUIRED: Introduceti codul OTP de pe telefon.");
        aplica_xor(raspuns_final, 1024);
        write(tdL.cl, raspuns_final, 1024);

        //asteptam ca browser-ul sa ne trimita codul de 6 cifre
        char cod_primit[10];
        bzero(cod_primit, 10);
        read(tdL.cl, cod_primit, 10);
        aplica_xor(cod_primit, 10);
        printf("[thread %d] Utilizatorul a introdus codul: %s. Verificam la 2FA...\n", tdL.idThread, cod_primit);

        //trimitem cererea de verificare la serverul 2FA
        sprintf(comanda_2fa, "VERIF_OTP %s %s %s", utilizator, aplicatie, cod_primit);

        bzero(raspuns_2fa, 1024);
        comunica_cu_server_2fa(comanda_2fa, raspuns_2fa);

        //trimitem rezultatul final catre browser
        aplica_xor(raspuns_2fa, 1024);
        write(tdL.cl, raspuns_2fa, 1024);
    }
    else if(metoda == 2){
        //metoda PUSH
        sprintf(raspuns_final, "WAITING_PUSH: Verificati notificarea pe telefon.");
        aplica_xor(raspuns_final, 1024);
        write(tdL.cl, raspuns_final, 1024);

        printf("[thread %d] Cerem serverului 2FA sa trimita notificare Push...\n", tdL.idThread);
        sprintf(comanda_2fa, "SEND_PUSH %s %s", utilizator, aplicatie);

        bzero(raspuns_2fa, 1024);
        comunica_cu_server_2fa(comanda_2fa, raspuns_2fa);

        aplica_xor(raspuns_2fa, 1024);
        write(tdL.cl, raspuns_2fa, 1024);
    }
}

//functie auxiliara care transforma serverul app in client pentru serverul 2FA
void comunica_cu_server_2fa(char *comanda, char *raspuns_primit){
    int sd;
    struct sockaddr_in server;

    //cream socket ul
    if((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        perror("[server_app->server_2fa] eroare socket spre 2FA");
        return;
    }

    //setam portul la 2908 -> server_2fa
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(IP_2FA);
    server.sin_port = htons(PORT_2FA);

    //apel connect
    if(connect(sd, (struct sockaddr *) &server, sizeof(struct sockaddr)) == -1){
        perror("[server_app -> 2fa] eroare connect spre 2FA");
        strcpy(raspuns_primit, "EROARE: Serverul 2FA este offline.");
        close(sd);
        return;
    }

    char buffer_trimitere[1024];
    bzero(buffer_trimitere, 1024);
    strcpy(buffer_trimitere, comanda);

    aplica_xor(buffer_trimitere, 1024);
    write(sd, buffer_trimitere, 1024);

    bzero(raspuns_primit, 1024);
    int total = 0;
    while(total < 1024) {
        int r = read(sd, raspuns_primit + total, 1024 - total);
        if(r <= 0) break;
        total += r;
    }
    aplica_xor(raspuns_primit, 1024);
    close(sd);
}

int main(){
    struct sockaddr_in server;
    struct sockaddr_in from;
    int sd;
    pthread_t th[100];
    int i=0;

    //cream socket catre client app
    if((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        perror("[server_app] eroare la socket()\n");
        return errno;
    }

    //reuseaddr ca sa nu primim "address in use"
    int on=1;
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    bzero(&server, sizeof(server));
    bzero(&from, sizeof(from));

    //configuram serverul astfel incat sa asculte pe portul 2909
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(PORT_APP);

    if(bind(sd, (struct sockaddr *) &server, sizeof(struct sockaddr)) == -1){
        perror("[server_app] eroare la bind()\n");
        return errno;
    }

    if(listen(sd, 5) == -1){
        perror("[server_app] eroare la listen()\n");
        return errno;
    }

    printf("[server_app] asteptam utilizatori (client_app) la portul %d ...\n", PORT_APP);

    //bucla de acceptare clienti
    while(1){
        int client;
        thData *td;
        int len = sizeof(from);

        //asteptam sa se conecteze un client
        if((client = accept(sd, (struct sockaddr *) &from, &len)) < 0){
            perror("[server_app] eroare la accept()\n");
            continue;
        }

        //datele pentru thread-ul ce va servi acesrt client
        td = (struct thData*)malloc(sizeof(struct thData));
        td->idThread = i;
        td->cl = client;

        //cream thread ul
        if(pthread_create(&th[i], NULL, &treat, td) == 0) i++;
    }
}