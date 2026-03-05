/*CLIENT 2FA - SIMULEAZA TELEFONUL UTILIZATORULUI*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h>

#define PORT 2908

extern int errno;

//criptare
#define XOR_KEY 'K'
void aplica_xor(char *msg, int len){
    for(int i = 0; i < 1024; ++i){
        msg[i] = msg[i] ^ XOR_KEY;
    }
}

int main(int argc, char *argv[]){
    int sd;
    struct sockaddr_in server;
    char msg[1024];

    if(argc != 2){
        printf("Sintaxa: %s <adresa_server_2fa>\n", argv[0]);
        return -1;
    }

    //cream socket ul
    if((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        perror("eroare la socket()\n");
        return errno;
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(argv[1]);
    server.sin_port = htons(PORT);

    //conectarea la server
    if(connect(sd, (struct sockaddr *) &server, sizeof(struct sockaddr)) == -1){
        perror("[client_2fa]eroare la connect()\n");
        return errno;
    }

    char nume_posesor[50];
    printf("Introduceti numele de utilizator pentru acest telefon: ");
    scanf("%s", nume_posesor);

    char mesaj_identificare[1024];
    sprintf(mesaj_identificare, "IDENTIFICARE:%s", nume_posesor);
    aplica_xor(mesaj_identificare, 1024);
    write(sd, mesaj_identificare, 1024);

    bzero(msg, 1024);
    int bytes_identif = 0;
    while(bytes_identif < 1024){
        int n = read(sd, msg + bytes_identif, 1024 - bytes_identif);
        if(n <= 0) return 0;
        bytes_identif += n;
    }
    aplica_xor(msg, 1024);

    if (strstr(msg, "EROARE") != NULL) {
        printf("\n[telefon] EROARE: Serverul a respins inregistrarea! Utilizatorul '%s' nu exista.\n", nume_posesor);
        close(sd); //inchidem conexiunea
        return 0;  //oprim programul
    }

    printf("[telefon] Identificare reusita pentru posesorul: %s. Astept notificari..\n", nume_posesor);

    while(1){
        //meniu telefon
        printf("\n--- MENIU TELEFON 2FA ---\n");
        printf("1. Vezi coduri OTP\n");
        printf("2. Asteapta Notificari Push (Mod activ)\n");
        printf("Alegere: ");
        int opt;
        scanf("%d", &opt);
        getchar();

        if(opt == 1){
            printf("Pentru ce aplicatie vrei codul?: ");
            char app_ceruta[50];
            scanf("%s", app_ceruta);

            //cerere afisare cod OTP
            sprintf(msg, "GET_CODE %s %s", nume_posesor, app_ceruta);
            aplica_xor(msg, 1024);
            write(sd, msg, 1024);

            bzero(msg, 1024);
            int bytes_otp = 0;
            while(bytes_otp < 1024){
                int n = read(sd, msg + bytes_otp, 1024 - bytes_otp);
                if(n <= 0) break;
                bytes_otp += n;
            }
            aplica_xor(msg, 1024);
            printf("\n[COD OTP] %s\n", msg);
        }
        else if(opt == 2){
            //asteptam notificarile push
            int ramane_activ = 1;
            while(ramane_activ){
                printf("[telefon] Asteptam notificari...)\n");
                bzero(msg, 1024);
                if(read(sd, msg, 1024) <= 0) break;
                aplica_xor(msg, 1024);

                if(strstr(msg, "NOTIFICARE_APROBARE") != NULL){
                    printf("\n!!! NOTIFICARE NOUA !!!\n%s\nAprobi? (da/nu): ", msg);
                    fflush(stdout);

                    char rasp[1024];
                    scanf("%s", rasp);
                    aplica_xor(rasp, 1024);
                    write(sd, rasp, 1024);

                    printf("Doriti sa ramaneti in modul activ? (1-Da / 0-Nu): ");
                    int continuare;
                    scanf("%d", &continuare);
                    if(continuare == 0) ramane_activ = 0; 
                }
            }
        }
    }

    //inchidere socket
    close(sd);
    return 0;
}