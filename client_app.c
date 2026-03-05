/*CLIENT APP - SIMULEAZA BROWSER-UL UNDE VREA UTILIZATORUL SA SE LOGHEZE*/

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


#define PORT_SERVER_APP 2909

//criptare
#define XOR_KEY 'K'
void aplica_xor(char *msg, int len){
    for(int i = 0; i < len; ++i){
        msg[i] = msg[i] ^ XOR_KEY;
    }
}

int main(int argc, char *argv[]){
    int sd;
    struct sockaddr_in server;
    char mesaj[1024];
    int optiune;
    char nume_aplicatie[50];
    char nume_utilizator[50];

    if(argc != 2){
        printf("[browser] Sintaxa: %s <adresa_ip_server>\n", argv[0]);
        return -1;
    }

    //cream socket ul
    if((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
        perror("[browser] Eroare la socket()\n");
        return errno;
    }

    //configuram adresa serverului
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(argv[1]);
    server.sin_port = htons(PORT_SERVER_APP);

    //incercam sa ne conectam la server
    if(connect(sd, (struct sockaddr *) &server, sizeof(struct sockaddr)) == -1){
        perror("[browser] Eroare la connect() catre server_app\n");
        return errno;
    }

    //interfata utilizator
    printf("\n============================================\n");
    printf("   BINE ATI VENIT LA SISTEMUL DE LOGARE\n");
    printf("============================================\n");
    printf("Selectati aplicatia pe care vreti sa o accesati:\n");
    printf("1. Banca Transilvania\n");
    printf("2. Platforma Facultate\n");
    printf("3. Facebook\n");
    printf("4. YouTube\n");
    printf("5. Gmail\n");
    printf("0. Iesire\n");
    printf("--------------------------------------------\n");
    printf("Alegerea dumneavoastra: ");
    
    scanf("%d", &optiune);
    getchar(); //curatam buffer-ul

    switch (optiune)
    {
        case 1: strcpy(nume_aplicatie, "banca"); break;
        case 2: strcpy(nume_aplicatie, "facultate"); break;
        case 3: strcpy(nume_aplicatie, "facebook"); break;
        case 4: strcpy(nume_aplicatie, "youtube"); break;
        case 5: strcpy(nume_aplicatie, "gmail"); break;
        case 0: printf("La revedere!\n"); close(sd); return 0;
        default: printf("Optiune invalida!\n"); close(sd); return 0;
    }

    printf("Introduceti numele de utilizator: ");
    fgets(nume_utilizator, 50, stdin);
    nume_utilizator[strcspn(nume_utilizator, "\n")] = 0;

    int metoda;
    printf("\nAlegeti metoda de autentificare 2FA:\n");
    printf("1. Introducere cod OTP (de pe aplicatia 2FA)\n");
    printf("2. Notificare Push (aprobare in aplicatia 2FA)\n");
    printf("Alegere: ");
    scanf("%d", &metoda);
    getchar();

    //cerem parola stiuta de utilizator
    char parola[50];
    printf("Introduceti parola aplicatiei: ");
    scanf("%s", parola);
    getchar();

    //pregatim mesajul pentru server
    bzero(mesaj, 1024);
    sprintf(mesaj, "%s:%s:%d:%s", nume_utilizator, nume_aplicatie, metoda, parola);
    printf("\n[browser] Se trimit datele de login catre server...\n");

    aplica_xor(mesaj, 1024);
    if(write(sd, mesaj, 1024) <= 0){
        perror("[browser] Eroare la write() catre server\n");
        return errno;
    }

    //asteptam raspunsul de la server app (cererea de cod OTP)
    bzero(mesaj, 1024);
    if(read(sd, mesaj, 1024) <= 0){
        printf("[browser] Serverul a inchis conexiunea.\n");
    }
    else {
        aplica_xor(mesaj, 1024);
        //caz 1: cerere OTP
        if(strstr(mesaj, "COD_OTP_REQUIRED") != NULL){
            char cod_otp[1024];
            bzero(cod_otp, 1024);
            printf("Cod OTP: ");
            scanf("%s", cod_otp);

            aplica_xor(cod_otp, 1024);
            write(sd, cod_otp, 1024);

            bzero(mesaj, 1024);
            read(sd, mesaj, 1024);
            aplica_xor(mesaj, 1024);
            printf("\n[REZULTAT FINAL] %s\n", mesaj);
        }
        //caz 2: asteptare notificare
        else if(strstr(mesaj, "WAITING_PUSH") != NULL){
            printf("\n[2FA] O notificare a fost trimisa pe telefonul dvs. Va rugam sa o aprobati...\n");
            bzero(mesaj, 1024);
            read(sd, mesaj, 1024);
            aplica_xor(mesaj, 1024);
            printf("\n[REZULTAT FINAL] %s\n", mesaj);
        }
        else{
            printf("\n[EROARE] %s\n", mesaj);
        }
    }

    //inchidem socketul
    close(sd);
    printf("\n============================================\n");
    return 0;
}