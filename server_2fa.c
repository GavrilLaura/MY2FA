/*SERVERUL CENTRAL - GESTIONEAZA VALIDAREA CODURILOR SI NOTIFICARILE*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>

#define PORT 2908

extern int errno;

typedef struct thData{
    int idThread;
    int cl;
} thData;

//structura cu datele fiecarui utilizator din fisier
struct Utilizator{
    char nume[50];
    unsigned long parola_hash;
    char aplicatie[50];
    int cod_otp;
} lista_utilizatori[100];
int total_utilizatori = 0;

//mutex utilizatori
pthread_mutex_t lacat = PTHREAD_MUTEX_INITIALIZER;

//structura pentru a asocia un nume de utilizator cu socket ul lui activ
struct ClientOnline{
    char nume[50];
    int socket_telefon;
    char raspuns_pending[10];
} clienti_online[100];
int nr_clienti_online = 0;

//mutex clienti online
pthread_mutex_t lacat_clienti = PTHREAD_MUTEX_INITIALIZER;

void raspunde(void *arg);
void incarca_date_utilizatori();
void *gestioneaza_coduri_otp(void *arg);

//functia de thread - ruleaza in paralel pentru fiecare client conectat
static void *treat(void * arg){
    struct thData tdL;
    tdL = *((struct thData*)arg);
    printf("[thread %d] client conectat\n", tdL.idThread);
    fflush(stdout);
    pthread_detach(pthread_self()); 
    raspunde((struct thData*)arg); 
    close(tdL.cl); 
    free(arg); 
    return(NULL);
}

//functie XOR pentru criptare
#define XOR_KEY 'K'
void aplica_xor(char *msg, int len){
    for(int i = 0; i < 1024; ++i){
        msg[i] = msg[i] ^ XOR_KEY;
    }
}
//functie pentru transformarea parolelor in numere mari
unsigned long genereaza_hash(unsigned char *str){
    unsigned long hash = 5381;
    int c;
    //parcugere sir caracter cu caracter pana la \0
    while((c = *str++)){
        hash = ((hash << 5) + hash) + c; //echivalent cu hash*33+c
    }
    return hash;
}

//funcia de protocol - schimb de mesaje
void raspunde(void *arg){
    char msg[1024]; 
    char msgrasp[1024]; 

    struct thData tdL;
    tdL = *((struct thData*)arg);

    while(1){
        bzero(msg, 1024);
        //citire inainte de xor
        int bytes_cititi_acum = 0;
        int n;
        //fortam programul sa astepte pana cand buffer ul este complet - util pentru xor
        while(bytes_cititi_acum < 1024){
            n = read(tdL.cl, msg + bytes_cititi_acum, 1024 - bytes_cititi_acum);
            if(n <= 0) {
                printf("[thread %d] Clientul a inchis conexiunea.\n", tdL.idThread);
                //scoatem clientul din tabloul clienti_online
                pthread_mutex_lock(&lacat_clienti);
                for(int k = 0; k < nr_clienti_online; k++) {
                    if(clienti_online[k].socket_telefon == tdL.cl) {
                        for(int j = k; j < nr_clienti_online - 1; j++) {
                            clienti_online[j] = clienti_online[j+1];
                        }
                        nr_clienti_online--;
                        break;
                    }
                }
                pthread_mutex_unlock(&lacat_clienti);
                return;
            }
            bytes_cititi_acum += n;
        }

        aplica_xor(msg, 1024);

        if(strstr(msg, "IDENTIFICARE:") != NULL){
            char *nume_user = msg + 13;
            int exista_in_bd = 0;

            //verificam daca utilizatorul exista in baza de date (pentru telefon)
            pthread_mutex_lock(&lacat);
            for(int i = 0; i < total_utilizatori; i++) {
                if(strcmp(lista_utilizatori[i].nume, nume_user) == 0) {
                    exista_in_bd = 1;
                    break;
                }
            }
            pthread_mutex_unlock(&lacat);

            if(exista_in_bd == 0) {
                printf("[server 2FA] Respins: %s nu exista in baza de date.\n", nume_user);
                strcpy(msgrasp, "EROARE_IDENTIFICARE");
                aplica_xor(msgrasp, 1024);
                write(tdL.cl, msgrasp, 1024);
                continue; 
            }
            //verificam daca utilizatorul este deja online
            pthread_mutex_lock(&lacat_clienti);
            int gasit_online = 0;
            for(int k=0; k<nr_clienti_online; k++) {
                if(strcmp(clienti_online[k].nume, nume_user) == 0) {
                    clienti_online[k].socket_telefon = tdL.cl;
                    strcpy(clienti_online[k].raspuns_pending, "NONE");
                    gasit_online = 1; break;
                }
            }
            //adaugare utilizator nou
            if(gasit_online == 0) {
                strcpy(clienti_online[nr_clienti_online].nume, nume_user);
                clienti_online[nr_clienti_online].socket_telefon = tdL.cl;
                strcpy(clienti_online[nr_clienti_online].raspuns_pending, "NONE");
                nr_clienti_online++;
            }
            pthread_mutex_unlock(&lacat_clienti);

            strcpy(msgrasp, "IDENTIFICARE_OK");
            aplica_xor(msgrasp, 1024);
            write(tdL.cl, msgrasp, 1024);
            continue;
        }
        //raspuns pentru notificarea push
        if(strcmp(msg, "da") == 0 || strcmp(msg, "nu") == 0){
            pthread_mutex_lock(&lacat_clienti);
            for(int j=0; j<nr_clienti_online; ++j){
                if(clienti_online[j].socket_telefon == tdL.cl){
                    strcpy(clienti_online[j].raspuns_pending, msg);
                    printf("[server 2FA] Am salvat raspunsul '%s' de la %s\n", msg, clienti_online[j].nume);
                    break;
                }
            }
            pthread_mutex_unlock(&lacat_clienti);
            continue;
        }

        char comanda[50];
        char nume[50];
        char app[50];
        char cod_primit_str[50];

        sscanf(msg, "%s %s %s %s", comanda, nume, app, cod_primit_str);
        bzero(msgrasp, 1024);

        //verificare daca utilizatorul exista (pentru browser)
        if(strcmp(comanda, "CHECK_USER") == 0) {
            int exista = 0;
            pthread_mutex_lock(&lacat);
            for(int i = 0; i < total_utilizatori; i++) {
                if(strcmp(lista_utilizatori[i].nume, nume) == 0 && strcmp(lista_utilizatori[i].aplicatie, app) == 0) {
                    exista = 1; break;
                }
            }
            pthread_mutex_unlock(&lacat);

            if(exista == 1) strcpy(msgrasp, "USER_FOUND");
            else strcpy(msgrasp, "USER_NOT_FOUND");
            
            aplica_xor(msgrasp, 1024);
            write(tdL.cl, msgrasp, 1024);
            continue;
        }
        //verificare prima parola
        if(strcmp(comanda, "VERIF_CREDENTIALE") == 0) {
            unsigned long h_calculat = genereaza_hash((unsigned char*)cod_primit_str);
            int gasit = 0;

            pthread_mutex_lock(&lacat);
            for(int i = 0; i < total_utilizatori; i++) {
                if(strcmp(lista_utilizatori[i].nume, nume) == 0 && strcmp(lista_utilizatori[i].aplicatie, app) == 0) {
                    if(lista_utilizatori[i].parola_hash == h_calculat) {
                        gasit = 1;
                    }
                    break;
                }
            }
            pthread_mutex_unlock(&lacat);

            if(gasit == 1) strcpy(msgrasp, "LOGIN_OK");
            else strcpy(msgrasp, "LOGIN_FAILED");

            aplica_xor(msgrasp, 1024);
            write(tdL.cl, msgrasp, 1024);
            continue;
        }
        //verificare cod OTP
        if(strcmp(comanda, "VERIF_OTP") == 0){
            int cod_primit = atoi(cod_primit_str);
            int gasit = 0;
            int valid = 0;

            pthread_mutex_lock(&lacat);
            for(int i=0; i<total_utilizatori; i++){
                if(strcmp(lista_utilizatori[i].nume, nume) == 0 && strcmp(lista_utilizatori[i].aplicatie, app) == 0){
                    gasit = 1;
                    if(lista_utilizatori[i].cod_otp == cod_primit) valid = 1;
                    break;
                }
            }
            pthread_mutex_unlock(&lacat);

            if(valid == 1){
                sprintf(msgrasp, "AUTENTIFICARE REUSITA: Codul %d pentru %s este corect.", cod_primit, app);
            }
            else if(gasit == 1){
                sprintf(msgrasp, "EROARE: Codul OTP introdus este gresit sau a expirat.");
            }
            else{
                sprintf(msgrasp, "EROARE: Utilizatorul nu are 2FA activat pentru aceasta aplicatie.");
            }
        }
        //trimitere notificare aprobare logare
        else if(strcmp(comanda, "SEND_PUSH") == 0){
            int socket_destinatie = -1;
            int idx = -1;
            pthread_mutex_lock(&lacat_clienti);
            for(int i=0; i<nr_clienti_online; ++i){
                if(strcmp(clienti_online[i].nume, nume) == 0){
                    socket_destinatie = clienti_online[i].socket_telefon;
                    idx = i;
                    break;
                }
            }
            pthread_mutex_unlock(&lacat_clienti);

            if(socket_destinatie != -1){
                pthread_mutex_lock(&lacat_clienti);
                strcpy(clienti_online[idx].raspuns_pending, "NONE"); 
                pthread_mutex_unlock(&lacat_clienti);

                sprintf(msgrasp, "NOTIFICARE_APROBARE: Cineva vrea sa se logheze la %s. Aprobi?", app);
                aplica_xor(msgrasp, 1024);
                write(socket_destinatie, msgrasp, 1024);

                int timeout = 60;
                while(strcmp(clienti_online[idx].raspuns_pending, "NONE") == 0 && timeout > 0){
                    sleep(1); timeout--;
                }
                
                bzero(msgrasp, 1024);
                if(strcmp(clienti_online[idx].raspuns_pending, "da") == 0){
                    sprintf(msgrasp, "AUTENTIFICARE REUSITA: Utilizatorul a aprobat notificarea.");
                }
                else{
                    sprintf(msgrasp, "EROARE: Utilizatorul a respins notificarea sau timeout.");
                }
                strcpy(clienti_online[idx].raspuns_pending, "NONE");
            }
            else{
                sprintf(msgrasp, "EROARE: Telefonul utilizatorului nu este conectat.");
            }
        }
        //gererare cod OTP
        else if(strcmp(comanda, "GET_CODE") == 0){
            pthread_mutex_lock(&lacat);
            int gasit = 0;
            for(int i=0; i<total_utilizatori; i++){
                if(strcmp(lista_utilizatori[i].nume, nume) == 0 && strcmp(lista_utilizatori[i].aplicatie, app) == 0){
                    sprintf(msgrasp, "Codul tau pentru %s este: %d", app, lista_utilizatori[i].cod_otp);
                    gasit = 1;
                    break;
                }
            }
            pthread_mutex_unlock(&lacat);
            if(gasit == 0) strcpy(msgrasp, "Aplicatie negasita in lista ta.");
        }
        //caz pentru comanda neidentificata
        else{
            sprintf(msgrasp, "COMANDA_NECUNOSCUTA");
        }
        aplica_xor(msgrasp, 1024);
        write(tdL.cl, msgrasp, 1024);
    }
}

//initializarea bazei de date cu utilizatori
void incarca_date_utilizatori(){
    FILE *fisier = fopen("utilizatori.txt", "r");
    if(fisier == NULL){
        perror("Eroare la deschiderea fisierului utilizatori.txt");
        exit(1);
    }
    while(fscanf(fisier, "%s %s %lu", lista_utilizatori[total_utilizatori].nume, lista_utilizatori[total_utilizatori].aplicatie, &lista_utilizatori[total_utilizatori].parola_hash) !=EOF){
        lista_utilizatori[total_utilizatori].cod_otp = 0;
        total_utilizatori++;
    }
    fclose(fisier);
    printf("[server 2FA] Am incarcat cu succes %d utilizatori.\n", total_utilizatori);
}

//generator coduri OTP valabile timp de 1 min
void *gestioneaza_coduri_otp(void *arg){
    srand(time(NULL)); 
    while(1){
        pthread_mutex_lock(&lacat);
        for(int i=0; i<total_utilizatori; ++i){
            lista_utilizatori[i].cod_otp = 100000 + rand() % 900000;
        }
        pthread_mutex_unlock(&lacat);
        printf("[server 2FA] Am generat coduri noi OTP valabile 1 min.\n");
        sleep(60);
    }
    return NULL;
}

int main(){
    struct sockaddr_in server; 
    struct sockaddr_in from; 
    int sd;

    incarca_date_utilizatori();

    pthread_t th_gestionar;
    pthread_create(&th_gestionar, NULL, &gestioneaza_coduri_otp, NULL);

    if((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("[server_2fa]eroare la socket()\n");
        return errno;
    }

    int on=1;
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    bzero(&server, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl (INADDR_ANY); 
    server.sin_port = htons (PORT); 

    if(bind(sd, (struct sockaddr *) &server, sizeof(struct sockaddr)) == -1) {
        perror("[server_2fa]eroare la bind()\n");
        return errno;
    }

    if(listen(sd, 5) == -1) {
        perror("[server_2fa]eroare la listen()\n");
    }

    printf("[server_2fa]asteptam conexiuni la portul %d ...\n", PORT);
    fflush(stdout);

    int i = 0;
    while(1){
        int client;
        thData * td;
        unsigned int len = sizeof(from);
        
        if((client = accept(sd, (struct sockaddr *) &from, &len)) < 0){
            perror("[server_2fa]eroare la accept()\n");
            continue; 
        }

        td = (struct thData*)malloc(sizeof(struct thData));
        td->idThread = i++;
        td->cl = client;

        pthread_t t;
        if(pthread_create(&t, NULL, &treat, td) != 0 ){
            perror("Eroare la creare thread client");
        }
    }
}