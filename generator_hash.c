#include <stdio.h>
#include <stdlib.h>

unsigned long genereaza_hash(unsigned char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

int main() {
    FILE *f = fopen("utilizatori.txt", "w");
    if (f == NULL) {
        perror("Eroare la creare fisier");
        return 1;
    }

    //lista de utilizatori si parolele lor
    fprintf(f, "andrei banca %lu\n", genereaza_hash((unsigned char*)"parola111"));
    fprintf(f, "andrei facultate %lu\n", genereaza_hash((unsigned char*)"parola222"));
    fprintf(f, "andrei facebook %lu\n", genereaza_hash((unsigned char*)"parola333"));
    fprintf(f, "andrei youtube %lu\n", genereaza_hash((unsigned char*)"parola444"));
    fprintf(f, "andrei gmail %lu\n", genereaza_hash((unsigned char*)"parola555"));
    fprintf(f, "ioan facultate %lu\n", genereaza_hash((unsigned char*)"PC97bGo5F"));
    fprintf(f, "maria youtube %lu\n", genereaza_hash((unsigned char*)"NPg68jF51s"));
    fprintf(f, "alex banca %lu\n", genereaza_hash((unsigned char*)"parolaAlex"));
    fprintf(f, "elena facebook %lu\n", genereaza_hash((unsigned char*)"passElena"));
    fprintf(f, "mihai gmail %lu\n", genereaza_hash((unsigned char*)"mihai123"));
    fprintf(f, "cristina youtube %lu\n", genereaza_hash((unsigned char*)"cris_pass"));
    fprintf(f, "vlad facultate %lu\n", genereaza_hash((unsigned char*)"vlad_fac"));
    fprintf(f, "dana banca %lu\n", genereaza_hash((unsigned char*)"dana_banca"));
    fprintf(f, "radu gmail %lu\n", genereaza_hash((unsigned char*)"radu_gmail"));
    fprintf(f, "laura facebook %lu\n", genereaza_hash((unsigned char*)"laura_fb"));

    fclose(f);
    return 0;
}