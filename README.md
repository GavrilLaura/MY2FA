# Multi-Factor Authentication (MFA) Simulator

Acest proiect simuleaza procesul de logare securizata in doi pasi (parola + confirmare pe telefon), similar cu sistemele folosite de banci sau servicii email.

## Conceptul proiectului

Sistemul demonstreaza cum o incercare de logare pornita dintr-un browser necesita o validare secundara de pe un dispozitiv mobil pentru a fi finalizata cu succes.

## Componentele sistemului

Proiectul este impartit in patru programe care lucreaza impreuna:

1. **Serverul 2FA:** Gestioneaza baza de date, verifica parolele, genereaza coduri de securitate si trimite notificari catre telefoane.
2. **Serverul App:** Intermediar intre interfata de logare si serverul de securitate.
3. **Clientul Browser:** Interfata in care utilizatorul isi introduce datele de acces.
4. **Clientul Telefon:** Aplicatia care simuleaza dispozitivul mobil ce afiseaza codul OTP sau primeste cererea de aprobare.

## Fluxul de utilizare

* Utilizatorul introduce numele si parola in browser.
* Daca parola este corecta, sistemul cere a doua etapa de verificare.
* Utilizatorul foloseste telefonul pentru a genera un cod de 6 cifre sau pentru a aproba o notificare push (da/nu).
* Accesul este permis doar daca ambele verificari sunt validate de server.

## Detalii tehnice

* Criptare: Mesajele sunt protejate prin algoritm XOR pe durata transferului.
* Coduri OTP: Generare de coduri temporare care expira dupa 60 de secunde.
* Comunicatie: Realizata prin socket-uri TCP/IP in limbajul C.
