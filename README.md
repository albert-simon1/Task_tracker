/*Programul TaskTracker este impartit in 2 parti:
Prima parte-autentificarea, inregistrarea si modficarea utilizatorilor. 

Clasa Registered_users se ocupa cu verificarea daca un utilizator este sau nu existent in sistem, iar in cazul in care este si se autentifica cu username-ul si parola corecta, acesta primeste "acces" si la clasele derivate lui Registered_users(adica are acces la schimbarea numelui de utilizator, a parolei si stergerea completa a utilizatorului din sistem)

Clasa New_User este derivata clasei Registered_users si se ocupa cu adaugarea in sistem a noilor utilizatori. In cazul in care username-ul nu este deja folosit, are minim 8 caractere si introduce o parola valida, acestuia i se creaza un fisier personalizat in care ii vor fi stocate Task-urile pe care le are de indeplinit. Altfel, acesta "arunca" o eroare precum "numele de utilizator este deja folosit"

Clasa User_manager este derivata clasei registered_users si reprezinta o interfata pentru diferite actiuni precum schimbarea numelui de utilizator, stergerea utilizatorului din sistem si schimbarea parolei. Este o interfata datoria functiei virtuale pure, aceasta fiind suprascris in fiecare clasa derivata(change_username,change_password,delete_user), iar toate aceste actiuni sunt organizate intr-o singura clasa CommandExecutor care are ca atribut un pointer la clasa de baza(User_manager)

A doua parte - Gestiunea task-urilor
Clasa User_files este clasa de bază pentru gestionarea fișierelor utilizatorilor. Ea verifică autentificarea prin username și parolă, aruncând excepții specifice (InvalidPassword, UsernameNotFound) în caz de eroare. De asemenea, impune reguli pentru username și parolă (minim 8 caractere) și ține evidența numărului de utilizatori prin variabila statică users_count.

Clasa Task_Manager este o clasă abstractă derivată din User_files care reprezintă baza pentru toate operațiile legate de task-uri. Conține un nume de task (task_name) și o metodă pur virtuală action() care va fi implementată de clasele derivate pentru operatii specifice (adaugare, ștergere, etc.).

Clasa Add_Task este derivată din Task_Manager și se ocupă cu adăugarea unui nou task în fișierul utilizatorului. Un task conține:
-Numele task-ului
-Descriere (scrisă între ghilimele în fișier)
-Data limită (zi/lună)
-Prioritate (un număr întreg)

Clasa CompletedTasks este derivată din Task_Manager și are rolul de a marca un task ca fiind completat. Aceasta mută task-ul din fișierul principal al utilizatorului într-un fișier special pentru task-uri finalizate (username_completed_tasks.txt).

Clasa inProgressTasks este derivată din Task_Manager și marchează un task ca fiind în curs de desfășurare. Task-ul este adăugat într-un fișier special (username_inprogress_tasks.txt).

Clasa EditTask este o clasă abstractă derivată din Task_Manager care reprezintă baza pentru operațiile de editare a task-urilor (ștergere, redenumire). Nu implementează metoda action(), lăsând această responsabilitate claselor derivate.

Clasa DeleteTask este derivată din EditTask și se ocupă cu ștergerea unui task din fișierul utilizatorului. Task-ul șters este mutat într-un fișier de arhivă (username_archive.txt) pentru a păstra istoricul.

Clasa RenameTask este derivată din EditTask și permite modificarea numelui unui task existent. Aceasta citește întregul fișier, modifică linia corespunzătoare task-ului și rescrie fișierul cu noul nume.

Clasa ActionHandler este un wrapper similar cu CommandExecutor din prima parte, care gestionează execuția operațiilor pe task-uri prin intermediul unui pointer la clasa de bază Task_Manager. Asigură eliberarea corectă a memoriei prin destructor.

// logger scrie intr-un fisier text si tine evidenta actiunilor care au loc atunci cand un utilizator incearca
//sa se conecteze/daca exista sau nu utilizatorul, daca a gresit parola etc.
//getInstance se asigura ca este o singura instanta a clasei; log(std::string message): scrie mesajul în log.txt (append).
//Clasa SessionManager= Gestionează sesiunea utilizatorului – adică ține minte dacă un utilizator este conectat și cine este acel utilizator.
//getInstance(): singleton.
//login(username): setează utilizatorul curent ca logat.
//logout(): deloghează utilizatorul.
//isLoggedIn(): returnează true/false dacă există utilizator logat.
//getCurrentUser(): returnează numele utilizatorului logat.
//std::string User_files::cripted = "";
//Clasa UserRegistry=Ține o listă internă cu utilizatori înregistrați în aplicație (doar în memorie, nu în fișier).
//getInstance(): singleton.
//login(username): setează utilizatorul curent ca logat.
//logout(): deloghează utilizatorul.
//isLoggedIn(): returnează true/false dacă există utilizator logat.
//getCurrentUser(): returnează numele utilizatorului logat.
*/
