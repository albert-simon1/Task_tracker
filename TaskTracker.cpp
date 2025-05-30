#include "TaskTracker.h"
#include <memory>


std::string User_files::cripted = "";
int User_files::users_count = 0;
std::string Admin::admin_pwd = "";

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

void Logger::log(const std::string& message) {
    std::ofstream logfile("log.txt", std::ios::app);
    if (logfile) {
        logfile << message << std::endl;
    }
}


SessionManager& SessionManager::getInstance() {
    static SessionManager instance;
    return instance;
}

void SessionManager::login(const std::string& username) {
    currentUsername = username;
    loggedIn = true;
}

void SessionManager::logout() {
    currentUsername = "";
    loggedIn = false;
}

bool SessionManager::isLoggedIn() const { 
    return loggedIn; 
}

std::string SessionManager::getCurrentUser() const { 
    return currentUsername; 
}


UserRegistry& UserRegistry::getInstance() {
    static UserRegistry instance;
    return instance;
}

void UserRegistry::addUser(const registered_users& user) {
    users.push_back(user);
}

bool UserRegistry::userExists(const std::string& username) {
    return std::any_of(users.begin(), users.end(), [&](const registered_users& u) {
        return u.getUsername() == username;
    });
}


registered_users::registered_users(const std::string& username, const std::string& password)
    : username(username), password(password) {
    if (username.length() < 8 || password.length() < 8) {
        throw std::invalid_argument("Username și parola trebuie să aibă minim 8 caractere.");
    }
    UserRegistry::getInstance().addUser(*this);
}

bool registered_users::verify(const std::string& username, const std::string& password) const {
    return already_used(username, password);
}

std::string registered_users::getUsername() const {
    return username;
}

bool registered_users::log_in(const std::string& username, const std::string& password2) const {
    std::ifstream file("users.txt");
    std::string user_name, pass;

    if (!file) {
        Logger::getInstance().log("Eroare: nu s-a putut deschide fisierul users.txt");
        throw std::invalid_argument("NU am putut deschide fisierul.");
    }

    while (file >> user_name >> pass) {
        if (username == user_name) {
            if (pass == password2) {
                Logger::getInstance().log("Utilizator " + username + " s-a autentificat cu succes.");
                SessionManager::getInstance().login(username);
                return true;
            } else {
                Logger::getInstance().log("Eroare: parola gresita pentru utilizatorul " + username);
                return false;
            }
        }
    }

    Logger::getInstance().log("Eroare: utilizatorul " + username + " nu a fost gasit in users.txt");
    return false;
}

bool registered_users::already_used(const std::string& username, const std::string& password) const {
    std::ifstream file("users.txt");
    std::string user_name, pass;

    if (!file) {
        Logger::getInstance().log("Eroare: nu s-a putut deschide fisierul users.txt pentru verificare");
        throw std::invalid_argument("NU am putut deschide fisierul.");
    }

    while (file >> user_name >> pass) {
        if (username == user_name) {
            Logger::getInstance().log("Verificare: utilizatorul " + username + " este deja inregistrat.");
            return true;
        }
    }
    return false;
}

New_User::New_User(const std::string& user_name, const std::string& pass)
    : registered_users(user_name, pass) {
    if (username.length() < 8 || password.length() < 8) {
        throw std::invalid_argument("Username și parola trebuie să aibă minim 8 caractere.");
    }

    if (registered_users::verify(username, password)) {
        std::cout << "Utilizatorul "<<username<<" deja există. Nu va fi adăugat.\n";
        return;
    }

    std::ofstream file("users.txt", std::ios::app);
    file << username << " " << password << "\n";
    file.close();

    std::ofstream new_file(username + ".txt");
    std::cout << "Fișier creat pentru utilizatorul " << username << "\n";
    new_file.close();

    std::cout << "Utilizator nou creat: " << username << "\n";
}

User_Manager::User_Manager(const std::string& user_name, const std::string& pass)
    : registered_users(user_name, pass) {}

bool User_Manager::verify(const std::string& username, const std::string& password) const {
    return log_in(username, password);
}

Delete_user::Delete_user(const std::string& username, const std::string& password)
    : User_Manager(username, password) {}

void Delete_user::execute() {
    if(!User_Manager::verify(username, password)) {
        std::cout << "Autentificare eșuată. Utilizatorul nu poate fi șters.\n";
        return;
    }
    
    std::ifstream infile("users.txt"); 
    std::ofstream temp("temp.txt");
    std::string user, pass;
    
    while (infile >> user >> pass) {
        if (user != username || pass != password) {
            temp << user << " " << pass << "\n";
        }
    }
    
    infile.close();
    temp.close();
    
    std::remove("users.txt");
    std::rename("temp.txt", "users.txt");
    
    std::string user_file = username + ".txt";
    if (std::remove(user_file.c_str()) == 0) {
        std::cout << "Fișierul " << user_file << " a fost șters.\n";
    } else {
        std::cout << "Fișierul " << user_file << " nu a putut fi șters sau nu există.\n";
    }
    
    std::cout << "Utilizatorul " << username << " a fost șters cu succes.\n";
}

Change_username::Change_username(const std::string& user_name, const std::string& pass, 
                                const std::string& new_user_name)
    : User_Manager(user_name, pass), new_username(new_user_name) {}

void Change_username::execute() {
    if (User_Manager::verify(username, password) && !registered_users::verify(new_username, password)) {
        std::ifstream file("users.txt");
        std::ofstream temp("temp.txt");
        std::string user_name, pass;
        while(file >> user_name >> pass) {
            if(user_name == username) {
                temp << new_username << " " << pass << "\n";
                std::cout << "Buna, " << new_username << "\n";
            } else {
                temp << user_name << " " << pass << "\n";
            }
        }
        file.close();
        temp.close();
        
        std::remove("users.txt");
        std::rename("temp.txt", "users.txt");
        
        std::rename((username + ".txt").c_str(), (new_username + ".txt").c_str());
        
        std::cout << "Utilizatorul a fost modificat cu succes.\n";
    } else {
        if(!User_Manager::verify(username, password)) {
            std::cout << "Utilizatorul sau parola sunt gresite\n";
        } else {
            std::cout << "Numele de utilizator " << new_username << " este deja folosit\n";
        }
    }
}

Change_password::Change_password(const std::string& username, const std::string& old_pass, 
                               const std::string& new_pass)
    : User_Manager(username, old_pass), new_password(new_pass) {}

void Change_password::execute() {
    if (User_Manager::verify(username, password)) {
        std::ifstream file("users.txt");
        std::ofstream temp("temp.txt");
        std::string user_name, pass;
        while(file >> user_name >> pass) {
            if(user_name == username && pass == password) {
                temp << username << " " << new_password << " \n";
            } else {
                temp << user_name << " " << pass << "\n";
            }
        }
        file.close();
        temp.close();
        
        std::remove("users.txt");
        std::rename("temp.txt", "users.txt");
        
        std::cout << "Utilizatorul a fost modificat cu succes.\n";
    }
}

CommandExecutor::CommandExecutor(User_Manager* action) : action(action) {}

void CommandExecutor::run() {
    action->execute();
}

CommandExecutor::~CommandExecutor() {
    delete action;
}

Exceptions::Exceptions(const std::string& message) : message(message) {}

const char* Exceptions::what() const noexcept {
    return message.c_str();
}

InvalidPassword::InvalidPassword(const std::string& password) 
    : Exceptions(password + " is incorrect") {}

UsernameNotFound::UsernameNotFound(const std::string& username) 
    : Exceptions(username + " not registered") {}

Username_Failed::Username_Failed(const std::string& username) 
    : Exceptions(username + " must be at least 8 characters long") {}

Password_Failed::Password_Failed(const std::string& password) 
    : Exceptions(password + " must be at least 8 characters long") {}

login_fail::login_fail(const std::string& username) 
    : Exceptions(username + ", you failed logging in") {}

FileError::FileError(const std::string& msg) : Exceptions(msg) {}

invalidDate::invalidDate(const std::string& msg) : Exceptions(msg) {}

std::string User_files::XORencrypt(const std::string& input, char key) {
    std::string output = input;
    for (size_t i = 0; i < input.size(); i++) {
        output[i] = input[i] ^ key;
    }
    return output;
}

User_files::User_files(const std::string& username, const std::string& password) {
    if(!log_in(username, password)) {
        throw login_fail(username);
    }
    if (username.length() < 8) {
        throw Username_Failed(username);
    }
    if (password.length() < 8) {
        throw Password_Failed(password);
    }
    
    this->username = username;
    this->password = password;
    this->users_count += 1;
    const char key = 'P';
    cripted = XORencrypt(username, key);
    std::ofstream admin("admin.txt", std::ios::app);
    admin << cripted << " ";
    cripted = XORencrypt(password, key);
    admin << cripted << "\n";
    admin.close();
}

bool User_files::valid_login(const std::string& username, const std::string& password) const {
    return log_in(username, password);
}

int User_files::User_count() {
    return users_count;
}

User_files::User_files(const User_files& other) {
    this->username = other.username;
    this->password = other.password;
}

User_files& User_files::operator=(User_files other) {
    std::swap(this->username, other.username);
    std::swap(this->password, other.password);
    return *this;
}

bool User_files::log_in(const std::string& username, const std::string& password2) const {
    std::ifstream file("users.txt");
    std::string user_name, pass;
    
    if (!file) {
        throw std::runtime_error("Could not open users file");
    }
    
    while (file >> user_name >> pass) {
        if (username == user_name) {
            if (pass == password2) {
                return true;
            } else {
                throw InvalidPassword(password2);
            }
        }
    }
    throw UsernameNotFound(username);
}

Task_Manager::Task_Manager(const std::string& username, const std::string& password, 
                          const std::string& task_name)
    : User_files(username, password), task_name(task_name) {
    if(!User_files::valid_login(username, password)) {
        throw login_fail(username);
    }
}

Add_Task::Add_Task(const std::string& name, const std::string& description, const int& day_due, 
                   const int& month_due, const int& priority, const std::string& username, 
                   const std::string& password)
    : Task_Manager(username, password, name), name(name), description(description), 
      day_due(day_due), month_due(month_due), priority(priority) {}

void Add_Task::action() {
    std::ofstream file(username + ".txt", std::ios::app);
    if(!file.is_open()) {
        throw FileError("File cannot be opened");
    }
    file << name << " \"" << description << "\" Due " << day_due << "/" << month_due 
         << " Priority " << priority << "\n";
    file.close();
}

CompletedTasks::CompletedTasks(const std::string& username, const std::string& password, 
                             const std::string& task_name)
    : Task_Manager(username, password, task_name) {}

void CompletedTasks::action() {
    std::ofstream file(username + "_completed_tasks.txt", std::ios::app);
    file << task_name << "\n";
    file.close();
}

inProgressTasks::inProgressTasks(const std::string& username, const std::string& password, 
                               const std::string& task_name)
    : Task_Manager(username, password, task_name) {}

void inProgressTasks::action() {
    std::ofstream outfile(username + "_inprogress_tasks.txt", std::ios::app);
    outfile << task_name << "\n";
    outfile.close();
    std::cout << "Task-ul '" << task_name << "' a fost marcat ca în curs.\n";
}

EditTask::EditTask(const std::string& username, const std::string& password, 
                  const std::string& task_name)
    : Task_Manager(username, password, task_name) {}

DeleteTask::DeleteTask(const std::string& username, const std::string& password, 
                      const std::string& task_name)
    : EditTask(username, password, task_name) {}

void DeleteTask::action() {
    std::ifstream inFile(username + ".txt");
    if (!inFile.is_open()) {
        throw std::runtime_error("Nu s-a putut deschide fișierul pentru citire: " + username + ".txt");
    }
    std::ofstream archive(username + "_archive.txt", std::ios::app);
    if (!archive.is_open()) {
        throw std::runtime_error("Nu s-a putut deschide fișierul pentru arhivare pentru utilizatorul " + username);
    }

    std::vector<std::string> remainingLines;
    std::string line;

    while (std::getline(inFile, line)) {
        std::istringstream iss(line);
        std::string name;
        iss >> name;

        if (name != task_name) {
            remainingLines.push_back(line);
        } else {
            archive << line << "\n";
        }
    }

    inFile.close();

    std::ofstream outFile(username + ".txt");
    if (!outFile.is_open()) {
        throw std::runtime_error("Nu s-a putut deschide fișierul pentru scriere: " + username + ".txt");
    }

    for (const auto& remainingLine : remainingLines) {
        outFile << remainingLine << '\n';
    }

    outFile.close();
}

template<typename T>
RenameTask<T>::RenameTask(const std::string& username, const std::string& password, 
                         const T& old_name, const T& new_name)
    : EditTask(username, password, std::string(old_name)), 
      new_name(new_name), task_name(old_name) {}

template<typename T>
void RenameTask<T>::action() {
    std::ifstream inFile(username + ".txt");
    std::ofstream outFile(username + "_temp.txt");

    if (!inFile.is_open() || !outFile.is_open()) {
        std::cerr << "Eroare la deschiderea fișierului!\n";
        return;
    }

    std::string line;
    while (std::getline(inFile, line)) {
        std::istringstream iss(line);
        T name;
        iss >> name;

        if (name == task_name) {
            size_t pos = line.find(std::string(task_name));
            if (pos != std::string::npos) {
                line.replace(pos, std::string(task_name).length(), std::string(new_name));
            }
        }
        outFile << line << "\n";
    }

    inFile.close();
    outFile.close();

    std::remove((username + ".txt").c_str());
    std::rename((username + "_temp.txt").c_str(), (username + ".txt").c_str());
}

template<typename T>
T RenameTask<T>::getNewName() const {
    return new_name;
}

template<typename U>
void printRenameTaskInfo(const RenameTask<U>& task) {
    std::cout << "Task-ul este redenumit în: " << task.getNewName() << "\n";
}

// Change_due_date implementation
Change_due_date::Change_due_date(const std::string& username, const std::string& password, 
                                const std::string& task_name, int new_due_day, int new_due_month)
    : EditTask(username, password, task_name), new_due_day(new_due_day), new_due_month(new_due_month) {
    if(new_due_month <= 12 && new_due_month > 0 && new_due_day > 0 && new_due_day <= 31) {
        if(new_due_day > number_of_days_in_a_month(new_due_month)) {
            throw invalidDate("Data introdusa este invalida\n");
        }
    } else {
        throw invalidDate("Data introdusa este invalida\n");
    }
}

int Change_due_date::number_of_days_in_a_month(const int& new_due_month) {
    if (new_due_month == 1 || new_due_month == 3 || new_due_month == 5 || 
        new_due_month == 7 || new_due_month == 8 || new_due_month == 10 || new_due_month == 12) {
        return 31;
    }
    if(new_due_month == 2) {
        return 28;
    }
    return 30;
}

void Change_due_date::action(const std::string& username, const std::string& task_name, 
                            int& new_due_day, int& new_due_month) {
    std::ifstream infile(username + ".txt");
    if (!infile.is_open()) {
        throw std::runtime_error("Nu s-a putut deschide fișierul pentru scriere: " + username + ".txt");
    }
    std::ofstream outfile("temp.txt", std::ios::app);
    if (!outfile.is_open()) {
        throw std::runtime_error("Nu s-a putut deschide fișierul pentru scriere: " + username + ".txt");
    }

    std::string line;
    while (std::getline(infile, line)) {
        std::istringstream iss(line);
        std::string name_t, description_t;
        int day_due_t, month_due_t;
        int priority_t;
        char quote;
        iss >> name_t;
        iss >> quote;
        std::getline(infile, description_t, '"');
        if(name_t == task_name) {
            outfile << task_name << " " << description_t << " " << new_due_day << " " 
                   << new_due_month << " " << priority_t << "\n";
        } else {
            outfile << task_name << " " << description_t << " " << day_due_t << " " 
                   << month_due_t << " " << priority_t << "\n";
        }
    }
    infile.close();
    outfile.close();
    std::remove((username + ".txt").c_str()); 
    std::rename("temp.txt", (username + ".txt").c_str());
}

// Admin implementation
Admin::Admin(const std::string& pwd) {
    if(User_files::XORencrypt(pwd, admin_key) == admin_pwd) {
        acces = true;
    } else {
        throw InvalidPassword(pwd);
    }
}

void Admin::initialize_password(const std::string& pwd) {
    admin_pwd = User_files::XORencrypt(pwd, admin_key);
}

// ActionHandler implementation
ActionHandler::ActionHandler(Task_Manager* task) : task(task) {}

void ActionHandler::run() {
    task->action();
}

ActionHandler::~ActionHandler() {
    delete task;
}

// Test functions implementation
void test_admin_initializare() {
    std::cout << "\n=== TESTE INITIALIZARE ADMIN ===\n";
    
    try {
        Admin::initialize_password("adminSecret123");
        std::cout << "[PASS] Inițializare parolă admin reușită\n";
    } catch (...) {
        std::cout << "[FAIL] Inițializare parolă admin a eșuat\n";
    }

    try {
        Admin admin("adminSecret123");
        std::cout << "[PASS] Autentificare admin cu parolă corectă\n";
    } catch (const InvalidPassword& e) {
        std::cout << "[FAIL] Autentificare admin cu parolă corectă: " << e.what() << "\n";
    } catch (...) {
        std::cout << "[FAIL] Eroare neașteptată la autentificare admin\n";
    }

    try {
        Admin admin("parolaGresita");
        std::cout << "[FAIL] Autentificare admin cu parolă greșită nu a aruncat excepție\n";
    } catch (const InvalidPassword& e) {
        std::cout << "[PASS] Autentificare admin cu parolă greșită a aruncat InvalidPassword\n";
    } catch (...) {
        std::cout << "[FAIL] Autentificare admin a aruncat alt tip de excepție\n";
    }
}

void test_admin_acces_fisiere() {
    std::cout << "\n=== TESTE ACCES FISIERE ADMIN ===\n";
    
    try {
        Admin admin("adminSecret123");
        std::ifstream adminFile("admin.txt");
        
        if (!adminFile) throw FileError("Nu s-a putut deschide admin.txt");
        
        std::cout << "[PASS] Acces fișier admin reușit\n";
        adminFile.close();
    } catch (const FileError& e) {
        std::cout << "[FAIL] Acces fișier admin: " << e.what() << "\n";
    } catch (...) {
        std::cout << "[FAIL] Eroare neașteptată la acces fișier admin\n";
    }
}

void test_creare_utilizator() {
    try {
        New_User nou_utilizator("JohnDoee", "parola123");
        std::cout << "Test crearea utilizatorului JohnDoee a fost realizat cu succes.(respecta restrictiile pentru username,sa nu fie \n deja folosit si sa aiba lungime de 8 caractere)\n\n";
    } catch (const std::exception& e) {
        std::cout << "Eroare: " << e.what() << std::endl;
    }
}

void test_logare_utilizator() {
    try {
        registered_users utilizator("JohnDoee", "parola123");

        if (utilizator.verify("JohnDoee", "parola123")) {
            std::cout << "Test logare utilizator JohnDoee - succes.\n\n";
        } else {
            std::cout << "Test logare utilizator - eșec.\n";
        }
    } catch (const std::exception& e) {
        std::cout << "Eroare: " << e.what() << std::endl;
    }
}

void test_modificare_parola() {
    try {
        Change_password schimbare_parola("JohnDoee", "parola123", "parolaNoua");
        schimbare_parola.execute();
        std::cout << "Test schimbare parolă - succes.\n";
    } catch (const std::exception& e) {
        std::cout << "Eroare: " << e.what() << std::endl;
    }
}

void test_stergere_utilizator() {
    try {
        Delete_user stergere_utilizator("JohnDoee", "parolaNoua");
        stergere_utilizator.execute();
        std::cout << "Test ștergere utilizator JohnDoee - succes(dupa ce am modificat parola utilizatorului).\n\n";
    } catch (const std::exception& e) {
        std::cout << "Eroare: " << e.what() << std::endl;
    }
}

void test_adaugare_task() {
    try {
        Add_Task task("TaskImportant", "Descriere task", 12, 5, 1, "JohnDoee", "parolaNoua");
        task.action();
        std::cout << "Test adăugare task cu numele TaskImportant in fisierul personal al Utilizatorului JohnDoee - succes.\n\n";
    } catch (const std::exception& e) {
        std::cout << "Eroare: " << e.what() << std::endl;
    }
}

void test_finalizare_task() {
    try {
        CompletedTasks task_finalizat("JohnDoee", "parolaNoua", "TaskImportant");
        task_finalizat.action();
        std::cout << "Test finalizare task - succes.(dupa ce am terminat task-ul il mut in fisierul cu task-uri completate ale utilizatorului JohnDoee)\n\n";
    } catch (const std::exception& e) {
        std::cout << "Eroare: " << e.what() << std::endl;
    }
}

void test_redenumire_task() {
    try {
        RenameTask<std::string> redenumire_task("JohnDoee", "parolaNoua", "TaskImportant", "TaskNou");
        redenumire_task.action();
        std::cout << "Test redenumire task(TaskImportant devine TaskNou) - succes.\n\n";
    } catch (const std::exception& e) {
        std::cout << "Eroare: " << e.what() << std::endl;
    }
}

void test_stergere_task() {
    try {
        DeleteTask stergere_task("JohnDoee", "parolaNoua", "TaskImportant");
        stergere_task.action();
        std::cout << "Test ștergere task TaskImportant - succes.\n\n";
    } catch (const std::exception& e) {
        std::cout << "Eroare: " << e.what() << std::endl;
    }
}

void test_creare_utilizator_nume_existenta() {
    try {
        New_User utilizator1("JohnDoee", "parolaNoua");
        std::cout << "Testul pentru crearea unui utilizator cu numele deja existent JohnDoee -succes(Utilizatorul ar fi trebuit să fie respins).\n\n";
    } catch (const std::exception& e) {
        std::cout << "Eroare: " << e.what() << "\n\n";
    }
}

// Funcție pentru testarea logării unui utilizator cu o parolă greșită
void test_logare_utilizator_parola_gresita() {
    try {
        registered_users utilizator("JohnDoee", "parolaGresita");
        if (!utilizator.verify("JohnDoee", "parolaGresita")) {
            std::cout << "Test logare utilizator cu parola greșită - succes(adica JohnDoee a incercat sa se logheze cu o parola gresita si nu a avut succes).\n\n";
        }
        }
     catch (const std::exception& e) {
        std::cout << "Eroare: " << e.what() << std::endl;
    }
}

// Funcție pentru testarea modificării unei parole incorecte
void test_modificare_parola_incorecta() {
    try {

        // Încercăm să schimbăm parola fără a fi autentificat corect
        Change_password schimbare_parola_incorecta("JohnDoee", "parolaGresita", "parolaNoua");
        schimbare_parola_incorecta.execute();
        std::cout << "Test modificare parolă incorectă - succes((utilizatorul JohnDoee a incercat sa se logheze cu o parola incorecta si dupa sa o schimbe)).\n\n";
    } catch (const std::exception& e) {
        std::cout << "Eroare: " << e.what() << std::endl;
    }
}

// Funcție pentru testarea ștergerii unui utilizator care nu există
void test_stergere_utilizator_inexistent() {
    try {
        Delete_user stergere_utilizator("UtilizatorInexistent", "parola123");
        stergere_utilizator.execute();  // Utilizatorul nu există
        std::cout << "Testul pentru ștergerea unui utilizator inexistent-succes(am incercat sa sterg un utilizator care e inexistent) .\n\n";
    } catch (const std::exception& e) {
        std::cout << "Eroare : " << e.what() << std::endl;
    }
}

// Funcție pentru testarea adăugării unui task fără autentificare
void test_adaugare_task_fara_autentificare() {
    try {
        Add_Task task("TaskImportant", "Descriere task", 12, 5, 1, "", "");
        task.action();  // Nu există utilizatorul logat
        std::cout << "Testul pentru adăugarea unui task fără autentificare a eșuat.\n";
    } catch (const std::exception& e) {
        std::cout << "Eroare așteptată: " << e.what() << "\n\n";
    }
}

// Funcție pentru testarea modificării unui task care nu există
void test_modificare_task_inexistent() {
    try {
       RenameTask<std::string> redenumire_task("JohnDoee", "parolaNoua", "TaskInexistent", "TaskNou");
        redenumire_task.action();  // Task-ul nu există
        std::cout << "Testul pentru redenumirea unui task inexistent -succes (am incercat sa modific numele unui task inexistent)\n\n";
    } catch (const std::exception& e) {
        std::cout << "Eroare: " << e.what() << std::endl;
    }
}

// Funcție pentru testarea ștergerii unui task care nu există
void test_stergere_task_inexistent() {
    try {
        DeleteTask stergere_task("JohnDoee", "parolaNoua", "TaskInexistent");
        stergere_task.action();  // Task-ul nu există
        std::cout << "Testul pentru ștergerea unui task inexistent a avut succes (am incercat sa sterg un task care nici macar nu exista).\n\n";
    } catch (const std::exception& e) {
        std::cout << "Eroare: " << e.what() << std::endl;
    }
}

// Funcție pentru testarea redenumirii unui task care nu există


// Funcție pentru testarea autentificării unui utilizator fără nume de utilizator
void test_logare_fara_utilizator() {
    try {
        registered_users utilizator("", "parola123");  // Fără nume de utilizator
        if (!utilizator.verify("", "parola123")) {
            std::cout << "Test logare fără nume de utilizator(programul meu a oprit crearea unui utilizator care nu a specificat username-ul) - succes.\n\n";
        } else {
            std::cout << "Testul fără nume de utilizator a eșuat.\n";
        }
    } catch (const std::exception& e) {
        std::cout << "Eroare: " << e.what() << "\n\n";
    }
}

int main() {
     New_User b("username123","password123");
    Add_Task c("oldTask","2",1,2,3,"username123","password123");
    RenameTask<std::string> task("username123","password123", "oldTask", "newTask");
          try {
        // Creăm utilizator nou (se adaugă automat în UserRegistry și log)
        registered_users user1("username123", "password123");

        // Verificăm dacă utilizatorul a fost adăugat în UserRegistry
        if (UserRegistry::getInstance().userExists("username123")) {
            std::cout << "User 'username123' exists in UserRegistry.\n";
        } else {
            std::cout << "User 'username123' NOT found in UserRegistry.\n";
        }

        // Verificăm dacă userul este deja înregistrat în users.txt
        if (user1.verify("username123", "password123")) {
            std::cout << "User already registered in users.txt.\n";
        } else {
            std::cout << "User not found in users.txt.\n";
        }

        // Facem login manual (deoarece log_in e privat)
        SessionManager::getInstance().login("username123");

        if (SessionManager::getInstance().isLoggedIn()) {
            std::cout << "Session active for user: "
                      << SessionManager::getInstance().getCurrentUser() << "\n";
        } else {
            std::cout << "No active session.\n";
        }

        // Test logger
        Logger::getInstance().log("Test message from main()");

    } catch (const std::exception& e) {
        std::cerr << "Exceptie: " << e.what() << '\n';
    }


task.action();
printRenameTaskInfo(task);
    std::cout << "\n=== TESTE ADMIN ===\n";
    test_admin_initializare();
    test_admin_acces_fisiere();

    std::cout<<"\n";
    test_creare_utilizator();
    test_logare_utilizator();
    test_modificare_parola();
    test_adaugare_task();
    test_finalizare_task();
    
    test_redenumire_task();
    test_stergere_task();
    test_creare_utilizator_nume_existenta();
    test_logare_utilizator_parola_gresita();
    test_modificare_parola_incorecta();
    test_stergere_utilizator_inexistent();
    test_adaugare_task_fara_autentificare();
    test_modificare_task_inexistent();
    test_stergere_task_inexistent();
    test_logare_fara_utilizator();
    test_stergere_utilizator();

    return 0;
}