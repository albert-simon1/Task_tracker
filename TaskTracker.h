#ifndef TASKTRACKER_H
#define TASKTRACKER_H

#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <algorithm>
#include <memory>

class Logger {
private:
    Logger() {}
public:
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    static Logger& getInstance();
    void log(const std::string& message);
};

class SessionManager {
private:
    std::string currentUsername;
    bool loggedIn = false;
    SessionManager() {}
public:
    SessionManager(const SessionManager&) = delete;
    SessionManager& operator=(const SessionManager&) = delete;
    static SessionManager& getInstance();
    void login(const std::string& username);
    void logout();
    bool isLoggedIn() const;
    std::string getCurrentUser() const;
};

class registered_users;

class UserRegistry {
private:
    std::vector<registered_users> users;
    UserRegistry() {}
public:
    UserRegistry(const UserRegistry&) = delete;
    UserRegistry& operator=(const UserRegistry&) = delete;
    static UserRegistry& getInstance();
    void addUser(const registered_users& user);
    bool userExists(const std::string& username);
};

class registered_users {
protected:
    std::string username, password;
    bool log_in(const std::string& username, const std::string& password2) const;
private:
    bool already_used(const std::string& username, const std::string& password) const;
public:
    registered_users(const std::string& username, const std::string& password);
    virtual bool verify(const std::string& username, const std::string& password) const;
    std::string getUsername() const;
};

class New_User : public registered_users {
public:
    New_User(const std::string& user_name, const std::string& pass);
};

class User_Manager: public registered_users {
public:
    User_Manager(const std::string& user_name, const std::string& pass);
    bool verify(const std::string& username, const std::string& password) const override;
    virtual void execute() = 0;
};

class Delete_user: public User_Manager {
public:
    Delete_user(const std::string& username, const std::string& password);
    void execute() override;
};

class Change_username: public User_Manager {
    std::string new_username;
public:
    Change_username(const std::string& user_name, const std::string& pass, const std::string& new_user_name);
    void execute() override;
};

class Change_password: public User_Manager {
    std::string new_password;
public:
    Change_password(const std::string& username, const std::string& old_pass, const std::string& new_pass);
    void execute() override;
};

class CommandExecutor {
    User_Manager* action;
public:
    CommandExecutor(User_Manager* action);
    void run();
    ~CommandExecutor();
};

class Exceptions: public std::exception {
    std::string message;
public:
    Exceptions(const std::string& message);
    const char* what() const noexcept override;
};

class InvalidPassword: public Exceptions {
public:
    InvalidPassword(const std::string& password);
};

class UsernameNotFound: public Exceptions {
public:
    UsernameNotFound(const std::string& username);
};

class Username_Failed: public Exceptions {
public:
    Username_Failed(const std::string& username);
};

class Password_Failed: public Exceptions {
public:
    Password_Failed(const std::string& password);
};

class login_fail: public Exceptions {
public:
    login_fail(const std::string& username);
};

class FileError: public Exceptions {
public:
    FileError(const std::string& msg);
};

class invalidDate: public Exceptions {
public:
    invalidDate(const std::string& msg);
};

class User_files {
    static std::string cripted;
    friend class Admin;
    static std::string XORencrypt(const std::string& input, char key);
protected:
    std::string username;
private:
    std::string password;
    static int users_count;
    bool log_in(const std::string& username, const std::string& password2) const;
public:
    User_files(const std::string& username, const std::string& password);
    bool valid_login(const std::string& username, const std::string& password) const;
    static int User_count();
    User_files(const User_files& other);
    User_files& operator=(User_files other);
};

class Task_Manager: public User_files {
protected:
    std::string task_name;
public:
    Task_Manager(const std::string& username, const std::string& password, const std::string& task_name);
    virtual void action() = 0;
};

class Add_Task: public Task_Manager {
    std::string name, description;
    int day_due, month_due;
    int priority;
public:
    Add_Task(const std::string& name, const std::string& description, const int& day_due, 
             const int& month_due, const int& priority, const std::string& username, 
             const std::string& password);
    void action() override;
};

class CompletedTasks: public Task_Manager {
public:
    CompletedTasks(const std::string& username, const std::string& password, const std::string& task_name);
    void action() override;
};

class inProgressTasks: public Task_Manager {
public:
    inProgressTasks(const std::string& username, const std::string& password, const std::string& task_name);
    void action() override;
};

class EditTask: public Task_Manager {
public:
    EditTask(const std::string& username, const std::string& password, const std::string& task_name);
};

class DeleteTask: public EditTask {
public:
    DeleteTask(const std::string& username, const std::string& password, const std::string& task_name);
    void action() override;
};

template<typename T>
class RenameTask : public EditTask {
    T new_name;
    T task_name;
public:
    RenameTask(const std::string& username, const std::string& password, const T& old_name, const T& new_name);
    void action() override;
    T getNewName() const;
    template<typename U> friend void printRenameTaskInfo(const RenameTask<U>& task);
};

template<typename U>
void printRenameTaskInfo(const RenameTask<U>& task);

class Change_due_date: public EditTask {
    int new_due_day, new_due_month;
    int number_of_days_in_a_month(const int& new_due_month);
public:
    Change_due_date(const std::string& username, const std::string& password, 
                   const std::string& task_name, int new_due_day, int new_due_month);
    void action(const std::string& username, const std::string& task_name, int& new_due_day, int& new_due_month);
};

class Admin {
    static const char admin_key = 'l';
    static std::string admin_pwd;
    bool acces = false;
public:
    Admin(const std::string& pwd);
    static void initialize_password(const std::string& pwd);
};

class ActionHandler {
    Task_Manager* task;
public:
    ActionHandler(Task_Manager* task);
    void run();
    ~ActionHandler();
};

// Test functions
void test_admin_initializare();
void test_admin_acces_fisiere();
void test_creare_utilizator();
void test_logare_utilizator();
void test_modificare_parola();
void test_stergere_utilizator();
void test_adaugare_task();
void test_finalizare_task();
void test_redenumire_task();
void test_stergere_task();
void test_creare_utilizator_nume_existenta();
void test_logare_utilizator_parola_gresita();
void test_modificare_parola_incorecta();
void test_stergere_utilizator_inexistent();
void test_adaugare_task_fara_autentificare();
void test_modificare_task_inexistent();
void test_stergere_task_inexistent();
void test_logare_fara_utilizator();

#endif // TASKTRACKER_H