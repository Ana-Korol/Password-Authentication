#include "httplib.h"
#include "sqlite3.h"
#include "functions.h"
#include <iostream>
#include <string>
#include <clocale>
#include <sstream>
#include <vector>
#include <map>
#include <chrono>
#include <random>


// === ФУНКЦИЯ ДЛЯ ВЫПОЛНЕНИЯ SQL ЗАПРОСОВ ===
bool executeSQL(sqlite3* db, const std::string& sql) {
    char* errMsg = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "Ошибка SQL: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}



int main() {
    
    setlocale(LC_ALL, "Russian");

    std::cout << "========================================" << std::endl;
    std::cout << "Запуск сервера аутентификации..." << std::endl;
    std::cout << "Используется хеширование Argon2id" << std::endl;

    // === ПОДКЛЮЧЕНИЕ К БАЗЕ ДАННЫХ ===
    sqlite3* db;
    int rc = sqlite3_open("database.db", &db);

    if (rc != SQLITE_OK) {
        std::cerr << "Ошибка: Не удалось открыть базу данных: " << sqlite3_errmsg(db) << std::endl;
        return 1;
    }

    std::cout << "База данных подключена" << std::endl;

    // === СОЗДАНИЕ ТАБЛИЦЫ ПОЛЬЗОВАТЕЛЕЙ ===
    std::string createTableSQL =
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "login TEXT UNIQUE NOT NULL,"
        "hash TEXT NOT NULL,"
        "salt TEXT NOT NULL,"
        "created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
        ");";

    if (!executeSQL(db, createTableSQL)) {
        std::cerr << "Ошибка: Не удалось создать таблицу" << std::endl;
        sqlite3_close(db);
        return 1;
    }

    std::cout << "Таблица users готова" << std::endl;
    std::cout << "========================================" << std::endl;

    // === ХРАНИЛИЩЕ ПОПЫТОК ВХОДА ===
    // Структура: логин → { количество неудач, время разблокировки }
    std::map<std::string, LoginAttempt> loginAttempts;

    // Настройки rate limiting
    const int MAX_FAILS = 5;                    // максимум неудачных попыток
    const int LOCK_DURATION_SEC = 300;          // блокировка на 5 минут (300 секунд)

    // === RATE LIMIT ПО IP ===
    std::map<std::string, LoginAttempt> ipAttempts;
    const int MAX_IP_FAILS = 20;              // 20 неудач с одного IP
    const int IP_LOCK_DURATION_SEC = 300;     // блокировка на 5 минут

    // === ХРАНИЛИЩЕ СЕССИЙ ===
    std::map<std::string, Session> sessions;
    const int SESSION_DURATION_SEC = 1800;  // 30 минут

    httplib::Server svr;

    // === CORS ДЛЯ ВСЕХ ЗАПРОСОВ (включая 404) ===
    svr.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");

        // Если это preflight-запрос OPTIONS — сразу отвечаем 200 OK
        if (req.method == "OPTIONS") {
            res.status = 200;
            return httplib::Server::HandlerResponse::Handled;
        }

        return httplib::Server::HandlerResponse::Unhandled;
    });

    // === ОБРАБОТЧИК GET /salt ===
    // Возвращает соль пользователя или случайную соль,
    // если пользователь не найден (чтобы не раскрывать существование)
    svr.Get("/salt", [&db](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Content-Type", "text/plain; charset=utf-8");

        // Получаем логин из query-параметра
        std::string login;
        if (req.has_param("login")) {
            login = req.get_param_value("login");
        }

        if (login.empty()) {
            res.status = 400;
            res.set_content("ERROR: login required", "text/plain; charset=utf-8");
            return;
        }

        // === RATE LIMIT НА /salt ===
        // 10 запросов в минуту на логин
        static std::map<std::string, std::pair<int, std::chrono::steady_clock::time_point>> saltLimits;
        const int SALT_MAX_REQUESTS = 10;
        const int SALT_WINDOW_SEC = 60;

        auto now = std::chrono::steady_clock::now();
        auto& entry = saltLimits[login];

        if (std::chrono::duration_cast<std::chrono::seconds>(now - entry.second).count() >= SALT_WINDOW_SEC) {
            entry.first = 0;
            entry.second = now;
        }

        entry.first++;

        if (entry.first > SALT_MAX_REQUESTS) {
            res.status = 429;
            res.set_content("ERROR: too many requests", "text/plain; charset=utf-8");
            return;
        }

        // Ищем соль в БД
        std::string sql = "SELECT salt FROM users WHERE login = '" + login + "';";
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);

        if (rc == SQLITE_OK) {
            rc = sqlite3_step(stmt);
            if (rc == SQLITE_ROW) {
                // Пользователь найден — возвращаем его соль
                std::string salt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                res.set_content(salt, "text/plain; charset=utf-8");
                sqlite3_finalize(stmt);
                return;
            }
            sqlite3_finalize(stmt);
        }

        // Пользователь не найден — возвращаем детерминированную фиктивную соль
        // (чтобы злоумышленник не мог определить, существует ли пользователь,
        //  по формату соли — у нас всегда hex из 32 символов)
        std::string fakeSaltValue = fakeSalt(login);
        res.set_content(fakeSaltValue, "text/plain; charset=utf-8");
    });

    // === ОБРАБОТЧИК /register ===
    svr.Post("/register", [&db](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Content-Type", "text/plain; charset=utf-8");

        // Парсим JSON
        std::string login = parseJSON(req.body, "login");
        std::string hash = parseJSON(req.body, "hash");
        std::string salt = parseJSON(req.body, "salt");
        std::string timestamp = parseJSONNumber(req.body, "timestamp");

        // === ПРОВЕРКА TIMESTAMP ===
        if (!isTimestampValid(timestamp, 3000)) {
            res.set_content("OK: \xd0\x97\xd0\xb0\xd0\xbf\xd1\x80\xd0\xbe\xd1\x81 \xd1\x83\xd1\x81\xd1\x82\xd0\xb0\xd1\x80\xd0\xb5\xd0\xbb. \xd0\x9e\xd0\xb1\xd0\xbd\xd0\xbe\xd0\xb2\xd0\xb8\xd1\x82\xd0\xb5 \xd1\x81\xd1\x82\xd1\x80\xd0\xb0\xd0\xbd\xd0\xb8\xd1\x86\xd1\x83", "text/plain; charset=utf-8");
            return;
        }

        // Проверка на пустые поля
        if (login.empty() || hash.empty() || salt.empty()) {
            res.set_content("OK: \xd0\x9d\xd0\xb5\xd0\xb2\xd0\xb5\xd1\x80\xd0\xbd\xd1\x8b\xd0\xb5 \xd0\xb4\xd0\xb0\xd0\xbd\xd0\xbd\xd1\x8b\xd0\xb5", "text/plain; charset=utf-8");
            return;
        }

        // === RATE LIMIT НА /register ===
        // 5 запросов в минуту на логин
        static std::map<std::string, std::pair<int, std::chrono::steady_clock::time_point>> registerLimits;
        const int REG_MAX_REQUESTS = 5;
        const int REG_WINDOW_SEC = 60;

        auto now = std::chrono::steady_clock::now();
        auto& entry = registerLimits[login];

        if (std::chrono::duration_cast<std::chrono::seconds>(now - entry.second).count() >= REG_WINDOW_SEC) {
            entry.first = 0;
            entry.second = now;
        }

        entry.first++;

        if (entry.first > REG_MAX_REQUESTS) {
            res.status = 429;
            res.set_content("ERROR: too many requests", "text/plain; charset=utf-8");
            return;
        }

        // Проверяем, существует ли пользователь
        std::string checkSQL = "SELECT id FROM users WHERE login = '" + login + "';";
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, checkSQL.c_str(), -1, &stmt, nullptr);

        if (rc != SQLITE_OK) {
            res.set_content("OK: \xd0\x9e\xd1\x88\xd0\xb8\xd0\xb1\xd0\xba\xd0\xb0 \xd0\xb1\xd0\xb0\xd0\xb7\xd1\x8b \xd0\xb4\xd0\xb0\xd0\xbd\xd0\xbd\xd1\x8b\xd1\x85", "text/plain; charset=utf-8");
            return;
        }

        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) {
            sqlite3_finalize(stmt);
            res.set_content("OK: \xd0\x9f\xd0\xbe\xd0\xbb\xd1\x8c\xd0\xb7\xd0\xbe\xd0\xb2\xd0\xb0\xd1\x82\xd0\xb5\xd0\xbb\xd1\x8c \xd1\x83\xd0\xb6\xd0\xb5 \xd1\x81\xd1\x83\xd1\x89\xd0\xb5\xd1\x81\xd1\x82\xd0\xb2\xd1\x83\xd0\xb5\xd1\x82", "text/plain; charset=utf-8");
            return;
        }
        sqlite3_finalize(stmt);

        // Сохраняем hash и salt
        std::string insertSQL =
            "INSERT INTO users (login, hash, salt) VALUES ('" + login + "', '" + hash + "', '" + salt + "');";

        if (executeSQL(db, insertSQL)) {
            res.set_content("OK: \xd0\xa0\xd0\xb5\xd0\xb3\xd0\xb8\xd1\x81\xd1\x82\xd1\x80\xd0\xb0\xd1\x86\xd0\xb8\xd1\x8f \xd1\x83\xd1\x81\xd0\xbf\xd0\xb5\xd1\x88\xd0\xbd\xd0\xb0", "text/plain; charset=utf-8");
            
        }
        else {
            res.set_content("OK: \xd0\x9e\xd1\x88\xd0\xb8\xd0\xb1\xd0\xba\xd0\xb0 \xd1\x80\xd0\xb5\xd0\xb3\xd0\xb8\xd1\x81\xd1\x82\xd1\x80\xd0\xb0\xd1\x86\xd0\xb8\xd0\xb8", "text/plain; charset=utf-8");
            
        }
    });

    // === ОБРАБОТЧИК /login ===
    svr.Post("/login", [&db, &loginAttempts, &ipAttempts, &sessions, MAX_FAILS, LOCK_DURATION_SEC, MAX_IP_FAILS, IP_LOCK_DURATION_SEC, SESSION_DURATION_SEC](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Content-Type", "text/plain; charset=utf-8");

        // Парсим JSON
        std::string login = parseJSON(req.body, "login");
        std::string hash = parseJSON(req.body, "hash");
        std::string timestamp = parseJSONNumber(req.body, "timestamp");

        // === ПРОВЕРКА БЛОКИРОВКИ ПО IP ===
        std::string clientIp = req.remote_addr;
        if (isLocked(clientIp, ipAttempts)) {
            res.status = 429;
            res.set_content("OK: \xd0\xa1\xd0\xbb\xd0\xb8\xd1\x88\xd0\xba\xd0\xbe\xd0\xbc \xd0\xbc\xd0\xbd\xd0\xbe\xd0\xb3\xd0\xbe \xd0\xbf\xd0\xbe\xd0\xbf\xd1\x8b\xd1\x82\xd0\xbe\xd0\xba \xd1\x81 \xd0\xb2\xd0\xb0\xd1\x88\xd0\xb5\xd0\xb3\xd0\xbe IP", "text/plain; charset=utf-8");
            return;
        }

        // === ПРОВЕРКА TIMESTAMP ===
        if (!isTimestampValid(timestamp, 3000)) {
            res.set_content("OK: \xd0\x97\xd0\xb0\xd0\xbf\xd1\x80\xd0\xbe\xd1\x81 \xd1\x83\xd1\x81\xd1\x82\xd0\xb0\xd1\x80\xd0\xb5\xd0\xbb. \xd0\x9e\xd0\xb1\xd0\xbd\xd0\xbe\xd0\xb2\xd0\xb8\xd1\x82\xd0\xb5 \xd1\x81\xd1\x82\xd1\x80\xd0\xb0\xd0\xbd\xd0\xb8\xd1\x86\xd1\x83", "text/plain; charset=utf-8");
            return;
        }

        if (login.empty() || hash.empty()) {
            res.set_content("OK: \xd0\x9d\xd0\xb5\xd0\xb2\xd0\xb5\xd1\x80\xd0\xbd\xd1\x8b\xd0\xb9 \xd0\xbb\xd0\xbe\xd0\xb3\xd0\xb8\xd0\xbd \xd0\xb8\xd0\xbb\xd0\xb8 \xd0\xbf\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c", "text/plain; charset=utf-8");
            return;
        }

        // === ПРОВЕРКА БЛОКИРОВКИ ===
        if (isLocked(login, loginAttempts)) {
            
            res.set_content("OK: \xd0\xa1\xd0\xbb\xd0\xb8\xd1\x88\xd0\xba\xd0\xbe\xd0\xbc \xd0\xbc\xd0\xbd\xd0\xbe\xd0\xb3\xd0\xbe \xd0\xbf\xd0\xbe\xd0\xbf\xd1\x8b\xd1\x82\xd0\xbe\xd0\xba. \xd0\x9f\xd0\xbe\xd0\xbf\xd1\x80\xd0\xbe\xd0\xb1\xd1\x83\xd0\xb9\xd1\x82\xd0\xb5 \xd0\xbf\xd0\xbe\xd0\xb7\xd0\xb6\xd0\xb5", "text/plain; charset=utf-8");
            return;
        }

        // Ищем пользователя в БД
        std::string sql = "SELECT hash FROM users WHERE login = '" + login + "';";
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);

        bool authSuccess = false;

        if (rc == SQLITE_OK) {
            rc = sqlite3_step(stmt);
            if (rc == SQLITE_ROW) {
                std::string dbHash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                if (dbHash == hash) {
                    authSuccess = true;
                }
            }
            sqlite3_finalize(stmt);
        }

        // Единый ответ для всех ошибок + rate limiting
        if (authSuccess) {
            resetFails(login, loginAttempts);
            resetFails(clientIp, ipAttempts);  // ← сбрасываем и IP-счётчик

            // === СОЗДАЁМ СЕССИЮ ===
            std::string sessionId = createSession(login, sessions, SESSION_DURATION_SEC);
            res.set_content("OK: \xd0\x92\xd1\x85\xd0\xbe\xd0\xb4 \xd1\x83\xd1\x81\xd0\xbf\xd0\xb5\xd1\x88\xd0\xbd\xd1\x8b\xd0\xb9|" + sessionId, "text/plain; charset=utf-8");
        }
        else {
            recordFail(login, loginAttempts, MAX_FAILS, LOCK_DURATION_SEC);
            recordFail(clientIp, ipAttempts, MAX_IP_FAILS, IP_LOCK_DURATION_SEC);  // ← пишем и IP
            res.set_content("OK: \xd0\x9d\xd0\xb5\xd0\xb2\xd0\xb5\xd1\x80\xd0\xbd\xd1\x8b\xd0\xb9 \xd0\xbb\xd0\xbe\xd0\xb3\xd0\xb8\xd0\xbd \xd0\xb8\u043b\u0438 \xd0\xbf\xd0\xb0\xd1\x80\u043e\u043b\u044c", "text/plain; charset=utf-8");
        }
    });

    // === ЗАЩИЩЁННЫЙ ЭНДПОИНТ /profile ===
    // Требует заголовок Authorization: Bearer <session_id>
    svr.Get("/profile", [&sessions](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Content-Type", "text/plain; charset=utf-8");

        // Проверяем наличие заголовка Authorization
        if (!req.has_header("Authorization")) {
            res.status = 401;
            res.set_content("OK: \xd0\xa2\xd1\x80\xd0\xb5\xd0\xb1\xd1\x83\xd0\xb5\xd1\x82\xd1\x81\xd1\x8f \xd0\xb0\xd0\xb2\xd1\x82\xd0\xbe\xd1\x80\xd0\xb8\xd0\xb7\xd0\xb0\xd1\x86\xd0\xb8\xd1\x8f", "text/plain; charset=utf-8");
            return;
        }

        std::string authHeader = req.get_header_value("Authorization");

        // Ожидаем формат: "Bearer <session_id>"
        if (authHeader.substr(0, 7) != "Bearer ") {
            res.status = 401;
            res.set_content("OK: \xd0\x9d\xd0\xb5\xd0\xb2\xd0\xb5\xd1\x80\xd0\xbd\xd1\x8b\xd0\xb9 \xd1\x84\xd0\xbe\xd1\x80\xd0\xbc\xd0\xb0\xd1\x82 \xd1\x82\xd0\xbe\xd0\xba\xd0\xb5\xd0\xbd\xd0\xb0", "text/plain; charset=utf-8");
            return;
        }

        std::string sessionId = authHeader.substr(7);
        std::string login = validateSession(sessionId, sessions);

        if (login.empty()) {
            res.status = 401;
            res.set_content("OK: \xd0\xa1\xd0\xb5\xd1\x81\xd1\x81\xd0\xb8\xd1\x8f \xd0\xbd\xd0\xb5\xd0\xb2\xd0\xb0\xd0\xbb\xd0\xb8\xd0\xb4\xd0\xbd\xd0\xb0", "text/plain; charset=utf-8");
            return;
        }

        res.set_content("OK: \xd0\x92\xd1\x8b \xd0\xb2\xd0\xbe\xd1\x88\xd0\xbb\xd0\xb8 \xd0\xba\xd0\xb0\xd0\xba " + login, "text/plain; charset=utf-8");
        });

    std::cout << "Сервер запущен на http://localhost:8080" << std::endl;
    std::cout << "Для регистрации: POST /register" << std::endl;
    std::cout << "Для входа: POST /login" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Нажмите Ctrl+C для остановки" << std::endl;

    if (!svr.listen("localhost", 8080)) {
        std::cerr << "Ошибка: не удалось запустить сервер на порту 8080" << std::endl;
        std::cin.get();
        sqlite3_close(db);
        return 1;
    }

    // Закрываем соединение с БД при завершении
    sqlite3_close(db);
    return 0;
}
