#include "httplib.h"
#include "sqlite3.h"
#include "Stribog.h"
#include <iostream>
#include <string>
#include <clocale>
#include <sstream>
#include <vector>

// === ФУНКЦИЯ ХЕШИРОВАНИЯ ЧЕРЕЗ СТРИБОГ ===
std::string hashPassword(const std::string& password) {
    std::vector<uint8_t> message(password.begin(), password.end());
    std::vector<uint8_t> hash = Stribog::GetHash256(message);
    return Stribog::ToHexString(hash);
}

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

// === ФУНКЦИЯ ДЛЯ ПАРСИНГА JSON ===
std::string parseJSON(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\"";
    size_t keyPos = json.find(searchKey);
    if (keyPos == std::string::npos) return "";

    size_t start = json.find(":", keyPos);
    if (start == std::string::npos) return "";
    start = json.find("\"", start);
    if (start == std::string::npos) return "";
    start++;

    size_t end = json.find("\"", start);
    if (end == std::string::npos) return "";

    return json.substr(start, end - start);
}

int main() {
    // Настройка консоли для русского языка
    setlocale(LC_ALL, "Russian");

    std::cout << "========================================" << std::endl;
    std::cout << "Запуск сервера аутентификации..." << std::endl;
    std::cout << "Используется хеширование Стрибог" << std::endl;

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
        "password TEXT NOT NULL,"
        "created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
        ");";

    if (!executeSQL(db, createTableSQL)) {
        std::cerr << "Ошибка: Не удалось создать таблицу" << std::endl;
        sqlite3_close(db);
        return 1;
    }

    std::cout << "Таблица users готова" << std::endl;
    std::cout << "========================================" << std::endl;

    httplib::Server svr;

    // === ОБРАБОТЧИК /register ===
    svr.Post("/register", [&db](const httplib::Request& req, httplib::Response& res) {
        // Настройка CORS
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
        res.set_header("Content-Type", "text/plain; charset=utf-8");

        // Парсим JSON
        std::string login = parseJSON(req.body, "login");
        std::string password = parseJSON(req.body, "password");

        std::cout << "[LOG] Попытка регистрации: " << login << std::endl;

        // Хешируем пароль через Стрибог
        std::string hashedPassword = hashPassword(password);
        std::cout << "[LOG] Хеш пароля (Стрибог): " << hashedPassword << std::endl;

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
            // Пользователь уже существует
            sqlite3_finalize(stmt);
            res.set_content("OK: \xd0\x9f\xd0\xbe\xd0\xbb\xd1\x8c\xd0\xb7\xd0\xbe\xd0\xb2\xd0\xb0\xd1\x82\xd0\xb5\xd0\xbb\xd1\x8c \xd1\x83\xd0\xb6\xd0\xb5 \xd1\x81\xd1\x83\xd1\x89\xd0\xb5\xd1\x81\xd1\x82\xd0\xb2\xd1\x83\xd0\xb5\xd1\x82", "text/plain; charset=utf-8");
            std::cout << "[LOG] Регистрация отклонена: пользователь уже существует" << std::endl;
            return;
        }
        sqlite3_finalize(stmt);

        // Добавляем нового пользователя (сохраняем ХЕШ)
        std::string insertSQL =
            "INSERT INTO users (login, password) VALUES ('" + login + "', '" + hashedPassword + "');";

        if (executeSQL(db, insertSQL)) {
            res.set_content("OK: \xd0\xa0\xd0\xb5\xd0\xb3\xd0\xb8\xd1\x81\xd1\x82\xd1\x80\xd0\xb0\xd1\x86\xd0\xb8\xd1\x8f \xd1\x83\xd1\x81\xd0\xbf\xd0\xb5\xd1\x88\xd0\xbd\xd0\xb0", "text/plain; charset=utf-8");
            std::cout << "[LOG] Регистрация успешна: " << login << std::endl;
        }
        else {
            res.set_content("OK: \xd0\x9e\xd1\x88\xd0\xb8\xd0\xb1\xd0\xba\xd0\xb0 \xd1\x80\xd0\xb5\xd0\xb3\xd0\xb8\xd1\x81\xd1\x82\xd1\x80\xd0\xb0\xd1\x86\xd0\xb8\xd0\xb8", "text/plain; charset=utf-8");
            std::cout << "[LOG] Ошибка регистрации: " << login << std::endl;
        }
        });

    // === ОБРАБОТЧИК /login ===
    svr.Post("/login", [&db](const httplib::Request& req, httplib::Response& res) {
        // Настройка CORS
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
        res.set_header("Content-Type", "text/plain; charset=utf-8");

        // Парсим JSON
        std::string login = parseJSON(req.body, "login");
        std::string password = parseJSON(req.body, "password");

        std::cout << "[LOG] Попытка входа: " << login << std::endl;

        // Хешируем введенный пароль через Стрибог
        std::string hashedPassword = hashPassword(password);
        std::cout << "[LOG] Хеш введенного пароля (Стрибог): " << hashedPassword << std::endl;

        // Ищем пользователя в БД
        std::string sql = "SELECT password FROM users WHERE login = '" + login + "';";
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);

        bool authSuccess = false;

        if (rc == SQLITE_OK) {
            rc = sqlite3_step(stmt);
            if (rc == SQLITE_ROW) {
                // Пользователь найден - получаем сохраненный хеш
                std::string dbHash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));

                // Сравниваем ХЕШИ (а не пароли!)
                if (dbHash == hashedPassword) {
                    authSuccess = true;
                    std::cout << "[LOG] Успешный вход: " << login << std::endl;
                }
                else {
                    std::cout << "[LOG] Неверный пароль для: " << login << std::endl;
                }
            }
            else {
                // Пользователь не найден
                std::cout << "[LOG] Пользователь не найден: " << login << std::endl;
            }
            sqlite3_finalize(stmt);
        }
        else {
            std::cout << "[LOG] Ошибка БД при входе: " << login << std::endl;
        }

        // === ЕДИНЫЙ ОТВЕТ ДЛЯ ВСЕХ ОШИБОК ===
        if (authSuccess) {
            res.set_content("OK: \xd0\x92\xd1\x85\xd0\xbe\xd0\xb4 \xd1\x83\xd1\x81\xd0\xbf\xd0\xb5\xd1\x88\xd0\xbd\xd1\x8b\xd0\xb9", "text/plain; charset=utf-8");
        }
        else {
            // Одинаковый ответ для любых ошибок авторизации
            res.set_content("OK: \xd0\x9d\xd0\xb5\xd0\xb2\xd0\xb5\xd1\x80\xd0\xbd\xd1\x8b\xd0\xb9 \xd0\xbb\xd0\xbe\xd0\xb3\xd0\xb8\xd0\xbd \xd0\xb8\xd0\xbb\xd0\xb8 \xd0\xbf\xd0\xb0\xd1\x80\xd0\xbe\xd0\xbb\xd1\x8c", "text/plain; charset=utf-8");
        }
        });

    // === ОБРАБОТЧИК ДЛЯ CORS (OPTIONS) ===
    svr.Options("/(.*)", [](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
        res.status = 200;
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