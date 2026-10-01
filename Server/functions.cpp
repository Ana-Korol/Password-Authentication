#include "functions.h"
#include <iostream>

// === RATE LIMITING ===

bool isLocked(const std::string& login, std::map<std::string, LoginAttempt>& attempts) {
    auto it = attempts.find(login);
    if (it == attempts.end()) return false;
    if (!it->second.isLocked) return false;

    auto now = std::chrono::steady_clock::now();

    if (now < it->second.lockedUntil) {
        return true;
    }

    // Блокировка истекла
    attempts.erase(it);
    return false;
}

void recordFail(const std::string& login, std::map<std::string, LoginAttempt>& attempts,
    int maxFails, int lockDurationSec) {
    auto& attempt = attempts[login];
    attempt.failCount++;

    if (attempt.failCount >= maxFails) {
        attempt.lockedUntil = std::chrono::steady_clock::now() +
            std::chrono::seconds(lockDurationSec);
        attempt.isLocked = true;
    }
}

void resetFails(const std::string& login, std::map<std::string, LoginAttempt>& attempts) {
    attempts.erase(login);
}

// === СЕССИИ ===

std::string generateSessionId() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 4; i++) {
        ss << std::setw(16) << dis(gen);
    }
    return ss.str();
}

std::string createSession(const std::string& login,
    std::map<std::string, Session>& sessions,
    int sessionDurationSec) {
    std::string sessionId = generateSessionId();
    Session session;
    session.login = login;
    session.createdAt = std::chrono::steady_clock::now();
    session.expiresAt = session.createdAt + std::chrono::seconds(sessionDurationSec);
    sessions[sessionId] = session;
    return sessionId;
}

std::string validateSession(const std::string& sessionId,
    std::map<std::string, Session>& sessions) {
    auto it = sessions.find(sessionId);
    if (it == sessions.end()) return "";

    auto now = std::chrono::steady_clock::now();
    if (now >= it->second.expiresAt) {
        sessions.erase(it);
        return "";
    }
    return it->second.login;
}

// === ПАРСИНГ JSON ===

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

std::string parseJSONNumber(const std::string& json, const std::string& key) {
    std::string searchKey = "\"" + key + "\"";
    size_t keyPos = json.find(searchKey);
    if (keyPos == std::string::npos) return "";

    size_t start = json.find(":", keyPos);
    if (start == std::string::npos) return "";
    start++;

    while (start < json.size() && (json[start] == ' ' || json[start] == '\t')) {
        start++;
    }

    size_t end = start;
    while (end < json.size() && json[end] != ',' && json[end] != '}') {
        end++;
    }

    return json.substr(start, end - start);
}

// === TIMESTAMP ===

bool isTimestampValid(const std::string& timestampStr, long long maxAgeMs) {
    if (timestampStr.empty()) {
        return false;
    }

    long long timestamp;
    try {
        timestamp = std::stoll(timestampStr);
    }
    catch (...) {
        return false;
    }

    long long now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    long long age = now - timestamp;

    if (age < 0) return false;
    if (age > maxAgeMs) return false;

    return true;
}

// === ФИКТИВНАЯ СОЛЬ ===
std::string fakeSalt(const std::string& login) {
    // Детерминированный хеш от логина + секрет.
    // Результат — 32 hex-символа (как настоящая соль).
    const std::string SECRET = "server_secret_pepper_2026_password_auth";

    // Простой хеш на основе std::hash
    std::hash<std::string> hasher;
    std::string data = login + SECRET;

    // Собираем 32 hex-символа из нескольких прогонов
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    // Первые 16 символов
    size_t h1 = hasher(data);
    ss << std::setw(16) << h1;

    // Ещё 16 символов (хеш от хеша)
    size_t h2 = hasher(std::to_string(h1) + SECRET);
    ss << std::setw(16) << h2;

    std::string result = ss.str();

    // На всякий случай — обрезаем/дополняем до 32
    if (result.length() > 32) result = result.substr(0, 32);
    while (result.length() < 32) result += "0";

    return result;
}