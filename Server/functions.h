#ifndef FUNCTIONS_H
#define FUNCTIONS_H

#include <string>
#include <map>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>

// === RATE LIMITING ===
struct LoginAttempt {
    int failCount = 0;
    std::chrono::steady_clock::time_point lockedUntil;
    bool isLocked = false;
};

bool isLocked(const std::string& login, std::map<std::string, LoginAttempt>& attempts);

void recordFail(const std::string& login, std::map<std::string, LoginAttempt>& attempts,
    int maxFails, int lockDurationSec);

void resetFails(const std::string& login, std::map<std::string, LoginAttempt>& attempts);

// === —≈——»» ===
struct Session {
    std::string login;
    std::chrono::steady_clock::time_point createdAt;
    std::chrono::steady_clock::time_point expiresAt;
};

std::string generateSessionId();

std::string createSession(const std::string& login,
    std::map<std::string, Session>& sessions,
    int sessionDurationSec);

std::string validateSession(const std::string& sessionId,
    std::map<std::string, Session>& sessions);

// === œ¿–—»Õ√ JSON ===
std::string parseJSON(const std::string& json, const std::string& key);
std::string parseJSONNumber(const std::string& json, const std::string& key);

// === TIMESTAMP ===
bool isTimestampValid(const std::string& timestampStr, long long maxAgeMs);

#endif // FUNCTIONS_H