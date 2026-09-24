#include <gtest/gtest.h>
#include <thread>
#include "functions.h"

// ============================================================
// ТЕСТЫ ДЛЯ parseJSON
// ============================================================

TEST(ParseJSON, ExtractsStringValue) {
    std::string json = R"({"login":"testuser","hash":"abc123"})";
    EXPECT_EQ(parseJSON(json, "login"), "testuser");
    EXPECT_EQ(parseJSON(json, "hash"), "abc123");
}

TEST(ParseJSON, ReturnsEmptyForMissingKey) {
    std::string json = R"({"login":"testuser"})";
    EXPECT_EQ(parseJSON(json, "nonexistent"), "");
}

TEST(ParseJSON, ReturnsEmptyForEmptyString) {
    EXPECT_EQ(parseJSON("", "login"), "");
}

// ============================================================
// ТЕСТЫ ДЛЯ parseJSONNumber
// ============================================================

TEST(ParseJSONNumber, ExtractsNumber) {
    std::string json = R"({"timestamp":1727176000000})";
    EXPECT_EQ(parseJSONNumber(json, "timestamp"), "1727176000000");
}

TEST(ParseJSONNumber, ReturnsEmptyForMissingKey) {
    std::string json = R"({"login":"test"})";
    EXPECT_EQ(parseJSONNumber(json, "timestamp"), "");
}

// ============================================================
// ТЕСТЫ ДЛЯ isTimestampValid
// ============================================================

TEST(Timestamp, FreshIsValid) {
    long long now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    EXPECT_TRUE(isTimestampValid(std::to_string(now), 3000));
}

TEST(Timestamp, OldIsInvalid) {
    long long now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    // 10 секунд назад — точно старше 3 секунд
    EXPECT_FALSE(isTimestampValid(std::to_string(now - 10000), 3000));
}

TEST(Timestamp, FutureIsInvalid) {
    long long now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    // 60 секунд в будущем
    EXPECT_FALSE(isTimestampValid(std::to_string(now + 60000), 3000));
}

TEST(Timestamp, EmptyIsInvalid) {
    EXPECT_FALSE(isTimestampValid("", 3000));
}

TEST(Timestamp, NonNumericIsInvalid) {
    EXPECT_FALSE(isTimestampValid("abc", 3000));
}

// ============================================================
// ТЕСТЫ ДЛЯ RATE LIMITING
// ============================================================

TEST(RateLimit, InitiallyNotLocked) {
    std::map<std::string, LoginAttempt> attempts;
    EXPECT_FALSE(isLocked("user1", attempts));
}

TEST(RateLimit, NotLockedAfter4Fails) {
    std::map<std::string, LoginAttempt> attempts;
    for (int i = 0; i < 4; i++) {
        recordFail("user1", attempts, 5, 300);
    }
    EXPECT_FALSE(isLocked("user1", attempts));
}

TEST(RateLimit, LockedAfter5Fails) {
    std::map<std::string, LoginAttempt> attempts;
    for (int i = 0; i < 5; i++) {
        recordFail("user1", attempts, 5, 300);
    }
    EXPECT_TRUE(isLocked("user1", attempts));
}

TEST(RateLimit, ResetUnlocksUser) {
    std::map<std::string, LoginAttempt> attempts;
    for (int i = 0; i < 5; i++) {
        recordFail("user1", attempts, 5, 300);
    }
    EXPECT_TRUE(isLocked("user1", attempts));

    resetFails("user1", attempts);
    EXPECT_FALSE(isLocked("user1", attempts));
}

TEST(RateLimit, DifferentUsersIndependent) {
    std::map<std::string, LoginAttempt> attempts;
    for (int i = 0; i < 5; i++) {
        recordFail("user1", attempts, 5, 300);
    }
    EXPECT_TRUE(isLocked("user1", attempts));
    EXPECT_FALSE(isLocked("user2", attempts));  // Другой юзер не заблокирован
}

// ============================================================
// ТЕСТЫ ДЛЯ СЕССИЙ
// ============================================================

TEST(Session, GenerateIdLength64) {
    std::string id = generateSessionId();
    EXPECT_EQ(id.length(), 64);
}

TEST(Session, GenerateIdIsHex) {
    std::string id = generateSessionId();
    for (char c : id) {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
}

TEST(Session, GenerateIdUnique) {
    std::string id1 = generateSessionId();
    std::string id2 = generateSessionId();
    EXPECT_NE(id1, id2);
}

TEST(Session, CreateAndValidate) {
    std::map<std::string, Session> sessions;
    std::string id = createSession("user1", sessions, 1800);
    EXPECT_EQ(validateSession(id, sessions), "user1");
}

TEST(Session, InvalidIdReturnsEmpty) {
    std::map<std::string, Session> sessions;
    EXPECT_EQ(validateSession("invalid_id", sessions), "");
}

TEST(Session, ExpiredSessionReturnsEmpty) {
    std::map<std::string, Session> sessions;
    std::string id = createSession("user1", sessions, 1);  // 1 секунда
    std::this_thread::sleep_for(std::chrono::seconds(2));
    EXPECT_EQ(validateSession(id, sessions), "");
}