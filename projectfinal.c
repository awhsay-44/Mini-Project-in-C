#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define BLOCK_THRESHOLD 3  // Number of failed attempts before flagging brute-force
#define TIME_WINDOW 60      // Time window in seconds
#define LOG_FILE "logins.log"

// Structure to store login details
typedef struct {
    char username[50];
    char ipAddress[20];
    time_t timestamp;
    int success; // 1 for success, 0 for failure
} LoginAttempt;

// Function to get current timestamp as string
void getTimeStamp(char *buffer, size_t size) {
    time_t now = time(NULL);
    struct tm *localTime = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", localTime);
}

// Function to record a login attempt in the log file
void recordAttempt(const char *username, const char *ip, int success) {
    FILE *file = fopen(LOG_FILE, "a");
    if (!file) {
        printf("Error: Unable to open log file!\n");
        return;
    }

    char timestamp[20];
    getTimeStamp(timestamp, sizeof(timestamp));

    fprintf(file, "%s,%s,%s,%d\n", username, ip, timestamp, success);
    fclose(file);
}

// Function to analyze login attempts and detect brute-force attacks
void analyzeAttempts() {
    FILE *file = fopen(LOG_FILE, "r");
    if (!file) {
        printf("Error: No login data found.\n");
        return;
    }

    LoginAttempt attempts[100]; // Stores read attempts
    int attemptCount = 0;

    // Read the file line by line
    while (fscanf(file, "%49[^,],%19[^,],%19[^,],%d\n",
                  attempts[attemptCount].username,
                  attempts[attemptCount].ipAddress,
                  (char *)&attempts[attemptCount].timestamp,
                  &attempts[attemptCount].success) == 4) {

        // Convert timestamp string to time_t
        struct tm timeStruct = {0};
        strptime((char *)&attempts[attemptCount].timestamp, "%Y-%m-%d %H:%M:%S", &timeStruct);
        attempts[attemptCount].timestamp = mktime(&timeStruct);

        attemptCount++;
        if (attemptCount >= 100) break; // Avoid exceeding array size
    }
    fclose(file);

    // Detect brute-force attacks
    for (int i = 0; i < attemptCount; i++) {
        if (attempts[i].success == 0) {  // Check only failed attempts
            int failCount = 1;
            for (int j = i + 1; j < attemptCount; j++) {
                if (strcmp(attempts[i].ipAddress, attempts[j].ipAddress) == 0 &&
                    attempts[j].success == 0 &&
                    difftime(attempts[j].timestamp, attempts[i].timestamp) <= TIME_WINDOW) {
                    failCount++;
                }
            }
            if (failCount >= BLOCK_THRESHOLD) {
                printf("ALERT: Possible brute-force attack from IP %s (%d failed attempts)\n",
                       attempts[i].ipAddress, failCount);
            }
        }
    }
}

// Function to simulate login attempts
void simulateLogins() {
    recordAttempt("alice", "192.168.1.1", 0);  // Failed
    recordAttempt("bob", "192.168.1.2", 1);    // Success
    recordAttempt("alice", "192.168.1.1", 0);  // Failed
    recordAttempt("charlie", "192.168.1.3", 0); // Failed
    recordAttempt("alice", "192.168.1.1", 0);  // Failed (Brute-force detected)

    analyzeAttempts();
}

int main() {
    printf("Simulating login attempts...\n");
    simulateLogins();
    return 0;
}
