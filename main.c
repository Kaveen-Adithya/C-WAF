#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <regex.h>
#include <time.h>

#define MAX_RULES 1000
#define MAX_BLOCKED_IPS 10000
#define MAX_CONNECTIONS 100
#define BUFFER_SIZE 8192
#define CONFIG_FILE "config-rule.conf"
#define BLOCKED_IPS_FILE "blocked_ips.txt"
#define WEB_UI_PORT 8080
#define WAF_LOG_FILE "waf.log"

// Configuration structure
typedef struct {
    char listen_address[16];
    int listen_port;
    char backend_address[16];
    int backend_port;
    int max_connections;
    int timeout;
    int enable_logging;
    char log_file[256];
} WafConfig;

// Rule structure
typedef struct {
    int id;
    char name[256];
    char pattern[1024];
    regex_t regex;
    char action[64]; // "block", "log", "allow"
    int enabled;
} Rule;

// Blocked IP structure
typedef struct {
    char ip[16];
    time_t block_time;
    int block_duration; // in seconds
    char reason[256];
} BlockedIP;

// Global variables
WafConfig config;
Rule rules[MAX_RULES];
BlockedIP blocked_ips[MAX_BLOCKED_IPS];
int rule_count = 0;
int blocked_ip_count = 0;
pthread_mutex_t rules_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t blocked_ips_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
int running = 1;

// Function declarations
void load_configuration();
void load_rules();
void load_blocked_ips();
void save_blocked_ips();
int is_ip_blocked(const char *ip);
void add_blocked_ip(const char *ip, const char *reason, int duration);
void remove_blocked_ip(const char *ip);
void *reverse_proxy_thread(void *arg);
void *web_ui_thread(void *arg);
void handle_web_ui_request(int client_socket);
void log_message(const char *format, ...);
int check_request(const char *request, const char *client_ip);
void cleanup_expired_blocked_ips();
void handle_signals(int sig);

// Signal handler
void handle_signals(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        log_message("Shutting down WAF...");
        running = 0;
        save_blocked_ips();
        exit(0);
    }
}

// Main function
int main(int argc, char *argv[]) {
    // Set up signal handlers
    signal(SIGINT, handle_signals);
    signal(SIGTERM, handle_signals);
    
    // Load configuration and rules
    load_configuration();
    load_rules();
    load_blocked_ips();
    
    // Start threads
    pthread_t proxy_thread, ui_thread, cleanup_thread;
    pthread_create(&proxy_thread, NULL, reverse_proxy_thread, NULL);
    pthread_create(&ui_thread, NULL, web_ui_thread, NULL);
    
    log_message("WAF started. Listening on %s:%d, forwarding to %s:%d", 
                config.listen_address, config.listen_port,
                config.backend_address, config.backend_port);
    
    // Periodically clean up expired blocked IPs
    while (running) {
        cleanup_expired_blocked_ips();
        sleep(60); // Check every minute
    }
    
    // Wait for threads to finish (this should not be reached due to signal handlers)
    pthread_join(proxy_thread, NULL);
    pthread_join(ui_thread, NULL);
    
    return 0;
}

// Load WAF configuration
void load_configuration() {
    FILE *file = fopen(CONFIG_FILE, "r");
    if (!file) {
        fprintf(stderr, "Error opening config file %s. Using default settings.\n", CONFIG_FILE);
        // Default settings
        strcpy(config.listen_address, "0.0.0.0");
        config.listen_port = 80;
        strcpy(config.backend_address, "127.0.0.1");
        config.backend_port = 8000;
        config.max_connections = MAX_CONNECTIONS;
        config.timeout = 30;
        config.enable_logging = 1;
        strcpy(config.log_file, WAF_LOG_FILE);
        return;
    }
    
    char line[1024];
    char key[256], value[256];
    
    // Set defaults
    strcpy(config.listen_address, "0.0.0.0");
    config.listen_port = 80;
    strcpy(config.backend_address, "127.0.0.1");
    config.backend_port = 8000;
    config.max_connections = MAX_CONNECTIONS;
    config.timeout = 30;
    config.enable_logging = 1;
    strcpy(config.log_file, WAF_LOG_FILE);
    
    while (fgets(line, sizeof(line), file)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;
        
        // Remove newline
        line[strcspn(line, "\r\n")] = 0;
        
        if (sscanf(line, "%255[^=]=%255s", key, value) == 2) {
            // Trim whitespace
            char *k = key;
            while (*k && (*k == ' ' || *k == '\t')) k++;
            char *end = k + strlen(k) - 1;
            while (end > k && (*end == ' ' || *end == '\t')) *end-- = '\0';
            
            if (strcmp(k, "listen_address") == 0)
                strncpy(config.listen_address, value, sizeof(config.listen_address) - 1);
            else if (strcmp(k, "listen_port") == 0)
                config.listen_port = atoi(value);
            else if (strcmp(k, "backend_address") == 0)
                strncpy(config.backend_address, value, sizeof(config.backend_address) - 1);
            else if (strcmp(k, "backend_port") == 0)
                config.backend_port = atoi(value);
            else if (strcmp(k, "max_connections") == 0)
                config.max_connections = atoi(value);
            else if (strcmp(k, "timeout") == 0)
                config.timeout = atoi(value);
            else if (strcmp(k, "enable_logging") == 0)
                config.enable_logging = atoi(value);
            else if (strcmp(k, "log_file") == 0)
                strncpy(config.log_file, value, sizeof(config.log_file) - 1);
        }
    }
    
    fclose(file);
    log_message("Configuration loaded successfully");
}

// Load WAF rules
void load_rules() {
    FILE *file = fopen(CONFIG_FILE, "r");
    if (!file) {
        fprintf(stderr, "Error opening rules file %s\n", CONFIG_FILE);
        return;
    }
    
    char line[1024];
    int section = 0; // 0 = config, 1 = rules
    
    rule_count = 0;
    while (fgets(line, sizeof(line), file) && rule_count < MAX_RULES) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;
        
        // Remove newline
        line[strcspn(line, "\r\n")] = 0;
        
        // Check for section markers
        if (strcmp(line, "[rules]") == 0) {
            section = 1;
            continue;
        } else if (line[0] == '[') {
            section = 0;
            continue;
        }
        
        if (section == 1) {
            // Parse rule line: id|name|pattern|action|enabled
            char *token = strtok(line, "|");
            if (!token) continue;
            
            rules[rule_count].id = atoi(token);
            
            token = strtok(NULL, "|");
            if (!token) continue;
            strncpy(rules[rule_count].name, token, sizeof(rules[rule_count].name) - 1);
            
            token = strtok(NULL, "|");
            if (!token) continue;
            strncpy(rules[rule_count].pattern, token, sizeof(rules[rule_count].pattern) - 1);
            
            token = strtok(NULL, "|");
            if (!token) continue;
            strncpy(rules[rule_count].action, token, sizeof(rules[rule_count].action) - 1);
            
            token = strtok(NULL, "|");
            if (!token) continue;
            rules[rule_count].enabled = atoi(token);
            
            // Compile regex pattern
            if (rules[rule_count].enabled) {
                int result = regcomp(&rules[rule_count].regex, rules[rule_count].pattern, REG_EXTENDED);
                if (result != 0) {
                    char error_buffer[100];
                    regerror(result, &rules[rule_count].regex, error_buffer, sizeof(error_buffer));
                    log_message("Error compiling regex pattern for rule %d: %s", rules[rule_count].id, error_buffer);
                    continue;
                }
            }
            
            rule_count++;
        }
    }
    
    fclose(file);
    log_message("Loaded %d rules successfully", rule_count);
}

// Load blocked IPs from file
void load_blocked_ips() {
    FILE *file = fopen(BLOCKED_IPS_FILE, "r");
    if (!file) {
        log_message("No blocked IPs file found. Starting with empty blocked IPs list.");
        return;
    }
    
    char line[1024];
    blocked_ip_count = 0;
    
    while (fgets(line, sizeof(line), file) && blocked_ip_count < MAX_BLOCKED_IPS) {
        // Remove newline
        line[strcspn(line, "\r\n")] = 0;
        
        // Parse line: ip|block_time|duration|reason
        char *token = strtok(line, "|");
        if (!token) continue;
        
        strncpy(blocked_ips[blocked_ip_count].ip, token, sizeof(blocked_ips[blocked_ip_count].ip) - 1);
        
        token = strtok(NULL, "|");
        if (!token) continue;
        blocked_ips[blocked_ip_count].block_time = (time_t)atoll(token);
        
        token = strtok(NULL, "|");
        if (!token) continue;
        blocked_ips[blocked_ip_count].block_duration = atoi(token);
        
        token = strtok(NULL, "|");
        if (token) {
            strncpy(blocked_ips[blocked_ip_count].reason, token, sizeof(blocked_ips[blocked_ip_count].reason) - 1);
        } else {
            strcpy(blocked_ips[blocked_ip_count].reason, "Unknown");
        }
        
        blocked_ip_count++;
    }
    
    fclose(file);
    log_message("Loaded %d blocked IPs", blocked_ip_count);
}

// Save blocked IPs to file
void save_blocked_ips() {
    FILE *file = fopen(BLOCKED_IPS_FILE, "w");
    if (!file) {
        log_message("Error opening blocked IPs file for writing");
        return;
    }
    
    pthread_mutex_lock(&blocked_ips_mutex);
    
    for (int i = 0; i < blocked_ip_count; i++) {
        // Check if the block has expired
        if (blocked_ips[i].block_duration > 0) {
            time_t current_time = time(NULL);
            if (current_time > blocked_ips[i].block_time + blocked_ips[i].block_duration) {
                continue; // Skip expired blocks
            }
        }
        
        fprintf(file, "%s|%ld|%d|%s\n", 
                blocked_ips[i].ip, 
                (long)blocked_ips[i].block_time, 
                blocked_ips[i].block_duration, 
                blocked_ips[i].reason);
    }
    
    pthread_mutex_unlock(&blocked_ips_mutex);
    fclose(file);
    log_message("Saved blocked IPs to file");
}

// Check if an IP is blocked
int is_ip_blocked(const char *ip) {
    time_t current_time = time(NULL);
    int blocked = 0;
    
    pthread_mutex_lock(&blocked_ips_mutex);
    
    for (int i = 0; i < blocked_ip_count; i++) {
        if (strcmp(blocked_ips[i].ip, ip) == 0) {
            // Check if the block has expired
            if (blocked_ips[i].block_duration > 0) {
                if (current_time > blocked_ips[i].block_time + blocked_ips[i].block_duration) {
                    continue; // Block expired
                }
            }
            blocked = 1;
            break;
        }
    }
    
    pthread_mutex_unlock(&blocked_ips_mutex);
    return blocked;
}

// Add an IP to the blocked list
void add_blocked_ip(const char *ip, const char *reason, int duration) {
    pthread_mutex_lock(&blocked_ips_mutex);
    
    // Check if IP is already blocked
    for (int i = 0; i < blocked_ip_count; i++) {
        if (strcmp(blocked_ips[i].ip, ip) == 0) {
            // Update existing entry
            blocked_ips[i].block_time = time(NULL);
            blocked_ips[i].block_duration = duration;
            strncpy(blocked_ips[i].reason, reason, sizeof(blocked_ips[i].reason) - 1);
            pthread_mutex_unlock(&blocked_ips_mutex);
            log_message("Updated block for IP %s: %s", ip, reason);
            return;
        }
    }
    
    // Add new blocked IP if there's space
    if (blocked_ip_count < MAX_BLOCKED_IPS) {
        strncpy(blocked_ips[blocked_ip_count].ip, ip, sizeof(blocked_ips[blocked_ip_count].ip) - 1);
        blocked_ips[blocked_ip_count].block_time = time(NULL);
        blocked_ips[blocked_ip_count].block_duration = duration;
        strncpy(blocked_ips[blocked_ip_count].reason, reason, sizeof(blocked_ips[blocked_ip_count].reason) - 1);
        blocked_ip_count++;
        log_message("Blocked IP %s: %s", ip, reason);
    } else {
        log_message("Blocked IPs list is full, cannot add %s", ip);
    }
    
    pthread_mutex_unlock(&blocked_ips_mutex);
    save_blocked_ips();
}

// Remove an IP from the blocked list
void remove_blocked_ip(const char *ip) {
    pthread_mutex_lock(&blocked_ips_mutex);
    
    int found = 0;
    for (int i = 0; i < blocked_ip_count; i++) {
        if (strcmp(blocked_ips[i].ip, ip) == 0) {
            // Remove by shifting all elements down
            for (int j = i; j < blocked_ip_count - 1; j++) {
                strcpy(blocked_ips[j].ip, blocked_ips[j + 1].ip);
                blocked_ips[j].block_time = blocked_ips[j + 1].block_time;
                blocked_ips[j].block_duration = blocked_ips[j + 1].block_duration;
                strcpy(blocked_ips[j].reason, blocked_ips[j + 1].reason);
            }
            blocked_ip_count--;
            found = 1;
            break;
        }
    }
    
    pthread_mutex_unlock(&blocked_ips_mutex);
    
    if (found) {
        log_message("Unblocked IP %s", ip);
        save_blocked_ips();
    }
}

// Clean up expired blocked IPs
void cleanup_expired_blocked_ips() {
    time_t current_time = time(NULL);
    int changes = 0;
    
    pthread_mutex_lock(&blocked_ips_mutex);
    
    for (int i = 0; i < blocked_ip_count; i++) {
        if (blocked_ips[i].block_duration > 0) {
            if (current_time > blocked_ips[i].block_time + blocked_ips[i].block_duration) {
                // Remove by shifting all elements down
                log_message("Block expired for IP %s", blocked_ips[i].ip);
                for (int j = i; j < blocked_ip_count - 1; j++) {
                    strcpy(blocked_ips[j].ip, blocked_ips[j + 1].ip);
                    blocked_ips[j].block_time = blocked_ips[j + 1].block_time;
                    blocked_ips[j].block_duration = blocked_ips[j + 1].block_duration;
                    strcpy(blocked_ips[j].reason, blocked_ips[j + 1].reason);
                }
                blocked_ip_count--;
                i--; // Adjust index since we removed an element
                changes++;
            }
        }
    }
    
    pthread_mutex_unlock(&blocked_ips_mutex);
    
    if (changes > 0) {
        log_message("Cleaned up %d expired IP blocks", changes);
        save_blocked_ips();
    }
}

// Check if a request matches any rules
int check_request(const char *request, const char *client_ip) {
    regmatch_t match;
    
    pthread_mutex_lock(&rules_mutex);
    
    for (int i = 0; i < rule_count; i++) {
        if (!rules[i].enabled) continue;
        
        int result = regexec(&rules[i].regex, request, 1, &match, 0);
        if (result == 0) {
            // Rule matched
            pthread_mutex_unlock(&rules_mutex);
            
            log_message("Rule %d (%s) matched for IP %s", 
                        rules[i].id, rules[i].name, client_ip);
            
            if (strcmp(rules[i].action, "block") == 0) {
                add_blocked_ip(client_ip, rules[i].name, 86400); // Block for 24 hours
                return 1; // Block the request
            } else if (strcmp(rules[i].action, "log") == 0) {
                // Just log, continue checking other rules
                continue;
            }
        }
    }
    
    pthread_mutex_unlock(&rules_mutex);
    return 0; // Allow the request
}

// Logging function with variable arguments
void log_message(const char *format, ...) {
    if (!config.enable_logging) return;
    
    va_list args;
    va_start(args, format);
    
    pthread_mutex_lock(&log_mutex);
    
    FILE *log_file = fopen(config.log_file, "a");
    if (log_file) {
        time_t now = time(NULL);
        struct tm *time_info = localtime(&now);
        char time_str[30];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", time_info);
        
        fprintf(log_file, "[%s] ", time_str);
        vfprintf(log_file, format, args);
        fprintf(log_file, "\n");
        
        fclose(log_file);
    }
    
    pthread_mutex_unlock(&log_mutex);
    
    va_end(args);
}

// Reverse proxy thread function
void *reverse_proxy_thread(void *arg) {
    // Create listening socket
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        log_message("Error creating server socket: %s", strerror(errno));
        return NULL;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_message("Error setting socket options: %s", strerror(errno));
        close(server_sock);
        return NULL;
    }
    
    // Bind to address and port
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(config.listen_address);
    server_addr.sin_port = htons(config.listen_port);
    
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        log_message("Error binding server socket: %s", strerror(errno));
        close(server_sock);
        return NULL;
    }
    
    // Listen for connections
    if (listen(server_sock, config.max_connections) < 0) {
        log_message("Error listening on server socket: %s", strerror(errno));
        close(server_sock);
        return NULL;
    }
    
    log_message("Reverse proxy started on %s:%d", config.listen_address, config.listen_port);
    
    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        // Accept connection from client
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) {
            if (errno != EINTR) {
                log_message("Error accepting connection: %s", strerror(errno));
            }
            continue;
        }
        
        // Get client IP
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        
        // Check if IP is blocked
        if (is_ip_blocked(client_ip)) {
            log_message("Rejected connection from blocked IP %s", client_ip);
            char *blocked_msg = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nYour IP address is blocked by the WAF.\r\n";
            send(client_sock, blocked_msg, strlen(blocked_msg), 0);
            close(client_sock);
            continue;
        }
        
        // Create connection to backend server
        int backend_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (backend_sock < 0) {
            log_message("Error creating backend socket: %s", strerror(errno));
            close(client_sock);
            continue;
        }
        
        struct sockaddr_in backend_addr;
        memset(&backend_addr, 0, sizeof(backend_addr));
        backend_addr.sin_family = AF_INET;
        backend_addr.sin_addr.s_addr = inet_addr(config.backend_address);
        backend_addr.sin_port = htons(config.backend_port);
        
        // Set timeout
        struct timeval timeout;
        timeout.tv_sec = config.timeout;
        timeout.tv_usec = 0;
        setsockopt(backend_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(backend_sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        
        // Connect to backend
        if (connect(backend_sock, (struct sockaddr *)&backend_addr, sizeof(backend_addr)) < 0) {
            log_message("Error connecting to backend server: %s", strerror(errno));
            close(client_sock);
            close(backend_sock);
            continue;
        }
        
        // Read request from client
        char buffer[BUFFER_SIZE];
        ssize_t bytes_read = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_read <= 0) {
            log_message("Error reading from client: %s", strerror(errno));
            close(client_sock);
            close(backend_sock);
            continue;
        }
        
        buffer[bytes_read] = '\0';
        
        // Check request against rules
        if (check_request(buffer, client_ip)) {
            log_message("Blocked request from IP %s", client_ip);
            char *blocked_msg = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nRequest blocked by WAF rules.\r\n";
            send(client_sock, blocked_msg, strlen(blocked_msg), 0);
            close(client_sock);
            close(backend_sock);
            continue;
        }
        
        // Forward request to backend
        if (send(backend_sock, buffer, bytes_read, 0) < 0) {
            log_message("Error forwarding request to backend: %s", strerror(errno));
            close(client_sock);
            close(backend_sock);
            continue;
        }
        
        // Receive response from backend and forward to client
        while ((bytes_read = recv(backend_sock, buffer, BUFFER_SIZE, 0)) > 0) {
            if (send(client_sock, buffer, bytes_read, 0) < 0) {
                log_message("Error forwarding response to client: %s", strerror(errno));
                break;
            }
        }
        
        // Close connections
        close(client_sock);
        close(backend_sock);
    }
    
    close(server_sock);
    return NULL;
}

// Web UI thread function
void *web_ui_thread(void *arg) {
    // Create listening socket
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        log_message("Error creating Web UI server socket: %s", strerror(errno));
        return NULL;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        log_message("Error setting Web UI socket options: %s", strerror(errno));
        close(server_sock);
        return NULL;
    }
    
    // Bind to address and port
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("0.0.0.0");
    server_addr.sin_port = htons(WEB_UI_PORT);
    
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        log_message("Error binding Web UI server socket: %s", strerror(errno));
        close(server_sock);
        return NULL;
    }
    
    // Listen for connections
    if (listen(server_sock, 10) < 0) {
        log_message("Error listening on Web UI server socket: %s", strerror(errno));
        close(server_sock);
        return NULL;
    }
    
    log_message("Web UI started on port %d", WEB_UI_PORT);
    
    while (running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        // Accept connection from client
        int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) {
            if (errno != EINTR) {
                log_message("Error accepting Web UI connection: %s", strerror(errno));
            }
            continue;
        }
        
        // Get client IP
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        log_message("Web UI connection from %s", client_ip);
        
        // Handle the web UI request
        handle_web_ui_request(client_sock);
        
        // Close connection
        close(client_sock);
    }
    
    close(server_sock);
    return NULL;
}

// Handle web UI request
void handle_web_ui_request(int client_socket) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_read <= 0) {
        return;
    }
    
    buffer[bytes_read] = '\0';
    
    // Parse HTTP request
    char method[16], path[256], protocol[16];
    sscanf(buffer, "%15s %255s %15s", method, path, protocol);
    
    // Handle API endpoints
    if (strcmp(method, "GET") == 0) {
        if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
            // Serve main UI page
            char *response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                             "<!DOCTYPE html>\n"
                             "<html>\n"
                             "<head>\n"
                             "    <title>WAF Management Console</title>\n"
                             "    <style>\n"
                             "        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }\n"
                             "        h1 { color: #333; }\n"
                             "        .container { display: flex; }\n"
                             "        .sidebar { width: 200px; padding: 10px; background: #f0f0f0; }\n"
                             "        .content { flex-grow: 1; padding: 20px; }\n"
                             "        .sidebar a { display: block; padding: 10px; text-decoration: none; color: #333; }\n"
                             "        .sidebar a:hover { background: #ddd; }\n"
                             "        table { border-collapse: collapse; width: 100%; }\n"
                             "        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n"
                             "        th { background-color: #f2f2f2; }\n"
                             "        tr:nth-child(even) { background-color: #f9f9f9; }\n"
                             "        .button { background: #4CAF50; color: white; border: none; padding: 8px 12px; cursor: pointer; }\n"
                             "        .button-red { background: #f44336; }\n"
                             "    </style>\n"
                             "    <script>\n"
                             "        function loadContent(page) {\n"
                             "            fetch(page)\n"
                             "                .then(response => response.text())\n"
                             "                .then(data => {\n"
                             "                    document.getElementById('content').innerHTML = data;\n"
                             "                });\n"
                             "        }\n"
                             "        function blockIP() {\n"
                             "            const ip = document.getElementById('ip-input').value;\n"
                             "            const reason = document.getElementById('reason-input').value;\n"
                             "            const duration = document.getElementById('duration-input').value;\n"
                             "            \n"
                             "            fetch('/api/block-ip', {\n"
                             "                method: 'POST',\n"
                             "                headers: {\n"
                             "                    'Content-Type': 'application/x-www-form-urlencoded',\n"
                             "                },\n"
                             "                body: `ip=${ip}&reason=${reason}&duration=${duration}`\n"
                             "            })\n"
                             "            .then(response => response.json())\n"
                             "            .then(data => {\n"
                             "                alert(data.message);\n"
                             "                loadContent('/api/blocked-ips');\n"
                             "            });\n"
                             "        }\n"
                             "        function unblockIP(ip) {\n"
                             "            if (confirm('Are you sure you want to unblock ' + ip + '?')) {\n"
                             "                fetch('/api/unblock-ip', {\n"
                             "                    method: 'POST',\n"
                             "                    headers: {\n"
                             "                        'Content-Type': 'application/x-www-form-urlencoded',\n"
                             "                    },\n"
                             "                    body: `ip=${ip}`\n"
                             "                })\n"
                             "                .then(response => response.json())\n"
                             "                .then(data => {\n"
                             "                    alert(data.message);\n"
                             "                    loadContent('/api/blocked-ips');\n"
                             "                });\n"
                             "            }\n"
                             "        }\n"
                             "        function toggleRule(id, enabled) {\n"
                             "            fetch('/api/toggle-rule', {\n"
                             "                method: 'POST',\n"
                             "                headers: {\n"
                             "                    'Content-Type': 'application/x-www-form-urlencoded',\n"
                             "                },\n"
                             "                body: `id=${id}&enabled=${enabled ? 0 : 1}`\n"
                             "            })\n"
                             "            .then(response => response.json())\n"
                             "            .then(data => {\n"
                             "                alert(data.message);\n"
                             "                loadContent('/api/rules');\n"
                             "            });\n"
                             "        }\n"
                             "    </script>\n"
                             "</head>\n"
                             "<body onload=\"loadContent('/api/dashboard')\">\n"
                             "    <h1>WAF Management Console</h1>\n"
                             "    <div class=\"container\">\n"
                             "        <div class=\"sidebar\">\n"
                             "            <a href=\"#\" onclick=\"loadContent('/api/dashboard'); return false;\">Dashboard</a>\n"
                             "            <a href=\"#\" onclick=\"loadContent('/api/blocked-ips'); return false;\">Blocked IPs</a>\n"
                             "            <a href=\"#\" onclick=\"loadContent('/api/rules'); return false;\">Rules</a>\n"
                             "            <a href=\"#\" onclick=\"loadContent('/api/logs'); return false;\">Logs</a>\n"
                             "            <a href=\"#\" onclick=\"loadContent('/api/settings'); return false;\">Settings</a>\n"
                             "        </div>\n"
                             "        <div id=\"content\" class=\"content\">\n"
                             "            Loading...\n"
                             "        </div>\n"
                             "    </div>\n"
                             "</body>\n"
                             "</html>";
            
            send(client_socket, response, strlen(response), 0);
        }
        else if (strcmp(path, "/api/dashboard") == 0) {
            // Serve dashboard content
            char response[4096];
            snprintf(response, sizeof(response), 
                     "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                     "<h2>Dashboard</h2>"
                     "<p>WAF Status: <span style='color:green;font-weight:bold;'>Running</span></p>"
                     "<p>Blocked IPs: %d</p>"
                     "<p>Active Rules: %d</p>"
                     "<p>Listening on: %s:%d</p>"
                     "<p>Forwarding to: %s:%d</p>"
                     "<h3>Quick Actions</h3>"
                     "<div>"
                     "    <button class='button' onclick=\"loadContent('/api/blocked-ips')\">Manage Blocked IPs</button> "
                     "    <button class='button' onclick=\"loadContent('/api/rules')\">Manage Rules</button>"
                     "</div>",
                     blocked_ip_count, rule_count, 
                     config.listen_address, config.listen_port,
                     config.backend_address, config.backend_port);
            
            send(client_socket, response, strlen(response), 0);
        }
        else if (strcmp(path, "/api/blocked-ips") == 0) {
            // Serve blocked IPs content
            char *header = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                           "<h2>Blocked IPs</h2>"
                           "<div style='margin-bottom: 20px;'>"
                           "    <h3>Block New IP</h3>"
                           "    <div>"
                           "        <label>IP Address: </label>"
                           "        <input type='text' id='ip-input' placeholder='192.168.1.1'>"
                           "    </div>"
                           "    <div style='margin-top: 10px;'>"
                           "        <label>Reason: </label>"
                           "        <input type='text' id='reason-input' placeholder='Suspicious activity'>"
                           "    </div>"
                           "    <div style='margin-top: 10px;'>"
                           "        <label>Duration (seconds): </label>"
                           "        <input type='number' id='duration-input' value='86400' min='0'>"
                           "        <span style='font-size: 0.8em;'>(0 for permanent)</span>"
                           "    </div>"
                           "    <div style='margin-top: 10px;'>"
                           "        <button class='button' onclick='blockIP()'>Block IP</button>"
                           "    </div>"
                           "</div>"
                           "<h3>Currently Blocked IPs</h3>";
            
            char table_start[] = "<table>"
                                "<tr>"
                                "<th>IP Address</th>"
                                "<th>Blocked Since</th>"
                                "<th>Duration</th>"
                                "<th>Reason</th>"
                                "<th>Actions</th>"
                                "</tr>";
            
            char *table_end = "</table>";
            
            // Send header and table start
            send(client_socket, header, strlen(header), 0);
            send(client_socket, table_start, strlen(table_start), 0);
            
            // Generate table rows for each blocked IP
            time_t current_time = time(NULL);
            pthread_mutex_lock(&blocked_ips_mutex);
            
            for (int i = 0; i < blocked_ip_count; i++) {
                char time_str[64];
                struct tm *tm_info = localtime(&blocked_ips[i].block_time);
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
                
                char duration_str[64];
                if (blocked_ips[i].block_duration == 0) {
                    strcpy(duration_str, "Permanent");
                } else {
                    time_t expires = blocked_ips[i].block_time + blocked_ips[i].block_duration;
                    time_t remaining = (expires > current_time) ? (expires - current_time) : 0;
                    
                    if (remaining > 0) {
                        if (remaining < 60) {
                            snprintf(duration_str, sizeof(duration_str), "%ld seconds", remaining);
                        } else if (remaining < 3600) {
                            snprintf(duration_str, sizeof(duration_str), "%ld minutes", remaining / 60);
                        } else if (remaining < 86400) {
                            snprintf(duration_str, sizeof(duration_str), "%ld hours", remaining / 3600);
                        } else {
                            snprintf(duration_str, sizeof(duration_str), "%ld days", remaining / 86400);
                        }
                    } else {
                        strcpy(duration_str, "Expired");
                    }
                }
                
                char row[1024];
                snprintf(row, sizeof(row), 
                         "<tr>"
                         "<td>%s</td>"
                         "<td>%s</td>"
                         "<td>%s</td>"
                         "<td>%s</td>"
                         "<td><button class='button button-red' onclick=\"unblockIP('%s')\">Unblock</button></td>"
                         "</tr>",
                         blocked_ips[i].ip, time_str, duration_str, blocked_ips[i].reason, blocked_ips[i].ip);
                
                send(client_socket, row, strlen(row), 0);
            }
            
            pthread_mutex_unlock(&blocked_ips_mutex);
            
            // Send table end
            send(client_socket, table_end, strlen(table_end), 0);
        }
        else if (strcmp(path, "/api/rules") == 0) {
            // Serve rules content
            char *header = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                           "<h2>WAF Rules</h2>"
                           "<p>Rules are loaded from the config-rule.conf file.</p>"
                           "<table>"
                           "<tr>"
                           "<th>ID</th>"
                           "<th>Name</th>"
                           "<th>Pattern</th>"
                           "<th>Action</th>"
                           "<th>Status</th>"
                           "<th>Toggle</th>"
                           "</tr>";
            
            char *table_end = "</table>";
            
            // Send header
            send(client_socket, header, strlen(header), 0);
            
            // Generate table rows for each rule
            pthread_mutex_lock(&rules_mutex);
            
            for (int i = 0; i < rule_count; i++) {
                char row[2048];
                snprintf(row, sizeof(row), 
                         "<tr>"
                         "<td>%d</td>"
                         "<td>%s</td>"
                         "<td><div style='max-width: 400px; overflow: auto;'>%s</div></td>"
                         "<td>%s</td>"
                         "<td>%s</td>"
                         "<td><button class='button' onclick=\"toggleRule(%d, %d)\">%s</button></td>"
                         "</tr>",
                         rules[i].id, rules[i].name, rules[i].pattern, rules[i].action,
                         rules[i].enabled ? "Enabled" : "Disabled",
                         rules[i].id, rules[i].enabled,
                         rules[i].enabled ? "Disable" : "Enable");
                
                send(client_socket, row, strlen(row), 0);
            }
            
            pthread_mutex_unlock(&rules_mutex);
            
            // Send table end
            send(client_socket, table_end, strlen(table_end), 0);
        }
        else if (strcmp(path, "/api/logs") == 0) {
            // Serve logs content
            char *header = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                           "<h2>WAF Logs</h2>"
                           "<div style='margin-bottom: 10px;'>"
                           "    <button class='button' onclick=\"loadContent('/api/logs')\">Refresh</button>"
                           "</div>"
                           "<pre style='background: #f0f0f0; padding: 10px; overflow: auto; height: 400px;'>";
            
            char *footer = "</pre>";
            
            // Send header
            send(client_socket, header, strlen(header), 0);
            
            // Read and send log file content
            FILE *log_file = fopen(config.log_file, "r");
            if (log_file) {
                char buffer[BUFFER_SIZE];
                
                // Go to the end of the file minus 4KB
                fseek(log_file, 0, SEEK_END);
                long file_size = ftell(log_file);
                long offset = (file_size > 4096) ? file_size - 4096 : 0;
                fseek(log_file, offset, SEEK_SET);
                
                // If we're not at the beginning of the file, ignore the first line (it might be incomplete)
                if (offset > 0) {
                    fgets(buffer, sizeof(buffer), log_file);
                }
                
                // Read and send the rest of the file
                while (fgets(buffer, sizeof(buffer), log_file)) {
                    // HTML-escape the buffer
                    char *escaped = buffer;
                    char html_buffer[BUFFER_SIZE * 2];
                    int j = 0;
                    
                    for (int i = 0; buffer[i] && j < sizeof(html_buffer) - 1; i++) {
                        if (buffer[i] == '<') {
                            html_buffer[j++] = '&';
                            html_buffer[j++] = 'l';
                            html_buffer[j++] = 't';
                            html_buffer[j++] = ';';
                        } else if (buffer[i] == '>') {
                            html_buffer[j++] = '&';
                            html_buffer[j++] = 'g';
                            html_buffer[j++] = 't';
                            html_buffer[j++] = ';';
                        } else if (buffer[i] == '&') {
                            html_buffer[j++] = '&';
                            html_buffer[j++] = 'a';
                            html_buffer[j++] = 'm';
                            html_buffer[j++] = 'p';
                            html_buffer[j++] = ';';
                        } else {
                            html_buffer[j++] = buffer[i];
                        }
                    }
                    html_buffer[j] = '\0';
                    
                    send(client_socket, html_buffer, strlen(html_buffer), 0);
                }
                
                fclose(log_file);
            } else {
                char *error_msg = "Could not open log file.";
                send(client_socket, error_msg, strlen(error_msg), 0);
            }
            
            // Send footer
            send(client_socket, footer, strlen(footer), 0);
        }
        else if (strcmp(path, "/api/settings") == 0) {
            // Serve settings content
            char response[2048];
            snprintf(response, sizeof(response), 
                     "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                     "<h2>WAF Settings</h2>"
                     "<p>To change these settings, edit the config-rule.conf file and restart the WAF.</p>"
                     "<table>"
                     "<tr><th>Setting</th><th>Value</th></tr>"
                     "<tr><td>Listen Address</td><td>%s</td></tr>"
                     "<tr><td>Listen Port</td><td>%d</td></tr>"
                     "<tr><td>Backend Address</td><td>%s</td></tr>"
                     "<tr><td>Backend Port</td><td>%d</td></tr>"
                     "<tr><td>Max Connections</td><td>%d</td></tr>"
                     "<tr><td>Timeout</td><td>%d seconds</td></tr>"
                     "<tr><td>Logging</td><td>%s</td></tr>"
                     "<tr><td>Log File</td><td>%s</td></tr>"
                     "</table>"
                     "<h3>System Information</h3>"
                     "<table>"
                     "<tr><td>Compiled On</td><td>%s %s</td></tr>"
                     "</table>",
                     config.listen_address, config.listen_port,
                     config.backend_address, config.backend_port,
                     config.max_connections, config.timeout,
                     config.enable_logging ? "Enabled" : "Disabled",
                     config.log_file,
                     __DATE__, __TIME__);
            
            send(client_socket, response, strlen(response), 0);
        }
    }
    else if (strcmp(method, "POST") == 0) {
        // Handle API requests
        if (strcmp(path, "/api/block-ip") == 0) {
            // Extract IP, reason, and duration from POST data
            char ip[16] = {0};
            char reason[256] = "Manual block";
            int duration = 86400; // Default: 1 day
            
            char *content_start = strstr(buffer, "\r\n\r\n");
            if (content_start) {
                content_start += 4;
                
                // Parse form data (simple approach)
                char *ip_start = strstr(content_start, "ip=");
                if (ip_start) {
                    ip_start += 3;
                    char *end = strchr(ip_start, '&');
                    if (end) {
                        strncpy(ip, ip_start, end - ip_start < 15 ? end - ip_start : 15);
                    } else {
                        strncpy(ip, ip_start, 15);
                    }
                }
                
                char *reason_start = strstr(content_start, "reason=");
                if (reason_start) {
                    reason_start += 7;
                    char *end = strchr(reason_start, '&');
                    if (end) {
                        strncpy(reason, reason_start, end - reason_start < 255 ? end - reason_start : 255);
                    } else {
                        strncpy(reason, reason_start, 255);
                    }
                }
                
                char *duration_start = strstr(content_start, "duration=");
                if (duration_start) {
                    duration = atoi(duration_start + 9);
                }
            }
            
            // Validate IP
            struct sockaddr_in sa;
            int valid_ip = inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0;
            
            char response[512];
            if (valid_ip) {
                add_blocked_ip(ip, reason, duration);
                snprintf(response, sizeof(response), 
                         "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                         "{\"success\": true, \"message\": \"IP %s blocked successfully.\"}",
                         ip);
            } else {
                snprintf(response, sizeof(response), 
                         "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n"
                         "{\"success\": false, \"message\": \"Invalid IP address format.\"}");
            }
            
            send(client_socket, response, strlen(response), 0);
        }
        else if (strcmp(path, "/api/unblock-ip") == 0) {
            // Extract IP from POST data
            char ip[16] = {0};
            
            char *content_start = strstr(buffer, "\r\n\r\n");
            if (content_start) {
                content_start += 4;
                
                // Parse form data
                char *ip_start = strstr(content_start, "ip=");
                if (ip_start) {
                    ip_start += 3;
                    char *end = strchr(ip_start, '&');
                    if (end) {
                        strncpy(ip, ip_start, end - ip_start < 15 ? end - ip_start : 15);
                    } else {
                        strncpy(ip, ip_start, 15);
                    }
                }
            }
            
            char response[512];
            if (ip[0] != '\0') {
                remove_blocked_ip(ip);
                snprintf(response, sizeof(response), 
                         "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                         "{\"success\": true, \"message\": \"IP %s unblocked successfully.\"}",
                         ip);
            } else {
                snprintf(response, sizeof(response), 
                         "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n"
                         "{\"success\": false, \"message\": \"IP address is required.\"}");
            }
            
            send(client_socket, response, strlen(response), 0);
        }
        else if (strcmp(path, "/api/toggle-rule") == 0) {
            // Extract rule ID and enabled status from POST data
            int rule_id = -1;
            int enabled = -1;
            
            char *content_start = strstr(buffer, "\r\n\r\n");
            if (content_start) {
                content_start += 4;
                
                // Parse form data
                char *id_start = strstr(content_start, "id=");
                if (id_start) {
                    rule_id = atoi(id_start + 3);
                }
                
                char *enabled_start = strstr(content_start, "enabled=");
                if (enabled_start) {
                    enabled = atoi(enabled_start + 8);
                }
            }
            
            char response[512];
            if (rule_id >= 0 && enabled >= 0) {
                int found = 0;
                
                pthread_mutex_lock(&rules_mutex);
                
                for (int i = 0; i < rule_count; i++) {
                    if (rules[i].id == rule_id) {
                        // Clean up old regex if it was compiled
                        if (rules[i].enabled) {
                            regfree(&rules[i].regex);
                        }
                        
                        // Set new enabled status
                        rules[i].enabled = enabled;
                        
                        // Compile regex if enabled
                        if (rules[i].enabled) {
                            int result = regcomp(&rules[i].regex, rules[i].pattern, REG_EXTENDED);
                            if (result != 0) {
                                log_message("Error compiling regex pattern for rule %d", rules[i].id);
                                rules[i].enabled = 0;
                            }
                        }
                        
                        found = 1;
                        break;
                    }
                }
                
                pthread_mutex_unlock(&rules_mutex);
                
                if (found) {
                    snprintf(response, sizeof(response), 
                             "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"
                             "{\"success\": true, \"message\": \"Rule %d %s successfully.\"}",
                             rule_id, enabled ? "enabled" : "disabled");
                } else {
                    snprintf(response, sizeof(response), 
                             "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\n\r\n"
                             "{\"success\": false, \"message\": \"Rule with ID %d not found.\"}",
                             rule_id);
                }
            } else {
                snprintf(response, sizeof(response), 
                         "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\n\r\n"
                         "{\"success\": false, \"message\": \"Rule ID and enabled status are required.\"}");
            }
            
            send(client_socket, response, strlen(response), 0);
        }
    } else {
        // Method not allowed
        char *response = "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/plain\r\n\r\n"
                         "Method not allowed";
        send(client_socket, response, strlen(response), 0);
    }
}