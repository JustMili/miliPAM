#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <sodium.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include <array>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>

using namespace std;

static bool write_all(int fd, const char* p, size_t n);
static pid_t spawn_helper(int& wfd);
static int wait_helper(pid_t pid);
static int authenticate(const char* user, const char* pass);

extern "C" int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    const char *username = nullptr;
    const char *service_name = nullptr;
    const char *password = nullptr;

    pam_get_item(pamh, PAM_SERVICE, (const void **)&service_name);
    pam_get_user(pamh, &username, nullptr);
    pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);

    if (password == nullptr) {
        struct pam_conv *conv = nullptr;
        pam_get_item(pamh, PAM_CONV, (const void **)&conv);
        if (conv && conv->conv) {
            struct pam_message msg = {PAM_PROMPT_ECHO_OFF, "Password: "};
            const struct pam_message *msgp = &msg;
            struct pam_response *resp = nullptr;
            if (conv->conv(1, &msgp, &resp, conv->appdata_ptr) == PAM_SUCCESS && resp) {
                if (resp->resp != nullptr) {
                    pam_set_item(pamh, PAM_AUTHTOK, resp->resp);
                    sodium_memzero(resp->resp, strlen(resp->resp));
                    free(resp->resp);
                }
                free(resp);
                pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
            }
        }
    }

    if (username == nullptr || password == nullptr) {
        return PAM_AUTH_ERR;
    }
    int rc = authenticate(username, password);
    if (rc != PAM_SUCCESS) {
        pam_set_item(pamh, PAM_AUTHTOK, nullptr);
    }
    return rc;
}

extern "C" int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

static bool write_all(int fd, const char* p, size_t n) {
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return false; }
        p += w; n -= w;
    }
    return true;
}

static pid_t spawn_helper(int& wfd) {
    int p[2];
    if (pipe2(p, O_CLOEXEC) == -1) return -1;
    char a0[] = "milipam_helper";
    char* args[] = {a0, nullptr};
    char* envp[] = {nullptr};

    pid_t pid = fork();
    if (pid == 0) {
        dup2(p[0], 0);
        int dn = open("/dev/null", O_WRONLY);
        dup2(dn, 1); dup2(dn, 2);
        close_range(3, ~0U, 0);
        execve("/usr/bin/milipam_helper", args, envp);
        _exit(127);
    }
    close(p[0]);
    if (pid == -1) { close(p[1]); return -1; }
    wfd = p[1];
    return pid;
}

static int authenticate(const char* user, const char* pass) {
    size_t ul = strlen(user), pl = strlen(pass);
    if (ul == 0 || pl == 0 || ul + 1 + pl > 511) return PAM_AUTH_ERR;

    array<char, 512> buf{};
    memcpy(buf.data(), user, ul);
    memcpy(buf.data() + ul + 1, pass, pl);
    size_t len = ul + 1 + pl;

    sigset_t blk, old;
    sigemptyset(&blk); sigaddset(&blk, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &blk, &old);

    struct sigaction sa{}, oldsa{};
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGCHLD, &sa, &oldsa);

    int rc = PAM_SYSTEM_ERR, wfd = -1;
    pid_t pid = spawn_helper(wfd);
    if (pid > 0) {
        bool ok = write_all(wfd, buf.data(), len);
        close(wfd);
        rc = wait_helper(pid);
        if (!ok) rc = PAM_SYSTEM_ERR;
    }
    sigaction(SIGCHLD, &oldsa, nullptr);
    sodium_memzero(buf.data(), buf.size());

    timespec ts{0, 0};
    if (!sigismember(&old, SIGPIPE)) sigtimedwait(&blk, nullptr, &ts);
    pthread_sigmask(SIG_SETMASK, &old, nullptr);
    return rc;
}

static int wait_helper(pid_t pid) {
    int st;
    while (waitpid(pid, &st, 0) == -1)
        if (errno != EINTR) return PAM_SYSTEM_ERR;
    if (!WIFEXITED(st)) return PAM_SYSTEM_ERR;
    switch (WEXITSTATUS(st)) {
        case 0:  return PAM_SUCCESS;
        case 1: case 3: return PAM_AUTH_ERR;
        case 2:  return PAM_USER_UNKNOWN;
        default: return PAM_SYSTEM_ERR;
    }
}