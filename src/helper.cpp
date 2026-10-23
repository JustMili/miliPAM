#include <argon2.h>
#include <sodium.h>
#include <nlohmann/json.hpp>
#include <fcntl.h>
#include <pwd.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <array>
#include <cerrno>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace std;
using json = nlohmann::json;

static bool read_input(array<char, 513>& b, size_t& len);
static bool caller_allowed(string_view user);
void write_db(const string& path, const json& j);
static json read_db(const string& path);
static int check_password(const string& user, string_view pass);

const string db_path = "/var/lib/milipam/data.json";
const string lock_path = "/var/lib/milipam/data.lock";

class FileLock {
    int fd;
public:
    explicit FileLock(const string& path) {
        fd = open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
        if (fd == -1) throw runtime_error("lock open");
        if (flock(fd, LOCK_EX) == -1) { close(fd); throw runtime_error("lock flock"); }
    }
    ~FileLock() { flock(fd, LOCK_UN); close(fd); }
    FileLock(const FileLock&) = delete;
    FileLock& operator=(const FileLock&) = delete;
};


int main() {
    prctl(PR_SET_DUMPABLE, 0);
    rlimit rl{0, 0}; setrlimit(RLIMIT_CORE, &rl);
    umask(077);
    if (sodium_init() < 0) return 4;

    array<char, 513> buf{}; size_t len = 0;
    int rc = 4;
    if (read_input(buf, len)) {
        string_view all(buf.data(), len);
        size_t p = all.find('\0');
        if (p != string_view::npos && p > 0 && p + 1 < len) {
            auto user = all.substr(0, p);
            auto pass = all.substr(p + 1);
            rc = caller_allowed(user) ? check_password(string(user), pass) : 3;
        }
    }
    sodium_memzero(buf.data(), buf.size());
    if (rc != 0) sleep(1);
    return rc;
}

static bool read_input(array<char, 513>& b, size_t& len) {
    while (len < 512) {
        ssize_t n = read(0, b.data() + len, 512 - len);
        if (n < 0) { if (errno == EINTR) continue; return false; }
        if (n == 0) return true;
        len += n;
    }
    return false;
}

static bool caller_allowed(string_view user) {
    uid_t uid = getuid();
    if (uid == 0) return true;
    passwd pw{}; passwd* res = nullptr; char buf[1024];
    if (getpwuid_r(uid, &pw, buf, sizeof buf, &res) != 0 || !res) return false;
    return user == res->pw_name;
}

void write_db(const string& path, const json& j) {
    string tmp = path + ".tmp";
    { ofstream f(tmp, ios::trunc);
      if (!f) throw runtime_error("tmp open");
      f << setw(4) << j << '\n'; f.flush();
      if (!f) throw runtime_error("tmp write"); }
    if (rename(tmp.c_str(), path.c_str()) != 0) throw runtime_error("rename");
}

static int check_password(const string& user, string_view pass) {
    try {
        FileLock lock(lock_path);
        json db = read_db(db_path);
        auto users = db.find("users");
        if (users == db.end() || !users->is_object()) return 2;
        auto it = users->find(user);
        if (it == users->end() || !it->is_array()) return 2;

        for (auto& e : *it) {
            if (!e.is_array() || e.size() < 4 || !e[2].is_string() || !e[3].is_number_integer()) continue;
            int max_uses = e[3].get<int>();
            if (max_uses == 0) continue;

            string path = e[2].get<string>();
            if (path.rfind("/var/lib/milipam/psw/", 0) != 0 || path.find("..") != string::npos) continue;

            ifstream hf(path);
            string hash;
            if (!getline(hf, hash)) continue;

            if (argon2id_verify(hash.c_str(), pass.data(), pass.size()) == ARGON2_OK) {
                if (max_uses > 0) { e[3] = max_uses - 1; write_db(db_path, db); }
                return 0;
            }
        }
        return 1;
    } catch (...) { return 4; }
}

static json read_db(const string& path) {
    ifstream f(path);
    if (!f) throw runtime_error("db open");
    return json::parse(f);
}