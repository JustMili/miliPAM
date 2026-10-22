#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <nlohmann/json.hpp>
#include <sodium.h>
#include <argon2.h>
#include <fstream>

using namespace std;
using json = nlohmann::json;

const string db_path = "/var/lib/milipam/data.json";

json read_db(const string& filename){
    ifstream file(filename);
    if (!file.is_open()) {
        return json::object(); 
    }

    try {
        json j;
        file >> j;
        return j;
    } catch (const json::parse_error& e) {
        throw runtime_error("ERROR JSON READ: " + (string)e.what());
    }
}

void write_db(const string& filename, const json& j){
    ofstream file(filename);
    if (!file.is_open()) {
        throw runtime_error("ERROR JSON WHEN TRY OPEN: "+ filename);
    }
    file << setw(4) << j << endl;
    if (file.fail()) {
        throw runtime_error("ERROR JSON WRITE");
    }
}

bool verify_password(const string& hash, const char* password) {
    if (sodium_init() < 0) {
        return false;
    }
    return argon2id_verify(hash.c_str(), password, strlen(password)) == ARGON2_OK;
}

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

    string stored_hash;
    try {
        json j = read_db(db_path);
        if (!j.contains("users") || !j["users"].is_object()) {
            return PAM_USER_UNKNOWN;
        }

        string user_str(username);
        //cout<<user_str<<endl;
        if (!j["users"].contains(user_str)) {
            return PAM_USER_UNKNOWN;
        }

        auto& user_data = j["users"][user_str];
        bool authenticated = false;

        for (auto entry = user_data.begin(); entry != user_data.end(); entry++) {
            int max_uses = entry[0][3];
            if (max_uses == 0) {
                continue;
            }

            string hash_file_path = entry[0][2];
            ifstream h_file(hash_file_path);
            if (!h_file.is_open()) {
                continue;
            }
            getline(h_file, stored_hash);
            h_file.close();

            if (verify_password(stored_hash, password)) {
                if (max_uses > 0) {
                    entry[0][3] = max_uses - 1;
                    write_db(db_path, j);
                }
                authenticated = true;
                break;
            }
        }

        if (!stored_hash.empty()) {
            sodium_memzero(&stored_hash[0], stored_hash.size());
        }

        if (authenticated) {
            return PAM_SUCCESS;
        }
    } catch (...) {
        if (!stored_hash.empty()) {
            sodium_memzero(&stored_hash[0], stored_hash.size());
        }
        return PAM_SYSTEM_ERR;
    }

    return PAM_AUTH_ERR;
}

extern "C" int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}