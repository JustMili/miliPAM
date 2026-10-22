#include <iostream>
#include <nlohmann/json.hpp>
#include <string>
#include <unistd.h>
#include <sys/types.h>
#include <fstream>
#include <iomanip>
#include <argon2.h>
#include <random>
#include <sodium.h>
#include <termios.h>
#include <chrono>
#include <sys/stat.h>
#include <stdexcept>
#include <sodium.h>

using namespace std;
using json = nlohmann::json;

void run_help();
json read_db(const string& filename);
void write_db(const string& filename, const json& j);
string hash_password(const string& password);
bool verify_password(const string& hash, const string& password);
string get_password(const string& prompt);
void create_secure_root_file(const string& filepath);

const string db_path = "/var/lib/milipam/data.json";
const string hash_path = "/var/lib/milipam/psw";
const string vers = "0.1.0";

int main(int argc, char* argv[]){
    if(argc<2){
        cout<<"nothing to do. run -help for commands"<<endl;
        return 0;
    }
    string cmd = argv[1];
    if(cmd=="-help"){
        run_help();
        return 0;
    }
    if (getuid() != 0 && (string)argv[argc-1]!="-test-no-root") {
        cerr << "You need root dumbass.\n";
        return 1;
    }
    if(cmd=="-add"){
        int need = 4;//2 arg + 2
        if((string)argv[argc-1]=="-test-no-root"){
            need+=1;
        }
        if(argc<need){
            cerr<<"not enough arguments"<<endl;
            return 2;
        }
        string psw1, psw2, user, maxuse, hash, id, note;
        int maxdb=0;
        int i = 1;
        json arr;
        try{
            json j = read_db(db_path);
            if(j.empty() || !j.contains("users")){
                j["users"]=json::object();
                j["vers"]=vers;
            }
            psw1 = get_password("Enter password: ");
            psw2 = get_password("Repeat password: ");
            if(psw1!=psw2){
                sodium_memzero(&psw1[0], psw1.size());
                sodium_memzero(&psw2[0], psw2.size());
                cerr<<"Passwords do not match"<<endl;
                return 3;
            }
            hash = hash_password(psw1);
            sodium_memzero(&psw1[0], psw1.size());
            sodium_memzero(&psw2[0], psw2.size());
            user = argv[2];
            maxuse = argv[3];
            maxdb = stoi(maxuse);
            if(!j["users"].contains(user)){
                j["users"][user]=json::array();
            }
            auto now = chrono::system_clock::now();
            auto duration = now.time_since_epoch();
            long long timestamp_seconds = chrono::duration_cast<chrono::seconds>(duration).count();
            for (auto& [username, user_data] : j["users"].items()) {
                if(user==username){
                    id+=to_string(i)+to_string(user_data.size()+1);
                    break;
                }
                i++;
            }
            create_secure_root_file(hash_path+"/"+id);
            ofstream h_file(hash_path+"/"+id);
            h_file << hash;
            h_file.close();
            sodium_memzero(&hash[0], hash.size());
            if(!(argc<need+2)){
                if((string)argv[4]=="-note"){
                    note = argv[5];
                }
            }
            arr = json::array({user, id, hash_path+"/"+id, maxdb, timestamp_seconds, note, "argon2", vers});
            j["users"][user].push_back(arr);
            write_db(db_path, j);
            cout << "entry successfully added. id : "<<id << endl;
            sodium_memzero(&id[0], id.size());
        }catch(const exception& e){
            cerr<<"ADD CMD: "<<e.what()<<endl;
            if(!psw1.empty()) sodium_memzero(&psw1[0], psw1.size());
            if(!psw2.empty()) sodium_memzero(&psw2[0], psw2.size());
            if(!hash.empty()) sodium_memzero(&hash[0], hash.size());
            return 2;
        }
    } else if(cmd=="-delete"){
        int need = 3;//2 arg + 1
        if((string)argv[argc-1]=="-test-no-root"){
            need+=1;
        }
        if(argc<need){
            cerr<<"not enough arguments"<<endl;
            return 2;
        }
        string to_del;
        to_del = argv[2];
        try{
            json j = read_db(db_path);
            if (!j.contains("users") || !j["users"].is_object()) {
                cerr << "database is empty or invalid." << endl;
                return 2;
            }
            string file_p;
            bool found = false;
            for (auto& [username, user_data] : j["users"].items()) {
                for(auto entry = user_data.begin(); entry != user_data.end(); entry++){
                    if(entry[0][1]==to_del){
                        file_p = entry[0][2];
                        user_data.erase(entry);
                        found = true;
                    }
                }
            }
            if(!found){
                cerr<<"ERROR DIDN'T FIND ID: "<<to_del<<endl;
                return 2;
            }
            write_db(db_path, j);
            if (!file_p.empty()) {
                if (remove(file_p.c_str()) != 0) {
                    cerr << "WARNING: Could not delete physical hash file: " << file_p << endl;
                }
            } else {
                cerr<< "WARNING: HASH FILE PATH NOT FOUND"<<endl;
            }
            cout<<"entry id: "<<to_del<<" was successfully deleted"<<endl;
        }catch(const exception& e){
            cerr<<"DEL CMD ERROR: "<<e.what()<<endl;
        }
    } else if(cmd =="-list"){
        try{
            json j = read_db(db_path);
            for (auto& [username, user_data] : j["users"].items()) {
                for(auto entry = user_data.begin(); entry != user_data.end(); entry++){
                    cout<<"username: "<<entry[0][0]<<" id: "<<entry[0][1]<<" max times: "<<entry[0][3]<<" timestamp: "<<entry[0][4]<<" note: "<<entry[0][5]
                    <<" hash algorithm: "<<entry[0][6]<<endl;
                }
            }
        }catch(const exception& e){
            cerr<<"LIST CMD ERROR: "<<e.what()<<endl;
        }
    }
    return 0;
}

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

string hash_password(const string& password) {
    if (sodium_init() < 0) {
        throw runtime_error("ERROR HASH: sodium_init failed");
    }
    unsigned char salt[16];
    randombytes_buf(salt, sizeof(salt));
    char encoded[128];
    argon2id_hash_encoded(2, 1 << 16, 1, password.c_str(), password.length(), salt, 16, 32, encoded, sizeof(encoded));
    return string(encoded);
}

bool verify_password(const string& hash, const string& password) {
    if (sodium_init() < 0) {
        throw runtime_error("ERROR VERIFY: sodium_init failed");
    }
    return argon2id_verify(hash.c_str(), password.c_str(), password.length()) == ARGON2_OK;
}

string get_password(const string& prompt) {
    cout << prompt;

    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);

    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    string password;
    getline(cin, password);

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;

    return password;
}

void create_secure_root_file(const string& filepath) {
    ofstream file(filepath);
    if (!file.is_open()) {
        throw runtime_error("ERROR CAN'T MAKE FILE: " + filepath);
    }
    file.close();
    if (chmod(filepath.c_str(), S_IRUSR | S_IWUSR) != 0) {
        throw runtime_error("ERROR chmod for: " + filepath);
    }
    if (chown(filepath.c_str(), 0, 0) != 0) {
        throw runtime_error("ERROR chown (root:root) for: " + filepath);
    }
}

void run_help(){
    cout<<"-help : show all commands"<<endl;
    cout<<"-add username max_uses : makes an entry. you will be prompted to enter your password 2 times. set max_uses to -1 for permanent passwords. returns id"<<endl;
    cout<<"OPTIONAL: -note text : note of what the entry is for"<<endl;
    cout<<"-delete id : deletes an entry"<<endl;
    //cout<<"-modify id : modifies a entry"<<endl;
    //cout<<"what ca you modify : -modify id -password X -username Y -max_uses Z -note T"<<endl;
    cout<<"-list : list of all entries"<<endl;
}