#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
using namespace std;
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

static const char *GROUP14_P =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF";

static string hex_of(const unsigned char *p, size_t n)
{
    ostringstream out;
    for (size_t i = 0; i < n; ++i)
    {
        out << hex << setw(2) << setfill('0') << static_cast<int>(p[i]);
    }
    return out.str();
}

static string b64(const unsigned char *p, int n)
{
    string out(4 * ((n + 2) / 3), '\0');
    int written = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()), p, n);
    out.resize(written);
    return out;
}

static vector<unsigned char> unb64(const string &s)
{
    vector<unsigned char> out((s.size() * 3) / 4 + 4);
    int n = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char *>(s.data()), static_cast<int>(s.size()));
    if (n < 0)
    {
        return {};
    }
    int pad = 0;
    if (!s.empty() && s.back() == '=')
    {
        ++pad;
    }
    if (s.size() > 1 && s[s.size() - 2] == '=')
    {
        ++pad;
    }
    out.resize(n - pad);
    return out;
}

static string recv_line(int fd, size_t maxlen = 1024 * 1024)
{
    string s;
    char c = '\0';
    while (s.size() < maxlen)
    {
        ssize_t n = recv(fd, &c, 1, 0);
        if (n <= 0)
        {
            return {};
        }
        if (c == '\n')
        {
            return s;
        }
        s.push_back(c);
    }
    return {};
}

static bool send_all(int fd, const string &s)
{
    size_t off = 0;
    while (off < s.size())
    {
        ssize_t n = send(fd, s.data() + off, s.size() - off, MSG_NOSIGNAL);
        if (n <= 0)
        {
            return false;
        }
        off += static_cast<size_t>(n);
    }
    return true;
}

static BIGNUM *bn_from_hex(const char *s)
{
    BIGNUM *x = nullptr;
    BN_hex2bn(&x, s);
    return x;
}

static string bn_to_hex(const BIGNUM *value)
{
    char *tmp = BN_bn2hex(value);
    string out = tmp ? tmp : "";
    OPENSSL_free(tmp);
    return out;
}

static bool dh_make(BIGNUM *p, BIGNUM *g, BIGNUM **priv, BIGNUM **pub)
{
    *priv = BN_new();
    *pub = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if (!*priv || !*pub || !ctx)
    {
        BN_CTX_free(ctx);
        return false;
    }
    bool ok = BN_priv_rand(*priv, BN_num_bits(p) - 1, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY) == 1;
    ok = ok && BN_mod_exp(*pub, g, *priv, p, ctx) == 1;
    BN_CTX_free(ctx);
    return ok;
}

static BIGNUM *dh_shared(const BIGNUM *peer, const BIGNUM *priv, const BIGNUM *p)
{
    BIGNUM *secret = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if (!secret || !ctx)
    {
        BN_free(secret);
        BN_CTX_free(ctx);
        return nullptr;
    }
    if (BN_mod_exp(secret, peer, priv, p, ctx) != 1)
    {
        BN_free(secret);
        secret = nullptr;
    }
    BN_CTX_free(ctx);
    return secret;
}

static vector<unsigned char> derive_key(const BIGNUM *secret)
{
    int n = BN_num_bytes(secret);
    vector<unsigned char> raw(n);
    BN_bn2bin(secret, raw.data());
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(raw.data(), raw.size(), hash);
    return vector<unsigned char>(hash, hash + SHA256_DIGEST_LENGTH);
}

static string fingerprint(const vector<unsigned char> &key)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(key.data(), key.size(), hash);
    return hex_of(hash, SHA256_DIGEST_LENGTH);
}

static string gcm_encrypt(const vector<unsigned char> &key, const string &plain)
{
    unsigned char nonce[12];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
    {
        return {};
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return {};
    }

    vector<unsigned char> ciphertext(plain.size() + 16);
    int part1 = 0;
    int part2 = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), nullptr) == 1;
    ok = ok && EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) == 1;
    ok = ok && EVP_EncryptUpdate(ctx, ciphertext.data(), &part1,
                                 reinterpret_cast<const unsigned char *>(plain.data()),
                                 static_cast<int>(plain.size())) == 1;
    ok = ok && EVP_EncryptFinal_ex(ctx, ciphertext.data() + part1, &part2) == 1;

    unsigned char tag[16];
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok)
    {
        return {};
    }

    vector<unsigned char> wire(nonce, nonce + sizeof(nonce));
    wire.insert(wire.end(), ciphertext.begin(), ciphertext.begin() + part1 + part2);
    wire.insert(wire.end(), tag, tag + sizeof(tag));
    return "ENC|" + b64(wire.data(), static_cast<int>(wire.size()));
}

static bool gcm_decrypt(const vector<unsigned char> &key, const string &msg, string &plain)
{
    if (msg.rfind("ENC|", 0) != 0)
    {
        return false;
    }

    auto wire = unb64(msg.substr(4));
    if (wire.size() < 28)
    {
        return false;
    }

    const unsigned char *nonce = wire.data();
    const unsigned char *ciphertext = wire.data() + 12;
    const unsigned char *tag = wire.data() + wire.size() - 16;
    int ciphertext_len = static_cast<int>(wire.size()) - 28;

    vector<unsigned char> out(ciphertext_len + 1);
    int part1 = 0;
    int part2 = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return false;
    }

    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1;
    ok = ok && EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) == 1;
    ok = ok && EVP_DecryptUpdate(ctx, out.data(), &part1, ciphertext, ciphertext_len) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<unsigned char *>(tag)) == 1;
    ok = ok && EVP_DecryptFinal_ex(ctx, out.data() + part1, &part2) == 1;
    EVP_CIPHER_CTX_free(ctx);

    if (!ok)
    {
        return false;
    }

    plain.assign(reinterpret_cast<char *>(out.data()), part1 + part2);
    return true;
}

static void free_bn(BIGNUM *&x)
{
    BN_free(x);
    x = nullptr;
}

struct Client
{
    int fd;
    string user;
    vector<unsigned char> key;
    mutex send_mutex;
    bool active = true;
};

static vector<Client *> clients;
static mutex clients_mutex;

static bool safe_send(Client *client, const string &line)
{
    lock_guard<mutex> lock(client->send_mutex);
    return send_all(client->fd, line + "\n");
}

static void remove_client(Client *client)
{
    lock_guard<mutex> lock(clients_mutex);
    client->active = false;
    clients.erase(remove(clients.begin(), clients.end(), client), clients.end());
}

static Client *find_user(const string &name)
{
    lock_guard<mutex> lock(clients_mutex);
    for (Client *client : clients)
    {
        if (client->active && client->user == name)
        {
            return client;
        }
    }
    return nullptr;
}

static bool username_taken(Client *self, const string &name)
{
    lock_guard<mutex> lock(clients_mutex);
    for (Client *client : clients)
    {
        if (client != self && client->active && client->user == name)
        {
            return true;
        }
    }
    return false;
}

static string users_list()
{
    lock_guard<mutex> lock(clients_mutex);
    string out;
    for (Client *client : clients)
    {
        if (!client->active || client->user.empty())
        {
            continue;
        }
        if (!out.empty())
        {
            out += ",";
        }
        out += client->user;
    }
    return out;
}

static void handle(Client *client)
{
    BIGNUM *p = bn_from_hex(GROUP14_P);
    BIGNUM *g = BN_new();
    BIGNUM *priv = nullptr;
    BIGNUM *pub = nullptr;
    BIGNUM *peer = nullptr;
    BIGNUM *secret = nullptr;

    if (!p || !g || BN_set_word(g, 2) != 1 || !dh_make(p, g, &priv, &pub))
    {
        goto cleanup;
    }

    if (!safe_send(client, "DH_P|" + string(GROUP14_P)) ||
        !safe_send(client, "DH_G|2") ||
        !safe_send(client, "DH_PUB|" + bn_to_hex(pub)))
    {
        goto cleanup;
    }

    {
        string wire = recv_line(client->fd);
        if (wire.rfind("DH_PUB|", 0) != 0)
        {
            goto cleanup;
        }
        peer = bn_from_hex(wire.substr(7).c_str());
    }

    if (!peer || BN_cmp(peer, BN_value_one()) <= 0 || BN_cmp(peer, p) >= 0)
    {
        goto cleanup;
    }

    secret = dh_shared(peer, priv, p);
    if (!secret)
    {
        goto cleanup;
    }

    client->key = derive_key(secret);

    {
        string wire = recv_line(client->fd);
        if (wire != "DH_OK")
        {
            goto cleanup;
        }
    }

    {
        string wire = recv_line(client->fd);
        string plain;
        if (!gcm_decrypt(client->key, wire, plain) || plain.rfind("LOGIN|", 0) != 0)
        {
            goto cleanup;
        }

        string requested_name = plain.substr(6);
        if (requested_name.empty() || username_taken(client, requested_name))
        {
            safe_send(client, gcm_encrypt(client->key, "ERROR|username unavailable"));
            goto cleanup;
        }
        client->user = requested_name;
    }

    cout << "[DH] " << client->user << " shared-secret fingerprint: " << fingerprint(client->key) << "\n";
    cout << "[LOGIN] " << client->user << "\n";

    if (!safe_send(client, gcm_encrypt(client->key, "OK|LOGIN")))
    {
        goto cleanup;
    }

    while (client->active)
    {
        string wire = recv_line(client->fd);
        if (wire.empty())
        {
            break;
        }

        string plain;
        if (!gcm_decrypt(client->key, wire, plain))
        {
            cerr << "[SECURITY] " << client->user << " sent invalid or tampered ciphertext; discarded\n";
            continue;
        }

        if (plain == "WHO")
        {
            safe_send(client, gcm_encrypt(client->key, "USERS|" + users_list()));
            continue;
        }

        if (plain == "QUIT")
        {
            safe_send(client, gcm_encrypt(client->key, "BYE"));
            break;
        }

        if (plain.rfind("MSG|", 0) == 0)
        {
            size_t sep = plain.find('|', 4);
            if (sep == string::npos)
            {
                continue;
            }

            string recipient_name = plain.substr(4, sep - 4);
            string text = plain.substr(sep + 1);
            Client *recipient = find_user(recipient_name);
            if (!recipient)
            {
                safe_send(client, gcm_encrypt(client->key, "ERROR|user not online"));
                continue;
            }

            cout << "[RELAY " << client->user << " -> " << recipient_name << "] " << text << "\n";
            if (!safe_send(recipient, gcm_encrypt(recipient->key, "FROM|" + client->user + "|" + text)))
            {
                cerr << "[ERROR] failed to relay message to " << recipient_name << "\n";
            }
        }
    }

cleanup:
    if (!client->user.empty())
    {
        cout << "[DISCONNECT] " << client->user << "\n";
    }
    remove_client(client);
    shutdown(client->fd, SHUT_RDWR);
    close(client->fd);
    free_bn(p);
    free_bn(g);
    free_bn(priv);
    free_bn(pub);
    free_bn(peer);
    free_bn(secret);
    delete client;
}

int main(int argc, char **argv)
{
    int port = argc > 1 ? stoi(argv[1]) : 5000;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        perror("socket");
        return 1;
    }

    int one = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
    {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 2) < 0)
    {
        perror("listen");
        close(server_fd);
        return 1;
    }

    cout << "Server listening on port " << port << "\n";

    while (true)
    {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int fd = accept(server_fd, reinterpret_cast<sockaddr *>(&client_addr), &client_len);
        if (fd < 0)
        {
            continue;
        }

        {
            lock_guard<mutex> lock(clients_mutex);
            if (clients.size() >= 2)
            {
                send_all(fd, "SERVER_FULL\n");
                close(fd);
                continue;
            }
        }

        auto *client = new Client{fd};
        {
            lock_guard<mutex> lock(clients_mutex);
            clients.push_back(client);
        }
        thread(handle, client).detach();
    }
}
