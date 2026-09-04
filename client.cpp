#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <atomic>
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

static bool send_line(int fd, const string &s)
{
    return send_all(fd, s + "\n");
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

static bool expect_prefix(const string &line, const string &prefix, string &value)
{
    if (line.rfind(prefix, 0) != 0)
    {
        return false;
    }
    value = line.substr(prefix.size());
    return true;
}

static int connect_to(const string &ip, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        return -1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1 || connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv)
{
    if (argc < 3 || argc > 4)
    {
        cerr << "Usage: " << argv[0] << " <server-ip> <username> [port]\n";
        return 1;
    }

    string host = argv[1];
    string user = argv[2];
    int port = argc == 4 ? stoi(argv[3]) : 5000;

    int fd = connect_to(host, port);
    if (fd < 0)
    {
        perror("connect");
        return 1;
    }

    BIGNUM *p = nullptr;
    BIGNUM *g = nullptr;
    BIGNUM *priv = nullptr;
    BIGNUM *pub = nullptr;
    BIGNUM *peer = nullptr;
    BIGNUM *secret = nullptr;

    string p_hex;
    string g_hex;
    string peer_hex;
    if (!expect_prefix(recv_line(fd), "DH_P|", p_hex) ||
        !expect_prefix(recv_line(fd), "DH_G|", g_hex) ||
        !expect_prefix(recv_line(fd), "DH_PUB|", peer_hex))
    {
        cerr << "DH handshake failed\n";
        close(fd);
        return 1;
    }

    if (p_hex != GROUP14_P || g_hex != "2")
    {
        cerr << "Unexpected DH parameters from server\n";
        close(fd);
        return 1;
    }

    p = bn_from_hex(p_hex.c_str());
    g = BN_new();
    peer = bn_from_hex(peer_hex.c_str());
    if (!p || !g || !peer || BN_set_word(g, 2) != 1)
    {
        cerr << "Failed to initialize DH state\n";
        close(fd);
        free_bn(p);
        free_bn(g);
        free_bn(peer);
        return 1;
    }

    if (BN_cmp(peer, BN_value_one()) <= 0 || BN_cmp(peer, p) >= 0)
    {
        cerr << "Invalid DH public value\n";
        close(fd);
        free_bn(p);
        free_bn(g);
        free_bn(peer);
        return 1;
    }

    if (!dh_make(p, g, &priv, &pub))
    {
        cerr << "Failed to create DH key pair\n";
        close(fd);
        free_bn(p);
        free_bn(g);
        free_bn(peer);
        return 1;
    }

    if (!send_line(fd, "DH_PUB|" + bn_to_hex(pub)))
    {
        close(fd);
        return 1;
    }

    secret = dh_shared(peer, priv, p);
    if (!secret)
    {
        cerr << "Failed to derive shared secret\n";
        close(fd);
        return 1;
    }

    auto key = derive_key(secret);
    cout << "[DH] shared-secret fingerprint: " << fingerprint(key) << "\n";
    if (!send_line(fd, "DH_OK"))
    {
        close(fd);
        return 1;
    }

    string login = gcm_encrypt(key, "LOGIN|" + user);
    if (login.empty() || !send_line(fd, login))
    {
        close(fd);
        return 1;
    }

    string selected;
    atomic<bool> alive{true};
    mutex out_mutex;

    thread rx([&]()
                   {
        while (alive)
        {
            string wire = recv_line(fd);
            if (wire.empty())
            {
                alive = false;
                break;
            }

            string plain;
            if (!gcm_decrypt(key, wire, plain))
            {
                lock_guard<mutex> lock(out_mutex);
                cerr << "[SECURITY] Authentication/decryption failure; message discarded.\n";
                continue;
            }

            if (plain.rfind("FROM|", 0) == 0)
            {
                size_t sep = plain.find('|', 5);
                if (sep != string::npos)
                {
                    lock_guard<mutex> lock(out_mutex);
                    cout << "[" << plain.substr(5, sep - 5) << "] " << plain.substr(sep + 1) << "\n";
                }
            }
            else if (plain.rfind("USERS|", 0) == 0)
            {
                lock_guard<mutex> lock(out_mutex);
                cout << "[online] " << plain.substr(6) << "\n";
            }
            else
            {
                lock_guard<mutex> lock(out_mutex);
                cout << "[server] " << plain << "\n";
                if (plain == "BYE")
                {
                    alive = false;
                }
            }
        } });

    cout << "[Connected as " << user << "]\n";
    cout << "Commands: @username message | /chat username | /who | /quit\n";

    string input;
    while (alive && getline(cin, input))
    {
        if (input == "/quit")
        {
            auto msg = gcm_encrypt(key, "QUIT");
            if (!msg.empty())
            {
                send_line(fd, msg);
            }
            break;
        }

        if (input == "/who")
        {
            auto msg = gcm_encrypt(key, "WHO");
            if (msg.empty() || !send_line(fd, msg))
            {
                break;
            }
            continue;
        }

        if (input.rfind("/chat ", 0) == 0)
        {
            selected = input.substr(6);
            cout << "[chat] selected " << selected << "\n";
            continue;
        }

        string to;
        string text;
        if (input.rfind("@", 0) == 0)
        {
            size_t sp = input.find(' ');
            if (sp == string::npos)
            {
                cout << "Usage: @username message\n";
                continue;
            }
            to = input.substr(1, sp - 1);
            text = input.substr(sp + 1);
            selected = to;
        }
        else
        {
            if (selected.empty())
            {
                cout << "Select a user with /chat username or @username message\n";
                continue;
            }
            to = selected;
            text = input;
        }

        if (to.empty() || text.empty())
        {
            continue;
        }

        auto msg = gcm_encrypt(key, "MSG|" + to + "|" + text);
        if (msg.empty() || !send_line(fd, msg))
        {
            break;
        }
    }

    alive = false;
    shutdown(fd, SHUT_RDWR);
    close(fd);
    if (rx.joinable())
    {
        rx.join();
    }

    free_bn(p);
    free_bn(g);
    free_bn(priv);
    free_bn(pub);
    free_bn(peer);
    free_bn(secret);
    return 0;
}
