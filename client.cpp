
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <algorithm>

static const char *GROUP14_P =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF";

static std::string hex_of(const unsigned char *p, size_t n)
{
    std::ostringstream o;
    for (size_t i = 0; i < n; i++)
        o << std::hex << std::setw(2) << std::setfill('0') << (int)p[i];
    return o.str();
}
static std::vector<unsigned char> unhex(const std::string &s)
{
    std::vector<unsigned char> out;
    if (s.size() % 2)
        return {};
    for (size_t i = 0; i < s.size(); i += 2)
        out.push_back((unsigned char)std::stoul(s.substr(i, 2), nullptr, 16));
    return out;
}
static std::string b64(const unsigned char *p, int n)
{
    std::string out(4 * ((n + 2) / 3), '\0');
    int m = EVP_EncodeBlock((unsigned char *)out.data(), p, n);
    out.resize(m);
    return out;
}
static std::vector<unsigned char> unb64(const std::string &s)
{
    std::vector<unsigned char> out((s.size() * 3) / 4 + 4);
    int n = EVP_DecodeBlock(out.data(), (const unsigned char *)s.data(), (int)s.size());
    if (n < 0)
        return {};
    int pad = 0;
    if (!s.empty() && s.back() == '=')
        pad++;
    if (s.size() > 1 && s[s.size() - 2] == '=')
        pad++;
    out.resize(n - pad);
    return out;
}
static std::string recv_line(int fd, size_t maxlen = 1024 * 1024)
{
    std::string s;
    char c;
    while (s.size() < maxlen)
    {
        ssize_t n = recv(fd, &c, 1, 0);
        if (n <= 0)
            return {};
        if (c == '\n')
            return s;
        s.push_back(c);
    }
    return {};
}
static bool send_all(int fd, const std::string &s)
{
    size_t off = 0;
    while (off < s.size())
    {
        ssize_t n = send(fd, s.data() + off, s.size() - off, MSG_NOSIGNAL);
        if (n <= 0)
            return false;
        off += n;
    }
    return true;
}
static BIGNUM *bn_from_hex(const char *s)
{
    BIGNUM *x = nullptr;
    BN_hex2bn(&x, s);
    return x;
}

static bool dh_make(BIGNUM *p, BIGNUM *g, BIGNUM **priv, BIGNUM **pub)
{
    *priv = BN_new();
    *pub = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if (!*priv || !*pub || !ctx)
        return false;
    if (!BN_priv_rand(*priv, BN_num_bits(p) - 1, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY))
        return false;
    if (!BN_mod_exp(*pub, g, *priv, p, ctx))
        return false;
    BN_CTX_free(ctx);
    return true;
}
static BIGNUM *dh_shared(const BIGNUM *peer, const BIGNUM *priv, const BIGNUM *p)
{
    BIGNUM *s = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    if (!s || !ctx)
    {
        BN_free(s);
        BN_CTX_free(ctx);
        return nullptr;
    }
    if (!BN_mod_exp(s, peer, priv, p, ctx))
    {
        BN_free(s);
        s = nullptr;
    }
    BN_CTX_free(ctx);
    return s;
}
static std::vector<unsigned char> derive_key(const BIGNUM *secret)
{
    int n = BN_num_bytes(secret);
    std::vector<unsigned char> raw(n);
    BN_bn2bin(secret, raw.data());
    unsigned char h[SHA256_DIGEST_LENGTH];
    SHA256(raw.data(), raw.size(), h);
    return std::vector<unsigned char>(h, h + 32);
}
static std::string fingerprint(const std::vector<unsigned char> &key)
{
    unsigned char h[SHA256_DIGEST_LENGTH];
    SHA256(key.data(), key.size(), h);
    return hex_of(h, 32);
}
static std::string gcm_encrypt(const std::vector<unsigned char> &key, const std::string &plain)
{
    unsigned char nonce[12];
    if (RAND_bytes(nonce, 12) != 1)
        return {};
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c)
        return {};
    std::vector<unsigned char> ct(plain.size() + 16);
    int l1 = 0, l2 = 0;
    bool ok = EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1;
    ok = ok && EVP_EncryptInit_ex(c, nullptr, nullptr, key.data(), nonce) == 1;
    ok = ok && EVP_EncryptUpdate(c, ct.data(), &l1, (const unsigned char *)plain.data(), (int)plain.size()) == 1;
    ok = ok && EVP_EncryptFinal_ex(c, ct.data() + l1, &l2) == 1;
    unsigned char tag[16];
    ok = ok && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
    EVP_CIPHER_CTX_free(c);
    if (!ok)
        return {};
    std::vector<unsigned char> wire(nonce, nonce + 12);
    wire.insert(wire.end(), ct.begin(), ct.begin() + l1 + l2);
    wire.insert(wire.end(), tag, tag + 16);
    return "ENC|" + b64(wire.data(), (int)wire.size());
}
static bool gcm_decrypt(const std::vector<unsigned char> &key, const std::string &msg, std::string &plain)
{
    if (msg.rfind("ENC|", 0) != 0)
        return false;
    auto w = unb64(msg.substr(4));
    if (w.size() < 28)
        return false;
    const unsigned char *nonce = w.data(), *tag = w.data() + w.size() - 16, *ct = w.data() + 12;
    int ctlen = (int)w.size() - 28, l1 = 0, l2 = 0;
    std::vector<unsigned char> pt(ctlen + 1);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c)
        return false;
    bool ok = EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1;
    ok = ok && EVP_DecryptInit_ex(c, nullptr, nullptr, key.data(), nonce) == 1;
    ok = ok && EVP_DecryptUpdate(c, pt.data(), &l1, ct, ctlen) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) == 1;
    ok = ok && EVP_DecryptFinal_ex(c, pt.data() + l1, &l2) == 1;
    EVP_CIPHER_CTX_free(c);
    if (!ok)
        return false;
    plain.assign((char *)pt.data(), l1 + l2);
    return true;
}
static void free_bn(BIGNUM *&x)
{
    BN_free(x);
    x = nullptr;
}

static int connect_to(const std::string &ip, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &a.sin_addr) != 1 || connect(fd, (sockaddr *)&a, sizeof(a)) < 0)
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
        std::cerr << "Usage: " << argv[0] << " <server-ip> <username> [port]\n";
        return 1;
    }
    std::string host = argv[1], user = argv[2];
    int port = argc == 4 ? std::stoi(argv[3]) : 5000;
    int fd = connect_to(host, port);
    if (fd < 0)
    {
        perror("connect");
        return 1;
    }
    BIGNUM *p = bn_from_hex(GROUP14_P), *g = BN_new(), *priv = nullptr, *pub = nullptr, *peer = nullptr, *secret = nullptr;
    BN_set_word(g, 2);
    dh_make(p, g, &priv, &pub);
    std::string pub_hex = BN_bn2hex(pub);

    if (!send_all(fd, std::string("DH_P|") + GROUP14_P + "\n") ||
        !send_all(fd, "DH_G|2\n") ||
        !send_all(fd, std::string("DH_PUB|") + pub_hex + "\n"))
    {
        close(fd);
        return 1;
    }
    std::string line = recv_line(fd);
    if (line.rfind("DH_PUB|", 0) != 0)
    {
        std::cerr << "DH handshake failed\n";
        return 1;
    }
    peer = bn_from_hex(line.substr(7).c_str());
    if (BN_cmp(peer, BN_value_one()) <= 0 || BN_cmp(peer, p) >= 0)
    {
        std::cerr << "Invalid DH public value\n";
        return 1;
    }
    secret = dh_shared(peer, priv, p);
    auto key = derive_key(secret);
    std::cout << "[DH] shared-secret fingerprint: " << fingerprint(key) << "\n";
    if (!send_all(fd, "DH_OK\n"))
        return 1;
    std::string enc = gcm_encrypt(key, "LOGIN|" + user);
    if (enc.empty() || !send_all(fd, enc + "\n"))
        return 1;
    std::string selected;
    std::atomic<bool> alive{true};
    std::mutex out;
    std::thread rx([&]()
                   {
        while(alive){
            std::string w=recv_line(fd); if(w.empty()){alive=false;break;}
            std::string plain;
            if(!gcm_decrypt(key,w,plain)){std::lock_guard<std::mutex>lk(out);std::cerr<<"[SECURITY] Authentication/decryption failure; message discarded.\n";continue;}
            if(plain.rfind("FROM|",0)==0){
                size_t a=plain.find('|',5); if(a!=std::string::npos){
                    std::string from=plain.substr(5,a-5), text=plain.substr(a+1);
                    std::lock_guard<std::mutex>lk(out); std::cout<<"["<<from<<"] "<<text<<"\n";
                }
            } else if(plain.rfind("USERS|",0)==0){
                std::lock_guard<std::mutex>lk(out); std::cout<<"[online] "<<plain.substr(6)<<"\n";
            } else { std::lock_guard<std::mutex>lk(out); std::cout<<"[server] "<<plain<<"\n"; if(plain=="BYE") alive=false; }
        } });
    std::cout << "[Connected as " << user << "]\nCommands: @username message | /chat username | /who | /quit\n";
    std::string input;
    while (alive && std::getline(std::cin, input))
    {
        if (input == "/quit")
        {
            auto e = gcm_encrypt(key, "QUIT");
            send_all(fd, e + "\n");
            break;
        }
        if (input == "/who")
        {
            auto e = gcm_encrypt(key, "WHO");
            send_all(fd, e + "\n");
            continue;
        }
        if (input.rfind("/chat ", 0) == 0)
        {
            selected = input.substr(6);
            std::cout << "[chat] selected " << selected << "\n";
            continue;
        }
        std::string to, text;
        if (input.rfind("@", 0) == 0)
        {
            size_t sp = input.find(' ');
            if (sp == std::string::npos)
            {
                std::cout << "Usage: @username message\n";
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
                std::cout << "Select a user with /chat username or @username message\n";
                continue;
            }
            to = selected;
            text = input;
        }
        if (to.empty() || text.empty())
            continue;
        auto e = gcm_encrypt(key, "MSG|" + to + "|" + text);
        if (e.empty() || !send_all(fd, e + "\n"))
            break;
    }
    alive = false;
    shutdown(fd, SHUT_RDWR);
    close(fd);
    if (rx.joinable())
        rx.join();
    free_bn(p);
    free_bn(g);
    free_bn(priv);
    free_bn(pub);
    free_bn(peer);
    free_bn(secret);
    return 0;
}
