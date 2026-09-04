#include "crypto.h"
#include "dh_group.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

constexpr int PORT = 5000;
constexpr int MAX_CLIENTS = 2;

struct Client {
    int socket = -1;
    int slot = -1;
    std::string username;
    std::vector<unsigned char> aes_key;
    bool authenticated = false;
};

Client* clients[MAX_CLIENTS] = {nullptr, nullptr};
std::mutex clients_mutex;

bool send_all(int fd, const std::string& data)
{
    size_t sent = 0;

    while (sent < data.size())
    {
        ssize_t n = send(fd, data.data() + sent,
                         data.size() - sent, 0);

        if (n <= 0)
            return false;

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

        if (n <= 0)
            return false;

        if (c == '\n')
            return true;

        if (c != '\r')
            line.push_back(c);

        if (line.size() > 1024 * 1024)
            return false;
    }
}

bool send_encrypted(Client* client, const std::string& plaintext)
{
    std::vector<unsigned char> ciphertext;

    if (!aes_gcm_encrypt(client->aes_key, plaintext, ciphertext))
        return false;

    return send_line(
        client->socket,
        "ENC|" + base64_encode(ciphertext)
    );
}

bool receive_encrypted(Client* client, std::string& plaintext)
{
    std::string line;

    if (!receive_line(client->socket, line))
        return false;

    if (line.rfind("ENC|", 0) != 0)
        return false;

    std::vector<unsigned char> ciphertext;

    if (!base64_decode(line.substr(4), ciphertext))
        return false;

    return aes_gcm_decrypt(
        client->aes_key,
        ciphertext,
        plaintext
    );
}

Client* find_user(const std::string& username)
{
    std::lock_guard<std::mutex> lock(clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; ++i)
    {
        if (clients[i] &&
            clients[i]->authenticated &&
            clients[i]->username == username)
        {
            return clients[i];
        }
    }

    return nullptr;
}

void remove_client(Client* client)
{
    std::lock_guard<std::mutex> lock(clients_mutex);

    if (client->slot >= 0 &&
        client->slot < MAX_CLIENTS &&
        clients[client->slot] == client)
    {
        clients[client->slot] = nullptr;
    }
}

void send_who(Client* requester)
{
    std::string message = "USERS";

    std::lock_guard<std::mutex> lock(clients_mutex);

    for (int i = 0; i < MAX_CLIENTS; ++i)
    {
        if (clients[i] && clients[i]->authenticated)
            message += "|" + clients[i]->username;
    }

    send_encrypted(requester, message);
}

bool perform_dh_handshake(Client* client)
{
    BIGNUM* p = hex_to_bn(DH_GROUP14_P);
    BIGNUM* g = hex_to_bn(DH_GROUP14_G);

    BIGNUM* private_key = nullptr;
    BIGNUM* public_key = nullptr;
    BIGNUM* client_public = nullptr;
    BIGNUM* shared_secret = nullptr;

    if (!p || !g)
        goto fail;

    private_key = generate_private_key(p);
    if (!private_key)
        goto fail;

    public_key = compute_public_key(g, private_key, p);
    if (!public_key)
        goto fail;

    if (!send_line(client->socket, "DH_P|" + bn_to_hex(p)))
        goto fail;

    if (!send_line(client->socket, "DH_G|" + bn_to_hex(g)))
        goto fail;

    if (!send_line(client->socket, "DH_PUB|" + bn_to_hex(public_key)))
        goto fail;

    {
        std::string line;

        if (!receive_line(client->socket, line))
            goto fail;

        const std::string prefix = "DH_CLIENT_PUB|";

        if (line.rfind(prefix, 0) != 0)
            goto fail;

        client_public = hex_to_bn(line.substr(prefix.size()));

        if (!client_public)
            goto fail;
    }

    /*
     * Basic public-value validation.
     * Reject values outside the valid group interval.
     */
    if (BN_is_zero(client_public) ||
        BN_is_one(client_public) ||
        BN_cmp(client_public, p) >= 0)
        goto fail;

    shared_secret =
        compute_shared_secret(client_public, private_key, p);

    if (!shared_secret || BN_is_zero(shared_secret))
        goto fail;

    client->aes_key = derive_aes_key(shared_secret);

    if (client->aes_key.size() != 32)
        goto fail;

    std::cout
        << "[Server] Client " << client->slot
        << " DH fingerprint: "
        << fingerprint(shared_secret)
        << "\n";

    if (!send_line(client->socket, "DH_OK"))
        goto fail;

    BN_free(p);
    BN_free(g);
    BN_free(private_key);
    BN_free(public_key);
    BN_free(client_public);
    BN_free(shared_secret);

    return true;

fail:
    BN_free(p);
    BN_free(g);
    BN_free(private_key);
    BN_free(public_key);
    BN_free(client_public);
    BN_free(shared_secret);
    return false;
}

void handle_client(Client* client)
{
    std::cout << "[Server] Client "
              << client->slot
              << " connected.\n";

    if (!perform_dh_handshake(client))
    {
        std::cout << "[Server] DH handshake failed.\n";
        close(client->socket);
        remove_client(client);
        delete client;
        return;
    }

    std::string message;

    /*
     * Login is encrypted too, as required by Phase 2.
     */
    if (!receive_encrypted(client, message) ||
        message.rfind("LOGIN|", 0) != 0)
    {
        close(client->socket);
        remove_client(client);
        delete client;
        return;
    }

    std::string username = message.substr(6);

    if (username.empty() || username.size() > 64)
    {
        send_encrypted(client, "ERROR|Invalid username");
        close(client->socket);
        remove_client(client);
        delete client;
        return;
    }

    {
        std::lock_guard<std::mutex> lock(clients_mutex);

        for (int i = 0; i < MAX_CLIENTS; ++i)
        {
            if (clients[i] &&
                clients[i] != client &&
                clients[i]->authenticated &&
                clients[i]->username == username)
            {
                send_encrypted(
                    client,
                    "ERROR|Username already exists"
                );

                close(client->socket);
                clients[client->slot] = nullptr;
                delete client;
                return;
            }
        }

        client->username = username;
        client->authenticated = true;
    }

    std::cout << "[Server] User "
              << client->username
              << " logged in.\n";

    send_encrypted(client, "OK|Connected");

    while (true)
    {
        if (!receive_encrypted(client, message))
        {
            std::cout << "[Server] "
                      << client->username
                      << " connection lost or GCM authentication failed.\n";
            break;
        }

        if (message == "WHO")
        {
            send_who(client);
            continue;
        }

        if (message == "QUIT")
        {
            send_encrypted(client, "BYE");
            break;
        }

        /*
         * Application message:
         * MSG|recipient|text
         */
        if (message.rfind("MSG|", 0) == 0)
        {
            std::string rest = message.substr(4);
            size_t separator = rest.find('|');

            if (separator == std::string::npos)
            {
                send_encrypted(client, "ERROR|Invalid message");
                continue;
            }

            std::string recipient = rest.substr(0, separator);
            std::string text = rest.substr(separator + 1);

            std::cout << "[Server] RELAY "
                      << client->username
                      << " -> "
                      << recipient
                      << ": "
                      << text
                      << "\n";

            Client* destination = find_user(recipient);

            if (!destination)
            {
                send_encrypted(
                    client,
                    "ERROR|User not online"
                );
                continue;
            }

            if (!send_encrypted(
                    destination,
                    "FROM|" + client->username + "|" + text))
            {
                std::cout << "[Server] Failed to forward message.\n";
            }

            continue;
        }

        send_encrypted(client, "ERROR|Unknown command");
    }

    remove_client(client);
    close(client->socket);
    delete client;
}

int main()
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 0)
    {
        perror("socket");
        return 1;
    }

    int opt = 1;

    setsockopt(
        server_fd,
        SOL_SOCKET,
        SO_REUSEADDR,
        &opt,
        sizeof(opt)
    );

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(
            server_fd,
            reinterpret_cast<sockaddr*>(&address),
            sizeof(address)) < 0)
    {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, MAX_CLIENTS) < 0)
    {
        perror("listen");
        close(server_fd);
        return 1;
    }

    std::cout << "====================================\n";
    std::cout << "       Phase 2 Secure Server\n";
    std::cout << "====================================\n";
    std::cout << "[Server] Listening on port "
              << PORT << "\n";

    while (true)
    {
        sockaddr_in client_address{};
        socklen_t client_len = sizeof(client_address);

        int client_fd = accept(
            server_fd,
            reinterpret_cast<sockaddr*>(&client_address),
            &client_len
        );

        if (client_fd < 0)
        {
            perror("accept");
            continue;
        }

        Client* client = new Client;
        client->socket = client_fd;

        bool placed = false;

        {
            std::lock_guard<std::mutex> lock(clients_mutex);

            for (int i = 0; i < MAX_CLIENTS; ++i)
            {
                if (!clients[i])
                {
                    client->slot = i;
                    clients[i] = client;
                    placed = true;
                    break;
                }
            }
        }

        if (!placed)
        {
            std::cout << "[Server] Server full.\n";
            close(client_fd);
            delete client;
            continue;
        }

        std::thread(handle_client, client).detach();
    }

    close(server_fd);
    return 0;
}
