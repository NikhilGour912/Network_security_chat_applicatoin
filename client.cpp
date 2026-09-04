#include "crypto.h"
#include "dh_group.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

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

    if (!aes_gcm_decrypt(key, ciphertext, plaintext))
    {
        std::cerr
            << "\n[Client] AES-GCM authentication/decryption failed.\n";
        return false;
    }

    return true;
}

void receiver_thread(
    int fd,
    std::vector<unsigned char> key)
{
    while (true)
    {
        std::string message;

        if (!receive_encrypted(fd, key, message))
        {
            std::cout << "\n[Client] Connection closed.\n";
            return;
        }

        if (message.rfind("FROM|", 0) == 0)
        {
            std::string rest = message.substr(5);
            size_t separator = rest.find('|');

            if (separator != std::string::npos)
            {
                std::string sender =
                    rest.substr(0, separator);

                std::string text =
                    rest.substr(separator + 1);

                std::cout << "\n[" << sender << "] "
                          << text << "\n> ";
                std::cout.flush();
            }

            continue;
        }

        if (message.rfind("USERS", 0) == 0)
        {
            std::cout << "\n[Online users]\n";

            std::string rest = message.substr(5);

            if (!rest.empty() && rest[0] == '|')
                rest.erase(0, 1);

            std::stringstream ss(rest);
            std::string user;

            while (std::getline(ss, user, '|'))
            {
                if (!user.empty())
                    std::cout << "  " << user << "\n";
            }

            std::cout << "> ";
            std::cout.flush();
            continue;
        }

        if (message == "OK|Connected")
        {
            std::cout << "[Client] Login successful.\n";
            continue;
        }

        if (message == "BYE")
        {
            std::cout << "\n[Client] Server closed the session.\n";
            return;
        }

        if (message.rfind("ERROR|", 0) == 0)
        {
            std::cout << "\n[Server Error] "
                      << message.substr(6)
                      << "\n> ";
            std::cout.flush();
            continue;
        }
    }
}

bool perform_dh_handshake(
    int fd,
    std::vector<unsigned char>& aes_key)
{
    std::string line;

    if (!receive_line(fd, line) ||
        line.rfind("DH_P|", 0) != 0)
        return false;

    BIGNUM* p = hex_to_bn(line.substr(5));

    if (!p)
        return false;

    if (!receive_line(fd, line) ||
        line.rfind("DH_G|", 0) != 0)
    {
        BN_free(p);
        return false;
    }

    BIGNUM* g = hex_to_bn(line.substr(5));

    if (!g)
    {
        BN_free(p);
        return false;
    }

    if (!receive_line(fd, line) ||
        line.rfind("DH_PUB|", 0) != 0)
    {
        BN_free(p);
        BN_free(g);
        return false;
    }

    BIGNUM* server_public =
        hex_to_bn(line.substr(7));

    if (!server_public)
    {
        BN_free(p);
        BN_free(g);
        return false;
    }

    /*
     * The client expects the standard published group.
     * This prevents a malicious peer from silently replacing
     * the configured DH group.
     */
    BIGNUM* expected_p = hex_to_bn(DH_GROUP14_P);
    BIGNUM* expected_g = hex_to_bn(DH_GROUP14_G);

    bool expected_group =
        expected_p && expected_g &&
        BN_cmp(p, expected_p) == 0 &&
        BN_cmp(g, expected_g) == 0;

    BN_free(expected_p);
    BN_free(expected_g);

    if (!expected_group)
    {
        std::cerr << "[Client] Unexpected DH group.\n";

        BN_free(p);
        BN_free(g);
        BN_free(server_public);
        return false;
    }

    if (BN_is_zero(server_public) ||
        BN_is_one(server_public) ||
        BN_cmp(server_public, p) >= 0)
    {
        std::cerr << "[Client] Invalid server DH public value.\n";

        BN_free(p);
        BN_free(g);
        BN_free(server_public);
        return false;
    }

    BIGNUM* private_key =
        generate_private_key(p);

    BIGNUM* public_key =
        compute_public_key(
            g,
            private_key,
            p
        );

    if (!private_key || !public_key)
    {
        BN_free(p);
        BN_free(g);
        BN_free(server_public);
        BN_free(private_key);
        BN_free(public_key);
        return false;
    }

    if (!send_line(
            fd,
            "DH_CLIENT_PUB|" + bn_to_hex(public_key)))
    {
        BN_free(p);
        BN_free(g);
        BN_free(server_public);
        BN_free(private_key);
        BN_free(public_key);
        return false;
    }

    BIGNUM* shared_secret =
        compute_shared_secret(
            server_public,
            private_key,
            p
        );

    if (!shared_secret || BN_is_zero(shared_secret))
    {
        BN_free(p);
        BN_free(g);
        BN_free(server_public);
        BN_free(private_key);
        BN_free(public_key);
        BN_free(shared_secret);
        return false;
    }

    aes_key = derive_aes_key(shared_secret);

    std::cout
        << "[Client] DH fingerprint: "
        << fingerprint(shared_secret)
        << "\n";

    if (!receive_line(fd, line) || line != "DH_OK")
    {
        BN_free(p);
        BN_free(g);
        BN_free(server_public);
        BN_free(private_key);
        BN_free(public_key);
        BN_free(shared_secret);
        return false;
    }

    std::cout << "[Client] DH handshake completed.\n";

    BN_free(p);
    BN_free(g);
    BN_free(server_public);
    BN_free(private_key);
    BN_free(public_key);
    BN_free(shared_secret);

    return true;
}

int connect_to_server(
    const std::string& ip,
    int port)
{
    int fd = socket(
        AF_INET,
        SOCK_STREAM,
        0
    );

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
        std::cerr << "Invalid IPv4 address.\n";
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

int main(int argc, char* argv[])
{
    if (argc != 3 && argc != 4)
    {
        std::cout
            << "Usage: ./client <server-ip> <username> [port]\n";
        return 1;
    }

    std::string server_ip = argv[1];
    std::string username = argv[2];

    int port = 5000;

    if (argc == 4)
        port = std::stoi(argv[3]);

    int fd = connect_to_server(server_ip, port);

    if (fd < 0)
        return 1;

    std::cout << "====================================\n";
    std::cout << "       Phase 2 Secure Client\n";
    std::cout << "====================================\n";

    std::vector<unsigned char> aes_key;

    if (!perform_dh_handshake(fd, aes_key))
    {
        std::cerr << "[Client] DH handshake failed.\n";
        close(fd);
        return 1;
    }

    if (!send_encrypted(
            fd,
            aes_key,
            "LOGIN|" + username))
    {
        close(fd);
        return 1;
    }

    std::thread receiver(
        receiver_thread,
        fd,
        aes_key
    );

    receiver.detach();

    std::string current_partner;

    std::cout << "\nCommands:\n";
    std::cout << "  @username message\n";
    std::cout << "  /chat username\n";
    std::cout << "  /who\n";
    std::cout << "  /quit\n\n";

    while (true)
    {
        std::cout << "> ";
        std::cout.flush();

        std::string input;

        if (!std::getline(std::cin, input))
            break;

        if (input.empty())
            continue;

        if (input == "/quit")
        {
            send_encrypted(fd, aes_key, "QUIT");
            break;
        }

        if (input == "/who")
        {
            send_encrypted(fd, aes_key, "WHO");
            continue;
        }

        if (input.rfind("/chat ", 0) == 0)
        {
            std::string partner = input.substr(6);

            if (partner.empty())
            {
                std::cout << "Usage: /chat username\n";
                continue;
            }

            current_partner = partner;

            std::cout
                << "[Current chat partner: "
                << current_partner
                << "]\n";

            continue;
        }

        if (input[0] == '@')
        {
            size_t space = input.find(' ');

            if (space == std::string::npos)
            {
                std::cout
                    << "Usage: @username message\n";
                continue;
            }

            std::string recipient =
                input.substr(1, space - 1);

            std::string text =
                input.substr(space + 1);

            if (recipient.empty() || text.empty())
            {
                std::cout
                    << "Usage: @username message\n";
                continue;
            }

            current_partner = recipient;

            send_encrypted(
                fd,
                aes_key,
                "MSG|" + recipient + "|" + text
            );

            continue;
        }

        /*
         * Anything that is not a recognized command is a normal
         * chat message to the currently selected partner.
         */
        if (current_partner.empty())
        {
            std::cout
                << "No chat partner selected. "
                << "Use @username message or /chat username.\n";
            continue;
        }

        send_encrypted(
            fd,
            aes_key,
            "MSG|" + current_partner + "|" + input
        );
    }

    close(fd);
    return 0;
}
