#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <sstream>
#include <vector>

#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

using namespace std;

const int PORT = 5000;
const int MAX_CLIENTS = 2;

// username -> socket
unordered_map<string, int> clients;

mutex clients_mutex;

// Separate mutex for each client's socket.
// This prevents two server threads from writing to
// the same socket at the same time.
mutex send_mutexes[MAX_CLIENTS];


// --------------------------------------------------
// Send a complete line
// --------------------------------------------------

bool send_line(int socket_fd, int client_id, const string& message)
{
    string data = message + "\n";

    lock_guard<mutex> lock(send_mutexes[client_id]);

    size_t total_sent = 0;

    while (total_sent < data.size())
    {
        int bytes_sent = send(
            socket_fd,
            data.c_str() + total_sent,
            data.size() - total_sent,
            0
        );

        if (bytes_sent <= 0)
            return false;

        total_sent += bytes_sent;
    }

    return true;
}


// --------------------------------------------------
// Receive exactly one line from TCP stream
// --------------------------------------------------

bool receive_line(int socket_fd, string& line)
{
    line.clear();

    char ch;

    while (true)
    {
        int bytes_received = recv(
            socket_fd,
            &ch,
            1,
            0
        );

        if (bytes_received <= 0)
            return false;

        if (ch == '\n')
            break;

        if (ch != '\r')
            line += ch;
    }

    return true;
}


// --------------------------------------------------
// Send current online users
// --------------------------------------------------

void send_online_users(
    int client_socket,
    int client_id
)
{
    lock_guard<mutex> lock(clients_mutex);

    string response = "USERS";

    for (const auto& entry : clients)
    {
        response += "|" + entry.first;
    }

    send_line(
        client_socket,
        client_id,
        response
    );
}

// --------------------------------------------------
// Remove client
// --------------------------------------------------

void remove_client(
    const string& username
)
{
    lock_guard<mutex> lock(clients_mutex);

    clients.erase(username);
}


// --------------------------------------------------
// Handle one client
// --------------------------------------------------

void handle_client(
    int client_socket,
    int client_id
)
{
    string username;

    // ----------------------------------------------
    // First message must be:
    //
    // LOGIN|username
    // ----------------------------------------------

    string line;

    if (!receive_line(client_socket, line))
    {
        close(client_socket);
        return;
    }


    if (line.rfind("LOGIN|", 0) != 0)
    {
        send_line(
            client_socket,
            client_id,
            "ERROR|First message must be LOGIN"
        );

        close(client_socket);
        return;
    }


    username = line.substr(6);


    if (username.empty())
    {
        send_line(
            client_socket,
            client_id,
            "ERROR|Username cannot be empty"
        );

        close(client_socket);
        return;
    }


    // ----------------------------------------------
    // Register username
    // ----------------------------------------------

    {
        lock_guard<mutex> lock(clients_mutex);

        if (clients.size() >= MAX_CLIENTS)
        {
            send_line(
                client_socket,
                client_id,
                "ERROR|Server is full"
            );

            close(client_socket);
            return;
        }


        if (clients.find(username) != clients.end())
        {
            send_line(
                client_socket,
                client_id,
                "ERROR|Username already exists"
            );

            close(client_socket);
            return;
        }


        clients[username] = client_socket;
    }


    cout << "[Server] "
         << username
         << " connected."
         << endl;


    send_line(
        client_socket,
        client_id,
        "OK|Connected"
    );


    // ----------------------------------------------
    // Main message loop
    // ----------------------------------------------

    while (true)
    {
        if (!receive_line(client_socket, line))
        {
            cout << "[Server] "
                 << username
                 << " disconnected."
                 << endl;

            break;
        }


        // ------------------------------------------
        // WHO
        // ------------------------------------------

        if (line == "WHO")
        {
            cout << "[Server] "
                 << username
                 << " requested online users."
                 << endl;

            send_online_users(
                client_socket,
                client_id
            );

            continue;
        }


        // ------------------------------------------
        // QUIT
        // ------------------------------------------

        if (line == "QUIT")
        {
            cout << "[Server] "
                 << username
                 << " requested disconnect."
                 << endl;

            send_line(
                client_socket,
                client_id,
                "BYE"
            );

            break;
        }


        // ------------------------------------------
        // MESSAGE
        //
        // MSG|recipient|message
        // ------------------------------------------

        if (line.rfind("MSG|", 0) == 0)
        {
            string remaining = line.substr(4);

            size_t separator = remaining.find('|');

            if (separator == string::npos)
            {
                send_line(
                    client_socket,
                    client_id,
                    "ERROR|Invalid message format"
                );

                continue;
            }


            string recipient =
                remaining.substr(0, separator);

            string message =
                remaining.substr(separator + 1);


            // --------------------------------------
            // Required Phase 1 verification:
            // Server can read plaintext
            // --------------------------------------

            cout << "[Server] "
                 << username
                 << " -> "
                 << recipient
                 << ": "
                 << message
                 << endl;


            // --------------------------------------
            // Find recipient
            // --------------------------------------

            int recipient_socket = -1;
            int recipient_id = -1;

            {
                lock_guard<mutex> lock(clients_mutex);

                auto it = clients.find(recipient);

                if (it != clients.end())
                {
                    recipient_socket = it->second;

                    // Since we only support two clients,
                    // identify the other client.
                    //
                    // client_id 0 -> recipient 1
                    // client_id 1 -> recipient 0
                    recipient_id =
                        (client_id == 0) ? 1 : 0;
                }
            }


            if (recipient_socket == -1)
            {
                send_line(
                    client_socket,
                    client_id,
                    "ERROR|User not online"
                );

                continue;
            }


            // --------------------------------------
            // Relay plaintext
            // --------------------------------------

            string outgoing =
                "FROM|" + username + "|" + message;


            send_line(
                recipient_socket,
                recipient_id,
                outgoing
            );


            cout << "[Server] Relayed message."
                 << endl;

            continue;
        }


        // ------------------------------------------
        // Unknown command
        // ------------------------------------------

        send_line(
            client_socket,
            client_id,
            "ERROR|Unknown request"
        );
    }


    // ----------------------------------------------
    // Cleanup
    // ----------------------------------------------

    remove_client(username);

    close(client_socket);
}


int main()
{
    // ------------------------------------------------
    // Create TCP socket
    // ------------------------------------------------

    int server_socket = socket(
        AF_INET,
        SOCK_STREAM,
        0
    );

    if (server_socket < 0)
    {
        perror("socket");
        return 1;
    }


    // Allow immediate restart
    int opt = 1;

    setsockopt(
        server_socket,
        SOL_SOCKET,
        SO_REUSEADDR,
        &opt,
        sizeof(opt)
    );


    // ------------------------------------------------
    // Server address
    // ------------------------------------------------

    sockaddr_in server_address{};

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(PORT);


    // ------------------------------------------------
    // Bind
    // ------------------------------------------------

    if (bind(
            server_socket,
            (sockaddr*)&server_address,
            sizeof(server_address)
        ) < 0)
    {
        perror("bind");

        close(server_socket);

        return 1;
    }


    // ------------------------------------------------
    // Listen
    // ------------------------------------------------

    if (listen(
            server_socket,
            MAX_CLIENTS
        ) < 0)
    {
        perror("listen");

        close(server_socket);

        return 1;
    }


    cout << "====================================" << endl;
    cout << "        Phase 1 Chat Server         " << endl;
    cout << "====================================" << endl;

    cout << "[Server] Listening on port "
         << PORT
         << endl;


    // ------------------------------------------------
    // Accept clients
    // ------------------------------------------------

    int client_count = 0;

    while (client_count < MAX_CLIENTS)
    {
        sockaddr_in client_address{};

        socklen_t client_length =
            sizeof(client_address);


        int client_socket = accept(
            server_socket,
            (sockaddr*)&client_address,
            &client_length
        );


        if (client_socket < 0)
        {
            perror("accept");
            continue;
        }


        int client_id = client_count++;

        cout << "[Server] Connection "
             << client_id
             << " accepted from "
             << inet_ntoa(client_address.sin_addr)
             << endl;


        thread(
            handle_client,
            client_socket,
            client_id
        ).detach();
    }


    cout << "[Server] Maximum number of clients "
         << "connected." << endl;


    // Keep server alive
    while (true)
    {
        sleep(1);
    }


    close(server_socket);

    return 0;
}