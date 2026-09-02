#include <iostream>
#include <string>
#include <thread>
#include <sstream>

#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

using namespace std;

const int PORT = 5000;


// --------------------------------------------------
// Receive one complete line
// --------------------------------------------------

bool receive_line(
    int socket_fd,
    string& line
)
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
// Send one complete line
// --------------------------------------------------

bool send_line(
    int socket_fd,
    const string& message
)
{
    string data = message + "\n";

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
// Receive messages from server
// --------------------------------------------------

void receive_messages(
    int socket_fd
)
{
    string line;

    while (true)
    {
        if (!receive_line(socket_fd, line))
        {
            cout << "\n[Client] Server disconnected."
                 << endl;

            break;
        }


        // ------------------------------------------
        // Normal chat message
        //
        // FROM|alice|hello
        // ------------------------------------------

        if (line.rfind("FROM|", 0) == 0)
        {
            string remaining =
                line.substr(5);

            size_t separator =
                remaining.find('|');

            if (separator != string::npos)
            {
                string sender =
                    remaining.substr(
                        0,
                        separator
                    );

                string message =
                    remaining.substr(
                        separator + 1
                    );


                cout << "\n["
                     << sender
                     << "] "
                     << message
                     << endl;

                cout << "> ";
                cout.flush();
            }

            continue;
        }


        // ------------------------------------------
        // Online users
        //
        // USERS|alice|bob
        // ------------------------------------------

        if (line.rfind("USERS", 0) == 0)
        {
            cout << "\n[Online users]" << endl;

            string remaining = line.substr(5);

            if (!remaining.empty() &&
                remaining[0] == '|')
            {
                remaining.erase(0, 1);
            }


            stringstream ss(remaining);

            string user;

            while (getline(ss, user, '|'))
            {
                cout << "  " << user << endl;
            }

            cout << "> ";
            cout.flush();

            continue;
        }


        // ------------------------------------------
        // Connection successful
        // ------------------------------------------

        if (line == "OK|Connected")
        {
            cout << "[Client] Connected successfully."
                 << endl;

            continue;
        }


        // ------------------------------------------
        // Goodbye
        // ------------------------------------------

        if (line == "BYE")
        {
            cout << "\n[Client] Disconnected."
                 << endl;

            break;
        }


        // ------------------------------------------
        // Error
        // ------------------------------------------

        if (line.rfind("ERROR|", 0) == 0)
        {
            cout << "\n[Server Error] "
                 << line.substr(6)
                 << endl;

            cout << "> ";
            cout.flush();

            continue;
        }
    }
}


// --------------------------------------------------
// Main
// --------------------------------------------------

int main(
    int argc,
    char* argv[]
)
{
    if (argc != 3)
    {
        cout << "Usage: ./client <server-ip> <username>"
             << endl;

        return 1;
    }


    string server_ip = argv[1];
    string username = argv[2];


    // ------------------------------------------------
    // Create socket
    // ------------------------------------------------

    int client_socket = socket(
        AF_INET,
        SOCK_STREAM,
        0
    );

    if (client_socket < 0)
    {
        perror("socket");
        return 1;
    }


    // ------------------------------------------------
    // Server address
    // ------------------------------------------------

    sockaddr_in server_address{};

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(PORT);


    if (inet_pton(
            AF_INET,
            server_ip.c_str(),
            &server_address.sin_addr
        ) <= 0)
    {
        cout << "Invalid server IP address."
             << endl;

        close(client_socket);

        return 1;
    }


    // ------------------------------------------------
    // Connect
    // ------------------------------------------------

    if (connect(
            client_socket,
            (sockaddr*)&server_address,
            sizeof(server_address)
        ) < 0)
    {
        perror("connect");

        close(client_socket);

        return 1;
    }


    cout << "====================================" << endl;
    cout << "          Phase 1 Chat              " << endl;
    cout << "====================================" << endl;

    cout << "Username: "
         << username
         << endl;


    // ------------------------------------------------
    // Register username
    // ------------------------------------------------

    send_line(
        client_socket,
        "LOGIN|" + username
    );


    // ------------------------------------------------
    // Start receiving thread
    // ------------------------------------------------

    thread receiver(
        receive_messages,
        client_socket
    );

    receiver.detach();


    // ------------------------------------------------
    // Current selected chat partner
    // ------------------------------------------------

    string current_partner = "";


    cout << endl;
    cout << "Commands:" << endl;
    cout << "  @username message" << endl;
    cout << "  /chat username" << endl;
    cout << "  /who" << endl;
    cout << "  /quit" << endl;
    cout << endl;


    // ------------------------------------------------
    // Main input loop
    // ------------------------------------------------

    string input;

    while (true)
    {
        cout << "> ";
        getline(cin, input);


        if (cin.eof())
            break;


        if (input.empty())
            continue;


        // ==================================================
        // /quit
        // ==================================================

        if (input == "/quit")
        {
            send_line(
                client_socket,
                "QUIT"
            );

            break;
        }


        // ==================================================
        // /who
        // ==================================================

        if (input == "/who")
        {
            send_line(
                client_socket,
                "WHO"
            );

            continue;
        }


        // ==================================================
        // /chat username
        // ==================================================

        if (input.rfind("/chat ", 0) == 0)
        {
            string username =
                input.substr(6);


            if (username.empty())
            {
                cout << "Usage: /chat username"
                     << endl;

                continue;
            }


            current_partner = username;


            cout << "[Chat switched to "
                 << current_partner
                 << "]"
                 << endl;

            continue;
        }


        // ==================================================
        // @username message
        // ==================================================

        if (input[0] == '@')
        {
            size_t space =
                input.find(' ');


            if (space == string::npos)
            {
                cout << "Usage: @username message"
                     << endl;

                continue;
            }


            string recipient =
                input.substr(
                    1,
                    space - 1
                );


            string message =
                input.substr(space + 1);


            if (recipient.empty() ||
                message.empty())
            {
                cout << "Usage: @username message"
                     << endl;

                continue;
            }


            // This also changes the selected partner
            current_partner = recipient;


            send_line(
                client_socket,
                "MSG|" +
                recipient +
                "|" +
                message
            );

            continue;
        }


        // ==================================================
        // Plain message
        // ==================================================

        if (current_partner.empty())
        {
            cout << "No chat partner selected."
                 << endl;

            cout << "Use:"
                 << endl;

            cout << "  @username message"
                 << endl;

            cout << "or:"
                 << endl;

            cout << "  /chat username"
                 << endl;

            continue;
        }


        // Send plain message to currently selected user
        send_line(
            client_socket,
            "MSG|" +
            current_partner +
            "|" +
            input
        );
    }


    // ------------------------------------------------
    // Cleanup
    // ------------------------------------------------

    close(client_socket);

    return 0;
}