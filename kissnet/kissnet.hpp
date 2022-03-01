/*
 * MIT License
 *
 * Copyright (c) 2018-2020 Arthur Brainville (Ybalrid) and with the help of
 * Comunity Contributors!
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * INTRODUCTION
 * ============
 *
 * Kissnet is a simple C++17 layer around the raw OS provided socket API to be
 * used on IP networks with the TCP and UDP protocols.
 *
 * Kissnet is not a networking framework, and it will not process your data or
 * assist you in any way. Kissnet's only goal is to provide a simple API to send
 * and receive bytes,
 * without having to play around with a bunch of structure, file descriptors,
 * handles and pointers given to a C-style API. The other goal of Kissnet is to
 * provide an API that will works in a cross platform setting.
 *
 * Kissnet will automatically manage the eventual startup/shutdown of the
 * library needed to perform socket operations on a particular platform. (e.g.
 * the Windows Socket API on MS-Windows.
 *
 * Kissnet leverages (and expect you to do so), multiple features from C++17,
 * including: std::byte, if constexpr, structured bindings, if-initializer and
 * template parameter type deduction.
 *
 * The library is structured across 4 exposed data types:
 *
 *  - Buffer<size_t> : a static array of std::byte implemented via std::array.
 *  This is what you should use to hold raw data you are getting from a socket,
 *  before extracting what you need from the bytes
 *  - port_t : a 16 bit unsigned number. Represent a network mPort number
 *  - endpoint : a structure that represent a location where you need to connect
 *  to. Contains a hostname (as std::string) and a mPort number (as port_t)
 *  - socket<Protocol> : a templated class that represents an ipv4 or ipv6 socket.
 *  Protocol is either TCP or UDP
 *
 * Kissnet does Error handling in 2 ways:
 *
 *  1:
 *  When an operation can generate an Error that the user should handle by hand
 *  anyway, a tuple containing the expected type returned, and an object that
 *  represent the status of what happens is returned.
 *
 *  For example, socket send/receive operation can discover that the connection
 *  was closed, or was shut down properly. It could also be the fact that a
 *  socket was configured "non blocking" and would have blocked in this
 *  situation. On both occasion, these methods will return the fact that 0 bytes
 *  came across as the transaction size, and the status will indicate either an
 *  Error (socket no longer VALID), or an actual status message (connection
 *  closed, socket would have blocked)
 *
 *  These status objects will behave like a const bool that equals "false" when
 *  an Error occurred, and "true" when it's just a status notification
 *
 *  2:
 *  Fatal errors are by default handled by throwing a runtime_error exception.
 *  But, for many reasons, you may want to
 *  not use exceptions entirely.
 *
 *  Kissnet give you some facilities to get fatal errors information back, and
 *  to choose how to handle it. Kissnet give you a few levers you can use:
 *
 *  - You can deactivate the exception support by #defining KISSNET_NO_EXCEP
 *  before #including Kissnet.hpp. Instead, Kissnet will use a function based
 *  Error handler
 *  - By default, the Error handler prints to stderr the Error message, and
 *  abort the program
 *  - Kissnet::Error::pCallback is a function pointer that gets a string, and a
 *  context pointer. The string is the Error message, and the context pointer
 * what ever you gave Kissnet for the occasion. This is a global pointer that
 * you can set as you want. This will override the "print to stderr" behavior
 * at fatal Error time.
 *  - Kissnet::Error::pCtx is a void*, this will be passed to your Error handler
 *  as a "context" pointer. If you need your handler to write to a log,
 *  or to turn on the HTCPCP enabled teapot on John's desk, you can.
 *  - Kissnet::lAbortOnFatalError is a boolean that will control the call to
 *  abort(). This is independent to the fact that you did set or not an Error
 *  pCallback. please note that any object involved with the operation that
 * triggered the fatal Error is probably in an invalid state, and probably
 * deserve to be thrown away.
 */

#ifndef KISS_NET
#define KISS_NET

///Define this to not use exceptions
#ifndef KISSNET_NO_EXCEP
#define kissnet_fatal_error(STR) throw std::runtime_error(STR)
#else
#define kissnet_fatal_error(STR) Kissnet::Error::handle(STR);
#endif

#include <array>
#include <memory>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cassert>
#include <stdexcept>
#include <string>
#include <utility>

#ifdef _WIN32

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#ifndef NOMINMAX
#define NOMINMAX
#endif //endif nominmax

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

using ioctl_setting = u_long;
using buffsize_t	= int;

#define AI_ADDRCONFIG 0x00000400

#ifndef SHUT_RDWR
#define SHUT_RDWR SD_BOTH
#endif

// taken from: https://github.com/rxi/dyad/blob/915ae4939529b9aaaf6ebfd2f65c6cff45fc0eac/src/dyad.c#L58
inline const char* inet_ntop(int af, const void* src, char* dst, socklen_t size) {
    union {
        struct sockaddr sa;
        struct sockaddr_in sai;
        struct sockaddr_in6 sai6;
    } addr;
    int res;
    memset(&addr, 0, sizeof(addr));
    addr.sa.sa_family = af;
    if (af == AF_INET6) {
        memcpy(&addr.sai6.sin6_addr, src, sizeof(addr.sai6.sin6_addr));
    } else {
        memcpy(&addr.sai.sin_addr, src, sizeof(addr.sai.sin_addr));
    }
    res = WSAAddressToStringA(&addr.sa, sizeof(addr), 0, dst, reinterpret_cast<LPDWORD>(&size));
    if (res != 0) return NULL;
    return dst;
}

//Handle WinSock2/Windows Socket API initialization and cleanup
#pragma comment(lib, "Ws2_32.lib")
namespace Kissnet {

    namespace win32Specific {
        ///Forward declare the object that will permit to manage the WSAStartup/Cleanup automatically
        struct WSA;

        ///Enclose the global pointer in this namespace. Only use this inside a shared_ptr
        namespace internalState {
            static WSA* pGlobalWSA = nullptr;
        }

        ///WSA object. Only to be constructed with std::make_shared()
        struct WSA : std::enable_shared_from_this<WSA> {
            //For safety, only initialize Windows Socket API once, and delete it once
            ///Prevent copy construct
            WSA(const WSA&) = delete;
            ///Prevent copy assignment
            WSA& operator=(const WSA&) = delete;
            ///Prevent moving
            WSA(WSA&&) = delete;
            ///Prevent move assignment
            WSA& operator=(WSA&&) = delete;

            ///data storage
            WSADATA lWSAData;

            ///Startup
            WSA() :
             lWSAData {} {
                if (const auto lStatus = WSAStartup(MAKEWORD(2, 2), &lWSAData); lStatus != 0) {
                    std::string errorMessage;
                    switch (lStatus) // https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup#return-mValue
                    {
                        default:
                            errorMessage = "Unknown Error happened.";
                            break;
                        case WSASYSNOTREADY:
                            errorMessage = "The underlying network subsystem is not ready for network communication.";
                            break;
                        case WSAVERNOTSUPPORTED: //unlikely, we specify 2.2!
                            errorMessage = " The version of Windows Sockets support requested "
                                            "(2.2)" //we know here the version was 2.2, add that to the Error message copied from MSDN
                                            " is not provided by this particular Windows Sockets implementation. ";
                            break;
                        case WSAEINPROGRESS:
                            errorMessage = "A blocking Windows Sockets 1.1 operation is in progress.";
                            break;
                        case WSAEPROCLIM:
                            errorMessage = "A limit on the number of tasks supported by the Windows Sockets implementation has been reached.";
                            break;
                        case WSAEFAULT: //unlikely, if this ctor is running, wsa_data is part of this object's "stack" data
                            errorMessage = "The lpWSAData parameter is not a VALID pointer.";
                            break;
                    }
                    kissnet_fatal_error(errorMessage);
                }
#ifdef KISSNET_WSA_DEBUG
                std::cerr << "Initialized Windows Socket API\n";
#endif
            }

            ///Cleanup
            ~WSA() {
                WSACleanup();
                internalState::pGlobalWSA = nullptr;
#ifdef KISSNET_WSA_DEBUG
                std::cerr << "Cleanup Windows Socket API\n";
#endif
            }

            ///get the shared pointer
            std::shared_ptr<WSA> getPtr() {
                return shared_from_this();
            }
        };

        ///Get-or-create the global pointer
        inline std::shared_ptr<WSA> getWSA() {
            //If it has been created already:
            if (internalState::pGlobalWSA)
                return internalState::pGlobalWSA->getPtr(); //fetch the smart pointer from the naked pointer

            //Create in wsa
            auto lWSA = std::make_shared<WSA>();

            //Save the raw mAddress in the global state
            internalState::pGlobalWSA = lWSA.get();

            //Return the smart pointer
            return lWSA;
        }
    }

#define KISSNET_OS_SPECIFIC_PAYLOAD_NAME wsa_ptr
#define KISSNET_OS_SPECIFIC std::shared_ptr<Kissnet::win32Specific::WSA> KISSNET_OS_SPECIFIC_PAYLOAD_NAME
#define KISSNET_OS_INIT KISSNET_OS_SPECIFIC_PAYLOAD_NAME = Kissnet::win32Specific::getWSA()

    ///Return the last Error code
    inline int getErrorCode() {
        const auto lError = WSAGetLastError();

        //We need to posixify the Codes that we are actually using inside this header.
        switch (lError) {
            case WSAEWOULDBLOCK:
                return EWOULDBLOCK;
            case WSAEBADF:
                return EBADF;
            case WSAEINTR:
                return EINTR;
            default:
                return lError;
        }
    }
}
#else //UNIX platform

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>
#include <cerrno>
#include <fcntl.h>

using ioctl_setting = int;
using buffsize_t = size_t;

//To get consistent socket API between Windows and Linux:
static const int INVALID_SOCKET = -1;
static const int SOCKET_ERROR = -1;
using SOCKET = int;
using SOCKADDR_IN = sockaddr_in;
using SOCKADDR = sockaddr;
using IN_ADDR = in_addr;

//Wrap them lIn their WIN32 names
inline int closeSocket(SOCKET lIn) {
    return close(lIn);
}

template<typename... Params>
inline int ioctlSocket(int lFd, int lRequest, Params &&... rParams) {
    return ioctl(lFd, lRequest, rParams...);
}

#define KISSNET_OS_SPECIFIC_PAYLOAD_NAME dummy
#define KISSNET_OS_SPECIFIC char dummy
#define KISSNET_OS_INIT dummy = 42;

inline int getErrorCode() {
    return errno;
}

#endif //_WIN32

#ifdef KISSNET_USE_OPENSSL

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <vector>
#include <mutex>

#endif //KISSNET_USE_OPENSSL

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

///Main namespace of Kissnet
namespace Kissnet {

    ///Exception-less Error handling infrastructure
    namespace Error {
        static void (*pCallback)(const std::string &, void *) = nullptr;

        static void *pCtx = nullptr;
        static bool lAbortOnFatalError = true;

        inline void handle(const std::string &rStr) {
            //if the Error::pCallback function has been provided, call that
            if (pCallback) {
                pCallback(rStr, pCtx);
                //Print Error into the standard Error output
            } else {
                fputs(rStr.c_str(), stderr);
            }

            //If the Error abort hasn't been deactivated
            if (lAbortOnFatalError) {
                abort();
            }
        }
    }

    ///low level Protocol used, between TCP\TCP_SSL and UDP
    enum class Protocol {
        TCP,
        TCP_SSL,
        UDP
    };

    ///Address information structs
    struct AddrCollection {
        sockaddr_storage mAddrinf = {0};
        socklen_t mSockSize = 0;
    };

    ///File descriptor set types
    static constexpr int fds_read = 0x1;
    static constexpr int fds_write = 0x2;
    static constexpr int fds_except = 0x4;

    ///Buffer is an array of std::byte
    template<size_t buffSize>
    using Buffer = std::array<std::byte, buffSize>;

    ///port_t is the mPort
    using port_t = uint16_t;

    ///An endpoint is where the network will connect to (mAddress and mPort)
    class Endpoint {
        ///The mAddress to connect to
        std::string mAddress{};
        ///The mPort to connect to
        port_t mPort{};

    public:
        ///Default constructor
        Endpoint() = default;

        ///Basically create the endpoint with what you give it
        explicit Endpoint(std::string lAddr, port_t lPort) :
                mAddress{std::move(lAddr)}, mPort{lPort} {
            if (!isValidPortNumber(mPort)) {
                kissnet_fatal_error("Invalid port number " + std::to_string(mPort));
            }
        }

        static bool isValidPortNumber(unsigned long lPort) {
            return lPort < 1 << 16 && (lPort != 0);
        }

        ///Construct the endpoint from "mAddress:mPort"
        explicit Endpoint(const std::string &rAddr) {
            const auto lSeparator = rAddr.find_last_of(':');

            //Check if input wasn't missformed
            if (lSeparator == std::string::npos)
                kissnet_fatal_error("string is not of address:port form");
            if (lSeparator == rAddr.size() - 1)
                kissnet_fatal_error("string has ':' as last character. Expected port number here");

            //Isolate mAddress
            mAddress = rAddr.substr(0, lSeparator);

            //Read from string as unsigned
            const auto lParsedPort = strtoul(rAddr.substr(lSeparator + 1).c_str(), nullptr, 10);

            //In all other cases, mPort was always given as a port_t type, strongly preventing it to be a number outside of the [0; 65535] range. Here it's not the case.
            //To detect errors early, check it here :
            if (!isValidPortNumber(lParsedPort)) {
                kissnet_fatal_error("Invalid port number " + std::to_string(lParsedPort));
            }

            //Store it
            mPort = static_cast<port_t>(lParsedPort);
        }

        ///Construct an endpoint from a SOCKADDR
        explicit Endpoint(SOCKADDR *pAddr) {
            switch (pAddr->sa_family) {
                case AF_INET: {
                    auto lIP4Addr = (SOCKADDR_IN *) (pAddr);
                    mAddress = inet_ntoa(lIP4Addr->sin_addr);
                    mPort = ntohs(lIP4Addr->sin_port);
                }
                    break;

                case AF_INET6: {
                    auto lIP6Addr = (sockaddr_in6 *) (pAddr);
                    char buffer[INET6_ADDRSTRLEN];
                    mAddress = inet_ntop(AF_INET6, &(lIP6Addr->sin6_addr), buffer, INET6_ADDRSTRLEN);
                    mPort = ntohs(lIP6Addr->sin6_port);
                }
                    break;

                default: {
                    kissnet_fatal_error(
                            "Trying to construct an endpoint for a Protocol familly that is neither AF_INET or AF_INET6");
                }
            }

            if (empty()) {
                kissnet_fatal_error("Couldn't construct endpoint from sockaddr(_storage) struct");
            }
        }

        [[nodiscard]] bool empty() const {
            return mAddress.empty() || mPort == 0;
        }

        [[nodiscard]] std::string address() const {
            return mAddress;
        }

        [[nodiscard]] port_t port() const {
            return mPort;
        }
    };

    //Wrap "system calls" here to avoid conflicts with the names used in the socket class

    ///socket()
    inline auto syscallSocket = [](int lAf, int lType, int lProtocol) {
        return ::socket(lAf, lType, lProtocol);
    };

    ///select()
    inline auto syscallSelect = [](int lNfds, fd_set *pReadFds, fd_set *pWriteFds, fd_set *pExceptFds,
                                   struct timeval *pTimeout) {
        return ::select(lNfds, pReadFds, pWriteFds, pExceptFds, pTimeout);
    };

    ///recv()
    inline auto syscallRecv = [](SOCKET lSocket, char *pBuff, buffsize_t lLen, int lFlags) {
        return ::recv(lSocket, pBuff, lLen, lFlags);
    };

    ///send()
    inline auto syscallSend = [](SOCKET lSocket, const char *buff, buffsize_t lLen, int lFlags) {
        return ::send(lSocket, buff, lLen, lFlags);
    };

    ///bind()
    inline auto syscallBind = [](SOCKET lSocket, const struct sockaddr *pName, socklen_t lNameLen) {
        return ::bind(lSocket, pName, lNameLen);
    };

    ///connect()
    inline auto syscallConnect = [](SOCKET lSocket, const struct sockaddr *pName, socklen_t lNameLen) {
        return ::connect(lSocket, pName, lNameLen);
    };

    ///listen()
    inline auto syscallListen = [](SOCKET lSocket, int lBacklog) {
        return ::listen(lSocket, lBacklog);
    };

    ///accept()
    inline auto syscallAccept = [](SOCKET lSocket, struct sockaddr *pAddr, socklen_t *pAddrlen) {
        return ::accept(lSocket, pAddr, pAddrlen);
    };

    ///shutdown()
    inline auto syscallShutdown = [](SOCKET lSocket) {
        return ::shutdown(lSocket, SHUT_RDWR);
    };

    ///Represent the status of a socket as returned by a socket operation (send, received). Implicitly convertible to bool
    struct SocketStatus {
        ///Enumeration of socket status, with a 1 byte footprint
        enum Codes : int8_t {
            ERRORED = 0x0,
            VALID = 0x1,
            CLEANLY_DISCONNECTED = 0x2,
            NON_BLOCKING_WOULD_HAVE_BLOCKED = 0x3,
            TIMED_OUT = 0x4

            /* ... any other info on a "still VALID socket" goes here ... */

        };

        ///Actual mValue of the SocketStatus.
        const Codes mValue;

        ///Use the default constructor
        SocketStatus() :
                mValue{ERRORED} {}

        ///Construct a "ERRORED/VALID" status for a true/false
        explicit SocketStatus(bool state) :
                mValue(Codes(state ? VALID : ERRORED)) {}

        explicit SocketStatus(Codes lCodeValue) :
                mValue(lCodeValue) {}

        ///Copy socket status by default
        SocketStatus(const SocketStatus &) = default;

        ///Move socket status by default
        SocketStatus(SocketStatus &&) = default;

        ///implicitly convert this object to const bool (as the status should not change)
        explicit operator bool() const {
            //See the above enum: every mValue <= 0 correspond to an Error, and will return false. Every mValue > 0 returns true
            return mValue > 0;
        }

        [[nodiscard]] int8_t getValue() const {
            return mValue;
        }

        bool operator==(Codes v) const {
            return v == mValue;
        }
    };

#ifdef KISSNET_USE_OPENSSL
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    static std::shared_ptr<std::vector<std::mutex>> SSL_lock_cs;

    class ThreadSafe_SSL {
    public:
        ThreadSafe_SSL() {
            SSL_lock_cs = std::make_shared<std::vector<std::mutex>>(CRYPTO_num_locks());

            CRYPTO_set_locking_callback((void(*)(int, int, const char*, int))
                                            win32_locking_callback);
        }

        ~ThreadSafe_SSL() { CRYPTO_set_locking_callback(nullptr); }

    private:
        static void win32_locking_callback(int mode, int type, const char* file, int line) {
            auto& locks = *SSL_lock_cs;

            if (mode & CRYPTO_LOCK) {
                locks[type].lock();
            } else {
                locks[type].unlock();
            }
        }
    };

#endif

    class Initialize_SSL {
    public:
        Initialize_SSL() {
#if OPENSSL_VERSION_NUMBER < 0x1010001fL
            SSL_load_error_strings();
            SSL_library_init();
#else
            OPENSSL_init_ssl(
                    OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

            OPENSSL_init_crypto(
                    OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS,
                    nullptr);
#endif
        }

        ~Initialize_SSL() {
#if OPENSSL_VERSION_NUMBER < 0x1010001fL
            ERR_free_strings();
#endif
        }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        private:
            ThreadSafe_SSL thread_setup;
#endif
    };

    static Initialize_SSL InitializeSSL;
#endif

    ///Class that represent a socket
    template<Protocol sockProto>
    class Socket {
        ///Represent a number of bytes with a status information. Some of the methods of this class returns this.
        using bytesWithStatus = std::tuple<size_t, SocketStatus::Codes>;

        ///OS specific stuff. payload we have to hold onto for RAII management of the Operating System's socket library (e.g. Windows Socket API WinSock2)
        KISSNET_OS_SPECIFIC{};

        ///operatic-system type for a socket object
        SOCKET mSock = INVALID_SOCKET;

#ifdef KISSNET_USE_OPENSSL
        SSL *mSSL = nullptr;
        SSL_CTX *mContext = nullptr;
#endif

        ///Location where this socket is bound
        Endpoint mEndpoint = {};

        ///Address information structures
        addrinfo mGetAddrinfoHints = {};
        addrinfo *mGetAddrinfoResults = nullptr;
        addrinfo *mSocketAddrinfo = nullptr;

        void initialize_addrinfo() {
            int lType{};
            int lIprotocol{};
            if constexpr (sockProto == Protocol::TCP || sockProto == Protocol::TCP_SSL) {
                lType = SOCK_STREAM;
                lIprotocol = IPPROTO_TCP;
            } else if constexpr (sockProto == Protocol::UDP) {
                lType = SOCK_DGRAM;
                lIprotocol = IPPROTO_UDP;
            }

            mGetAddrinfoHints = {};
            mGetAddrinfoHints.ai_family = AF_UNSPEC;
            mGetAddrinfoHints.ai_socktype = lType;
            mGetAddrinfoHints.ai_protocol = lIprotocol;
            mGetAddrinfoHints.ai_flags = AI_ADDRCONFIG;
        }

        ///Create and connect to socket
        SocketStatus::Codes connect(addrinfo *pAddr, int64_t lTimeout, bool lCreatesocket) {
            if constexpr (sockProto == Protocol::TCP ||
                          sockProto == Protocol::TCP_SSL) //only TCP is a connected Protocol
            {
                if (lCreatesocket) {
                    close();
                    mSocketAddrinfo = nullptr;
                    mSock = syscallSocket(pAddr->ai_family, pAddr->ai_socktype, pAddr->ai_protocol);
                }

                if (mSock == INVALID_SOCKET)
                    return SocketStatus::Codes::ERRORED;

                mSocketAddrinfo = pAddr;

                if (lTimeout > 0)
                    setNonBlocking(true);

                int error = syscallConnect(mSock, pAddr->ai_addr, socklen_t(pAddr->ai_addrlen));
                if (error == SOCKET_ERROR) {
                    error = getErrorCode();
                    if (error == EWOULDBLOCK || error == EAGAIN || error == EINPROGRESS) {
                        struct timeval tv = {0};
                        tv.tv_sec = static_cast<long>(lTimeout / 1000);
                        tv.tv_usec = 1000 * static_cast<long>(lTimeout % 1000);

                        fd_set fd_write, fd_except;

                        FD_ZERO(&fd_write);
                        FD_SET(mSock, &fd_write);
                        FD_ZERO(&fd_except);
                        FD_SET(mSock, &fd_except);

                        int ret = syscallSelect(static_cast<int>(mSock) + 1, nullptr, &fd_write, &fd_except, &tv);
                        if (ret == -1)
                            error = getErrorCode();
                        else if (ret == 0)
                            error = ETIMEDOUT;
                        else {
                            socklen_t errlen = sizeof(error);
                            if (getsockopt(mSock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&error), &errlen) != 0)
                                kissnet_fatal_error("getting socket Error returned an Error");
                        }
                    }
                }

                if (lTimeout > 0)
                    setNonBlocking(false);

                if (error == 0) {
                    return SocketStatus::VALID;
                } else {
                    close();
                    mSocketAddrinfo = nullptr;
                    return SocketStatus::ERRORED;
                }
            }

            kissnet_fatal_error("connect called for non-TCP socket");
        }

        ///sockaddr struct
        sockaddr_storage mSocketInput = {};
        socklen_t mSocketInputSocklen = 0;

    public:
        ///Construct an invalid socket
        Socket() = default;

        ///socket<> isn't copyable
        Socket(const Socket &) = delete;

        ///socket<> isn't copyable
        Socket &operator=(const Socket &) = delete;

        ///Move constructor. socket<> isn't copyable
        Socket(Socket &&other) noexcept {
            KISSNET_OS_SPECIFIC_PAYLOAD_NAME = std::move(other.KISSNET_OS_SPECIFIC_PAYLOAD_NAME);
            mEndpoint = std::move(other.mEndpoint);
            mSock = std::move(other.mSock);
            mSocketInput = std::move(other.mSocketInput);
            mSocketInputSocklen = std::move(other.mSocketInputSocklen);
            mGetAddrinfoResults = std::move(other.mGetAddrinfoResults);
            mSocketAddrinfo = std::move(other.mSocketAddrinfo);

#ifdef KISSNET_USE_OPENSSL
            mSSL = other.mSSL;
            mContext = other.mContext;
            other.mSSL = nullptr;
            other.mContext = nullptr;
#endif

            other.mSock = INVALID_SOCKET;
            other.mGetAddrinfoResults = nullptr;
            other.mSocketAddrinfo = nullptr;
        }

        ///Move assign operation
        Socket &operator=(Socket &&other) noexcept {
            if (this != &other) {
                if (mSock >= 0 || mSock != INVALID_SOCKET)
                    closeSocket(mSock);

                KISSNET_OS_SPECIFIC_PAYLOAD_NAME = std::move(other.KISSNET_OS_SPECIFIC_PAYLOAD_NAME);
                mEndpoint = std::move(other.mEndpoint);
                mSock = std::move(other.mSock);
                mSocketInput = std::move(other.mSocketInput);
                mSocketInputSocklen = std::move(other.mSocketInputSocklen);
                mGetAddrinfoResults = std::move(other.mGetAddrinfoResults);
                mSocketAddrinfo = std::move(other.mSocketAddrinfo);

#ifdef KISSNET_USE_OPENSSL
                mSSL = other.mSSL;
                mContext = other.mContext;
                other.mSSL = nullptr;
                other.mContext = nullptr;
#endif

                other.mSock = INVALID_SOCKET;
                other.mGetAddrinfoResults = nullptr;
                other.mSocketAddrinfo = nullptr;
            }
            return *this;
        }

        ///Return true if the underlying OS provided socket representation (file descriptor, handle...). Both socket are pointing to the same thing in this case
        bool operator==(const Socket &other) const {
            return mSock == other.mSock;
        }

        ///Return true if socket is VALID. If this is false, you probably shouldn't attempt to send/receive anything, it will probably explode in your face!
        bool is_valid() const {
            return mSock != INVALID_SOCKET;
        }

        inline operator bool() const {
            return is_valid();
        }

        ///Construct socket and (if applicable) connect to the endpoint
        explicit Socket(Endpoint bind_to) :
                mEndpoint{std::move(bind_to)} {
            //operating system related housekeeping
            KISSNET_OS_INIT;

            //Do we use streams or datagrams
            initialize_addrinfo();

            if (getaddrinfo(mEndpoint.address().c_str(), std::to_string(mEndpoint.port()).c_str(), &mGetAddrinfoHints,
                            &mGetAddrinfoResults) != 0) {
                kissnet_fatal_error("getaddrinfo failed!");
            }

            for (auto *addr = mGetAddrinfoResults; addr; addr = addr->ai_next) {
                mSock = syscallSocket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
                if (mSock != INVALID_SOCKET) {
                    mSocketAddrinfo = addr;
                    break;
                }
            }

            if (mSock == INVALID_SOCKET) {
                kissnet_fatal_error("unable to create socket!");
            }
        }

        ///Construct a socket from an operating system socket, an additional endpoint to remember from where we are
        Socket(SOCKET native_sock, Endpoint bind_to) :
                mSock{native_sock}, mEndpoint(std::move(bind_to)) {
            KISSNET_OS_INIT;

            initialize_addrinfo();
        }

        ///Set the socket in non blocking mode
        /// \param lState By default "true". If put to false, it will set the socket back into blocking, normal mode
        void setNonBlocking(bool lState = true) const {
#ifdef _WIN32
            ioctl_setting set = lState ? 1 : 0;
            if (ioctlsocket(mSock, FIONBIO, &set) < 0)
#else
            const auto lFlags = fcntl(mSock, F_GETFL, 0);
            const auto lNewFlags = lState ? (lFlags | O_NONBLOCK) : (lFlags & ~O_NONBLOCK);
            if (fcntl(mSock, F_SETFL, lNewFlags) < 0)
#endif
                kissnet_fatal_error("setting socket to nonblock returned an Error");
        }

        ///Set the socket option for broadcasts
        /// \param lState By default "true". If put to false, it will disable broadcasts
        void setBroadcast(bool lState = true) const {
            const int lBroadcast = lState ? 1 : 0;
            if (setsockopt(mSock, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char *>(&lBroadcast),
                           sizeof(lBroadcast)) != 0)
                kissnet_fatal_error("setting socket lBroadcast mode returned an Error");
        }

        /// Set the socket option for TCPNoDelay
        /// \param lState By default "true". If put to false, it will disable TCPNoDelay
        void setTCPNoDelay(bool lState = true) const {
            if constexpr (sockProto == Protocol::TCP) {
                const int lTCPNoDelay = lState ? 1 : 0;
                if (setsockopt(mSock, SOL_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&lTCPNoDelay),
                               sizeof(lTCPNoDelay)) != 0)
                    kissnet_fatal_error("setting socket lTCPNoDelay mode returned an Error");
            }
        }

        /// Get socket status
        [[nodiscard]] SocketStatus::Codes getStatus() const {
            int lSocketError = 0;
            socklen_t lErrLen = sizeof(lSocketError);
            if (getsockopt(mSock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&lSocketError), &lErrLen) != 0)
                kissnet_fatal_error("getting socket Error returned an Error");

            return lSocketError == SOCKET_ERROR ? SocketStatus::Codes::ERRORED : SocketStatus::Codes::VALID;
        }

        ///Bind socket locally using the mAddress and mPort of the endpoint
        void bind() {
            if (syscallBind(mSock, static_cast<SOCKADDR *>(mSocketAddrinfo->ai_addr),
                            socklen_t(mSocketAddrinfo->ai_addrlen)) == SOCKET_ERROR) {
                kissnet_fatal_error("bind() failed\n");
            }
        }

        ///Join a multicast group
        void join(const Endpoint &rMultiCastEndPoint, const std::string &rLocalInterface = "") {
            if (sockProto != Protocol::UDP) {
                kissnet_fatal_error("joining a multicast is only possible in UDP mode\n");
            }

            addrinfo *pMulticastAddr;
            addrinfo *pLocalAddr;
            addrinfo lHints = {0};
            lHints.ai_family = PF_UNSPEC;
            lHints.ai_flags = AI_NUMERICHOST;
            if (getaddrinfo(rMultiCastEndPoint.address().c_str(), nullptr, &lHints, &pMulticastAddr) != 0) {
                kissnet_fatal_error("getaddrinfo() failed\n");
            }
            lHints.ai_family = pMulticastAddr->ai_family;
            lHints.ai_socktype = SOCK_DGRAM;
            lHints.ai_flags = AI_PASSIVE;
            if (getaddrinfo(nullptr, std::to_string(rMultiCastEndPoint.port()).c_str(), &lHints, &pLocalAddr) != 0) {
                kissnet_fatal_error("getaddrinfo() failed\n");
            }

            mSock = syscallSocket(pLocalAddr->ai_family, pLocalAddr->ai_socktype, pLocalAddr->ai_protocol);
            if (mSock != INVALID_SOCKET) {
                mSocketAddrinfo = pLocalAddr;
            } else {
                kissnet_fatal_error("syscallSocket() failed\n");
            }

            bind();

            //IPv4
            if (pMulticastAddr->ai_family == PF_INET && pMulticastAddr->ai_addrlen == sizeof(struct sockaddr_in)) {
                struct ip_mreq lMulticastRequest = {0};
                memcpy(&lMulticastRequest.imr_multiaddr,
                       &((struct sockaddr_in *) (pMulticastAddr->ai_addr))->sin_addr,
                       sizeof(lMulticastRequest.imr_multiaddr));
                if (rLocalInterface.length()) {
                    lMulticastRequest.imr_interface.s_addr = inet_addr(rLocalInterface.c_str());
                } else {
                    lMulticastRequest.imr_interface.s_addr = htonl(INADDR_ANY);
                }
                if (setsockopt(mSock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *) &lMulticastRequest,
                               sizeof(lMulticastRequest)) != 0) {
                    kissnet_fatal_error("setsockopt() failed\n");
                }
            }

                //IPv6
            else if (pMulticastAddr->ai_family == PF_INET6 &&
                     pMulticastAddr->ai_addrlen == sizeof(struct sockaddr_in6)) {
                struct ipv6_mreq lMulticastRequest = {0};
                memcpy(&lMulticastRequest.ipv6mr_multiaddr,
                       &((struct sockaddr_in6 *) (pMulticastAddr->ai_addr))->sin6_addr,
                       sizeof(lMulticastRequest.ipv6mr_multiaddr));
                if (rLocalInterface.length()) {
                    struct addrinfo *lResLocal;
                    if (getaddrinfo(rLocalInterface.c_str(), nullptr, nullptr, &lResLocal)) {
                        kissnet_fatal_error("getaddrinfo() failed\n");
                    }
                    lMulticastRequest.ipv6mr_interface = ((sockaddr_in6 *) lResLocal->ai_addr)->sin6_scope_id;
                    freeaddrinfo(lResLocal);
                } else {
                    lMulticastRequest.ipv6mr_interface = 0;
                }

                if (setsockopt(mSock, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char *) &lMulticastRequest,
                               sizeof(lMulticastRequest)) != 0) {
                    kissnet_fatal_error("setsockopt() failed\n");
                }
            } else {
                kissnet_fatal_error("unknown AI family.\n");
            }

            freeaddrinfo(pMulticastAddr);
        }

        ///(For TCP) connect to the endpoint as client
        SocketStatus::Codes connect(int64_t lTimeout = 0) {
            if constexpr (sockProto == Protocol::TCP) //only TCP is a connected Protocol
            {
                // try to connect to existing native socket, if any.
                auto lCurrAddr = mSocketAddrinfo;
                if (connect(lCurrAddr, lTimeout, false) != SocketStatus::VALID) {
                    // try to create/connect native socket for one of the other addrinfo, if any
                    for (auto *pAddr = mGetAddrinfoResults; pAddr; pAddr = pAddr->ai_next) {
                        if (pAddr == lCurrAddr)
                            continue; // already checked

                        if (connect(pAddr, lTimeout, true) == SocketStatus::VALID)
                            break; // success
                    }
                }

                if (mSock == INVALID_SOCKET)
                    kissnet_fatal_error("unable to create connectable socket!");

                return SocketStatus::Codes::VALID;
            }
#ifdef KISSNET_USE_OPENSSL
            else if constexpr (sockProto == Protocol::TCP_SSL) //only TCP is a connected Protocol
            {
                // try to connect to existing native socket, if any.
                auto lCurrAddr = mSocketAddrinfo;
                if (connect(lCurrAddr, lTimeout, false) != SocketStatus::VALID) {
                    // try to create/connect native socket for one of the other addrinfo, if any
                    for (auto *pAddr = mGetAddrinfoResults; pAddr; pAddr = pAddr->ai_next) {
                        if (pAddr == lCurrAddr)
                            continue; // already checked

                        if (connect(pAddr, lTimeout, true) == SocketStatus::VALID)
                            break; // success
                    }
                }

                if (mSock == INVALID_SOCKET)
                    kissnet_fatal_error("unable to create connectable socket!");

                auto *pMethod =
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
                        TLSv1_2_client_method();
#else
                        TLS_client_method();
#endif

                mContext = SSL_CTX_new(pMethod);
                mSSL = SSL_new(mContext);
                if (!mSSL)
                    return SocketStatus::ERRORED;

                if (!(static_cast<bool>(SSL_set_fd(mSSL, mSock))))
                    return SocketStatus::ERRORED;

                if (SSL_connect(mSSL) != 1)
                    return SocketStatus::ERRORED;

                return SocketStatus::VALID;
            }
#endif
            return {};
        }

        ///(for TCP= setup socket to listen to connection. Need to be called on binded socket, before being able to accept()
        void listen() {
            if constexpr (sockProto == Protocol::TCP) {
                if (syscallListen(mSock, SOMAXCONN) == SOCKET_ERROR) {
                    kissnet_fatal_error("listen failed\n");
                }
            }
        }

        ///(for TCP) Wait for incoming connection, return socket connect to the client. Blocking.
        Socket accept() {
            if constexpr (sockProto != Protocol::TCP) {
                return {INVALID_SOCKET, {}};
            }

            sockaddr_storage lSocketAddress = {0};
            SOCKET lSocket;
            socklen_t lSize = sizeof lSocketAddress;

            if ((lSocket = syscallAccept(mSock, reinterpret_cast<SOCKADDR *>(&lSocketAddress), &lSize)) ==
                INVALID_SOCKET) {
                const auto lError = getErrorCode();
                switch (lError) {
                    case EWOULDBLOCK: //if socket "would have blocked" from the call, ignore
                    case EINTR:          //if blocking call got interrupted, ignore;
                        return {};
                    default:;
                }

                kissnet_fatal_error("accept() returned an invalid socket\n");
            }

            return {lSocket, Endpoint(reinterpret_cast<SOCKADDR *>(&lSocketAddress))};
        }

        void close() {
            if (mSock != INVALID_SOCKET) {
#ifdef KISSNET_USE_OPENSSL
                if constexpr (sockProto == Protocol::TCP_SSL) {
                    if (mSSL) {
                        SSL_set_shutdown(mSSL, SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);
                        SSL_shutdown(mSSL);
                        SSL_free(mSSL);
                        if (mContext)
                            SSL_CTX_free(mContext);
                    }
                }
#endif
                closeSocket(mSock);
            }

            mSock = INVALID_SOCKET;
        }

        void shutdown() {
            if (mSock != INVALID_SOCKET) {
                syscallShutdown(mSock);
            }
        }

        ///Close socket on destruction
        ~Socket() {
            close();
            if (mGetAddrinfoResults) {
                freeaddrinfo(mGetAddrinfoResults);
            }
        }

        ///Select socket with lTimeout
        SocketStatus::Codes select(int lFds, int64_t lTimeout) {
            fd_set fd_read, fd_write, fd_except;

            struct timeval tv = {0};

            tv.tv_sec = static_cast<long>(lTimeout / 1000);
            tv.tv_usec = 1000 * static_cast<long>(lTimeout % 1000);

            if (lFds & fds_read) {
                FD_ZERO(&fd_read);
                FD_SET(mSock, &fd_read);
            }
            if (lFds & fds_write) {
                FD_ZERO(&fd_write);
                FD_SET(mSock, &fd_write);
            }
            if (lFds & fds_except) {
                FD_ZERO(&fd_except);
                FD_SET(mSock, &fd_except);
            }

            int lRet = syscallSelect(static_cast<int>(mSock) + 1,
                                     lFds & fds_read ? &fd_read : nullptr,
                                     lFds & fds_write ? &fd_write : nullptr,
                                     lFds & fds_except ? &fd_except : nullptr,
                                     &tv);
            if (lRet == -1)
                return SocketStatus::Codes::ERRORED;
            else if (lRet == 0)
                return SocketStatus::Codes::TIMED_OUT;
            return SocketStatus::Codes::VALID;
        }

        template<size_t buffSize>
        bytesWithStatus
        send(const Buffer<buffSize> &buff, const size_t length = buffSize, AddrCollection *addr = nullptr) {
            assert(buffSize >= length);
            return send(buff.data(), length, addr);
        }

        ///Send some bytes through the pipe
        bytesWithStatus send(const std::byte *pReadBuff, size_t lLength, AddrCollection *pAddr = nullptr) {
            auto lReceivedBytes{0};
            if constexpr (sockProto == Protocol::TCP) {
                lReceivedBytes = syscallSend(mSock, reinterpret_cast<const char *>(pReadBuff),
                                             static_cast<buffsize_t>(lLength), 0);
            }
#ifdef KISSNET_USE_OPENSSL
            else if constexpr (sockProto == Protocol::TCP_SSL) {
                lReceivedBytes = SSL_write(mSSL, reinterpret_cast<const char *>(pReadBuff),
                                           static_cast<buffsize_t>(lLength));
            }
#endif
            else if constexpr (sockProto == Protocol::UDP) {
                if (pAddr) {
                    lReceivedBytes = sendto(mSock, reinterpret_cast<const char *>(pReadBuff),
                                            static_cast<buffsize_t>(lLength), 0,
                                            reinterpret_cast<sockaddr *>(&pAddr->mAddrinf), pAddr->mSockSize);
                } else {
                    lReceivedBytes = sendto(mSock, reinterpret_cast<const char *>(pReadBuff),
                                            static_cast<buffsize_t>(lLength), 0,
                                            static_cast<SOCKADDR *>(mSocketAddrinfo->ai_addr),
                                            socklen_t(mSocketAddrinfo->ai_addrlen));
                }
            }

            if (lReceivedBytes < 0) {
                if (getErrorCode() == EWOULDBLOCK) {
                    return {0, SocketStatus::Codes::NON_BLOCKING_WOULD_HAVE_BLOCKED};
                }
                return {0, SocketStatus::Codes::ERRORED};
            }
            return {lReceivedBytes, SocketStatus::Codes::VALID};
        }

        ///receive bytes inside the Buffer, return the number of bytes you got. You can choose to write inside the Buffer at a specific start offset (in number of bytes)
        template<size_t buffSize>
        bytesWithStatus
        recv(Buffer<buffSize> &write_buff, size_t lStartOffset = 0, AddrCollection *pAddrInfo = nullptr) {
            auto lReceivedBytes = 0;
            if constexpr (sockProto == Protocol::TCP) {
                lReceivedBytes = syscallRecv(mSock, reinterpret_cast<char *>(write_buff.data()) + lStartOffset,
                                             static_cast<buffsize_t>(buffSize - lStartOffset), 0);
            }
#ifdef KISSNET_USE_OPENSSL
            else if constexpr (sockProto == Protocol::TCP_SSL) {
                lReceivedBytes = SSL_read(mSSL, reinterpret_cast<char *>(write_buff.data()) + lStartOffset,
                                          static_cast<buffsize_t>(buffSize - lStartOffset));
            }
#endif
            else if constexpr (sockProto == Protocol::UDP) {
                mSocketInputSocklen = sizeof mSocketInput;

                lReceivedBytes = ::recvfrom(mSock, reinterpret_cast<char *>(write_buff.data()) + lStartOffset,
                                            static_cast<buffsize_t>(buffSize - lStartOffset), 0,
                                            reinterpret_cast<sockaddr *>(&mSocketInput), &mSocketInputSocklen);
                if (pAddrInfo) {
                    pAddrInfo->mAddrinf = mSocketInput;
                    pAddrInfo->mSockSize = mSocketInputSocklen;
                }
            }

            if (lReceivedBytes < 0) {
                const auto error = getErrorCode();
                if (error == EWOULDBLOCK) {
                    return {0, SocketStatus::NON_BLOCKING_WOULD_HAVE_BLOCKED};
                } else if (error == EAGAIN) {
                    return {0, SocketStatus::NON_BLOCKING_WOULD_HAVE_BLOCKED};
                }
                return {0, SocketStatus::ERRORED};
            }
            if (lReceivedBytes == 0) {
                return {lReceivedBytes, SocketStatus::CLEANLY_DISCONNECTED};
            }
            return {size_t(lReceivedBytes), SocketStatus::VALID};
        }

        ///receive up-to lLen bytes inside the memory location pointed by pBuffer
        bytesWithStatus recv(std::byte *pBuffer, size_t lLen, bool lWait = true, AddrCollection *pAddrInfo = nullptr) {
            auto lReceivedBytes = 0;
            if constexpr (sockProto == Protocol::TCP) {
                int lFlags;
                if (lWait) {
                    lFlags = MSG_WAITALL;
                } else {
#ifdef _WIN32
                    lFlags = 0; // MSG_DONTWAIT not avail on windows, need to make socket nonblockingto emulate
                    set_non_blocking(true);
#else
                    lFlags = MSG_DONTWAIT;
#endif
                }
                lReceivedBytes = syscallRecv(mSock, reinterpret_cast<char *>(pBuffer), static_cast<buffsize_t>(lLen),
                                             lFlags);
#ifdef _WIN32
                set_non_blocking(false);
#endif
            }

#ifdef KISSNET_USE_OPENSSL
            else if constexpr (sockProto == Protocol::TCP_SSL) {
                lReceivedBytes = SSL_read(mSSL, reinterpret_cast<char *>(pBuffer), static_cast<int>(lLen));
            }
#endif

            else if constexpr (sockProto == Protocol::UDP) {
                mSocketInputSocklen = sizeof mSocketInput;

                lReceivedBytes = ::recvfrom(mSock, reinterpret_cast<char *>(pBuffer), static_cast<buffsize_t>(lLen), 0,
                                            reinterpret_cast<sockaddr *>(&mSocketInput), &mSocketInputSocklen);
                if (pAddrInfo) {
                    pAddrInfo->mAddrinf = mSocketInput;
                    pAddrInfo->mSockSize = mSocketInputSocklen;
                }
            }

            if (lReceivedBytes < 0) {
                const auto lError = getErrorCode();
                if (lError == EWOULDBLOCK)
                    return {0, SocketStatus::NON_BLOCKING_WOULD_HAVE_BLOCKED};
                if (lError == EAGAIN)
                    return {0, SocketStatus::NON_BLOCKING_WOULD_HAVE_BLOCKED};
                return {0, SocketStatus::ERRORED};
            }

            if (lReceivedBytes == 0) {
                return {lReceivedBytes, SocketStatus::CLEANLY_DISCONNECTED};
            }

            return {size_t(lReceivedBytes), SocketStatus::VALID};
        }

        ///Return the endpoint where this socket is talking to
        Endpoint getBindLoc() const {
            return mEndpoint;
        }

        ///Return an endpoint that originated the data in the last recv
        [[nodiscard]] Endpoint getRecvEndpoint() const {
            if constexpr (sockProto == Protocol::TCP) {
                return getBindLoc();
            }
            if constexpr (sockProto == Protocol::UDP) {
                return {Endpoint((sockaddr *) &mSocketInput)};
            }
            return {};
        }

        ///Return the number of bytes available inside the socket
        [[nodiscard]] size_t bytes_available() const {
            static ioctl_setting lSize = 0;
            const auto lStatus = ioctlSocket(mSock, FIONREAD, &lSize);

            if (lStatus < 0) {
                kissnet_fatal_error("ioctlsocket lStatus is negative when getting FIONREAD\n");
            }
            return lSize > 0 ? lSize : 0;
        }

        ///Return the Protocol used by this socket
        static Protocol getProtocol() {
            return sockProto;
        }
    };

    ///Alias for socket<Protocol::TCP>
    using TCPSocket = Socket<Protocol::TCP>;
#ifdef KISSNET_USE_OPENSSL
    ///Alias for socket<Protocol::TCP_SSL>
    using TCPSSLSocket = Socket<Protocol::TCP_SSL>;
#endif //KISSNET_USE_OPENSSL
    ///Alias for socket<Protocol::UDP>
    using UDPSocket = Socket<Protocol::UDP>;
}

//cleanup preprocessor macros
#undef KISSNET_OS_SPECIFIC_PAYLOAD_NAME
#undef KISSNET_OS_SPECIFIC
#undef KISSNET_OS_INIT
#undef kissnet_fatal_error

#endif //KISS_NET
