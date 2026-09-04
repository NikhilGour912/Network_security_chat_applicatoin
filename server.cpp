
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

static std::string hex_of(const unsigned char *p, size_t n) {
    std::ostringstream o;
    for (size_t i=0;i<n;i++) o << std::hex << std::setw(2) << std::setfill('0') << (int)p[i];
    return o.str();
}
static std::vector<unsigned char> unhex(const std::string &s) {
    std::vector<unsigned char> out;
    if (s.size()%2) return {};
    for(size_t i=0;i<s.size();i+=2) out.push_back((unsigned char)std::stoul(s.substr(i,2),nullptr,16));
    return out;
}
static std::string b64(const unsigned char *p, int n) {
    std::string out(4*((n+2)/3), '\0');
    int m=EVP_EncodeBlock((unsigned char*)out.data(),p,n);
    out.resize(m); return out;
}
static std::vector<unsigned char> unb64(const std::string &s) {
    std::vector<unsigned char> out((s.size()*3)/4+4);
    int n=EVP_DecodeBlock(out.data(),(const unsigned char*)s.data(),(int)s.size());
    if(n<0) return {};
    int pad=0; if(!s.empty()&&s.back()=='=') pad++; if(s.size()>1&&s[s.size()-2]=='=') pad++;
    out.resize(n-pad); return out;
}
static std::string recv_line(int fd, size_t maxlen=1024*1024) {
    std::string s; char c;
    while(s.size()<maxlen) {
        ssize_t n=recv(fd,&c,1,0);
        if(n<=0) return {};
        if(c=='\n') return s;
        s.push_back(c);
    }
    return {};
}
static bool send_all(int fd,const std::string &s) {
    size_t off=0; while(off<s.size()) {
        ssize_t n=send(fd,s.data()+off,s.size()-off,MSG_NOSIGNAL);
        if(n<=0) return false; off+=n;
    }
    return true;
}
static BIGNUM *bn_from_hex(const char *s) { BIGNUM *x=nullptr; BN_hex2bn(&x,s); return x; }

static bool dh_make(BIGNUM *p, BIGNUM *g, BIGNUM **priv, BIGNUM **pub) {
    *priv=BN_new(); *pub=BN_new(); BN_CTX *ctx=BN_CTX_new();
    if(!*priv||!*pub||!ctx) return false;
    if(!BN_priv_rand(*priv,BN_num_bits(p)-1,BN_RAND_TOP_TWO,BN_RAND_BOTTOM_ANY)) return false;
    if(!BN_mod_exp(*pub,g,*priv,p,ctx)) return false;
    BN_CTX_free(ctx); return true;
}
static BIGNUM *dh_shared(const BIGNUM *peer,const BIGNUM *priv,const BIGNUM *p) {
    BIGNUM *s=BN_new(); BN_CTX *ctx=BN_CTX_new();
    if(!s||!ctx) { BN_free(s); BN_CTX_free(ctx); return nullptr; }
    if(!BN_mod_exp(s,peer,priv,p,ctx)) { BN_free(s); s=nullptr; }
    BN_CTX_free(ctx); return s;
}
static std::vector<unsigned char> derive_key(const BIGNUM *secret) {
    int n=BN_num_bytes(secret); std::vector<unsigned char> raw(n);
    BN_bn2bin(secret,raw.data());
    unsigned char h[SHA256_DIGEST_LENGTH]; SHA256(raw.data(),raw.size(),h);
    return std::vector<unsigned char>(h,h+32);
}
static std::string fingerprint(const std::vector<unsigned char>& key) {
    unsigned char h[SHA256_DIGEST_LENGTH]; SHA256(key.data(),key.size(),h);
    return hex_of(h,32);
}
static std::string gcm_encrypt(const std::vector<unsigned char>& key,const std::string& plain) {
    unsigned char nonce[12]; if(RAND_bytes(nonce,12)!=1) return {};
    EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new(); if(!c) return {};
    std::vector<unsigned char> ct(plain.size()+16); int l1=0,l2=0;
    bool ok=EVP_EncryptInit_ex(c,EVP_aes_256_gcm(),nullptr,nullptr,nullptr)==1;
    ok=ok&&EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,12,nullptr)==1;
    ok=ok&&EVP_EncryptInit_ex(c,nullptr,nullptr,key.data(),nonce)==1;
    ok=ok&&EVP_EncryptUpdate(c,ct.data(),&l1,(const unsigned char*)plain.data(),(int)plain.size())==1;
    ok=ok&&EVP_EncryptFinal_ex(c,ct.data()+l1,&l2)==1;
    unsigned char tag[16]; ok=ok&&EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,16,tag)==1;
    EVP_CIPHER_CTX_free(c); if(!ok) return {};
    std::vector<unsigned char> wire(nonce,nonce+12);
    wire.insert(wire.end(),ct.begin(),ct.begin()+l1+l2); wire.insert(wire.end(),tag,tag+16);
    return "ENC|"+b64(wire.data(),(int)wire.size());
}
static bool gcm_decrypt(const std::vector<unsigned char>& key,const std::string& msg,std::string& plain) {
    if(msg.rfind("ENC|",0)!=0) return false;
    auto w=unb64(msg.substr(4)); if(w.size()<28) return false;
    const unsigned char *nonce=w.data(), *tag=w.data()+w.size()-16, *ct=w.data()+12;
    int ctlen=(int)w.size()-28, l1=0,l2=0; std::vector<unsigned char> pt(ctlen+1);
    EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new(); if(!c) return false;
    bool ok=EVP_DecryptInit_ex(c,EVP_aes_256_gcm(),nullptr,nullptr,nullptr)==1;
    ok=ok&&EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,12,nullptr)==1;
    ok=ok&&EVP_DecryptInit_ex(c,nullptr,nullptr,key.data(),nonce)==1;
    ok=ok&&EVP_DecryptUpdate(c,pt.data(),&l1,ct,ctlen)==1;
    ok=ok&&EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,16,(void*)tag)==1;
    ok=ok&&EVP_DecryptFinal_ex(c,pt.data()+l1,&l2)==1;
    EVP_CIPHER_CTX_free(c); if(!ok) return false;
    plain.assign((char*)pt.data(),l1+l2); return true;
}
static void free_bn(BIGNUM *&x){ BN_free(x); x=nullptr; }

struct Client { int fd; std::string user; std::vector<unsigned char> key; std::mutex send_m; std::mutex data_m; bool active=true; };
static std::vector<Client*> clients; static std::mutex cm;
static Client* find_user(const std::string& u){std::lock_guard<std::mutex>lk(cm);for(auto*c:clients)if(c->active&&c->user==u)return c;return nullptr;}
static bool safe_send(Client*c,const std::string&s){std::lock_guard<std::mutex>lk(c->send_m);return send_all(c->fd,s+"\n");}
static void remove_client(Client*c){std::lock_guard<std::mutex>lk(cm);c->active=false;clients.erase(std::remove(clients.begin(),clients.end(),c),clients.end());}
static std::string users(){std::lock_guard<std::mutex>lk(cm);std::string s;for(auto*c:clients){if(!s.empty())s+=',';s+=c->user;}return s;}
static void handle(Client*c){
    BIGNUM *p=bn_from_hex(GROUP14_P),*g=BN_new(),*priv=nullptr,*pub=nullptr,*peer=nullptr,*secret=nullptr; BN_set_word(g,2);
    dh_make(p,g,&priv,&pub);
    if(!safe_send(c,"DH_P|"+std::string(GROUP14_P))||!safe_send(c,"DH_G|2")) goto cleanup;
    {std::string w=recv_line(c->fd); if(w.rfind("DH_PUB|",0)!=0)goto cleanup; peer=bn_from_hex(w.substr(7).c_str());}
    if(BN_cmp(peer,BN_value_one())<=0||BN_cmp(peer,p)>=0)goto cleanup;
    if(!safe_send(c,"DH_PUB|"+std::string(BN_bn2hex(pub))))goto cleanup;
    secret=dh_shared(peer,priv,p); if(!secret)goto cleanup;
    c->key=derive_key(secret);
    std::cout<<"[DH] "<<c->user<<" fingerprint: "<<fingerprint(c->key)<<"\n";
    {std::string w=recv_line(c->fd);if(w!="DH_OK")goto cleanup;}
    {
        std::string w=recv_line(c->fd),plain;
        if(!gcm_decrypt(c->key,w,plain)||plain.rfind("LOGIN|",0)!=0)goto cleanup;
        std::string name=plain.substr(6);
        if(name.empty())goto cleanup;
        {std::lock_guard<std::mutex>lk(cm);for(auto*x:clients)if(x!=c&&x->active&&x->user==name){goto cleanup;}c->user=name;}
    }
    std::cout<<"[LOGIN] "<<c->user<<"\n"; safe_send(c,gcm_encrypt(c->key,"OK|LOGIN") );
    while(c->active){
        std::string w=recv_line(c->fd); if(w.empty())break; std::string plain;
        if(!gcm_decrypt(c->key,w,plain)){std::cerr<<"[SECURITY] "<<c->user<<" sent invalid/tampered ciphertext; discarded\n";continue;}
        if(plain=="WHO"){safe_send(c,gcm_encrypt(c->key,"USERS|"+users()));}
        else if(plain=="QUIT"){safe_send(c,gcm_encrypt(c->key,"BYE"));break;}
        else if(plain.rfind("MSG|",0)==0){
            size_t a=plain.find('|',4),b=a==std::string::npos?std::string::npos:plain.find('|',a+1);
            if(a==std::string::npos||b==std::string::npos)continue;
            std::string to=plain.substr(4,a-4),text=plain.substr(b+1);
            Client* d=find_user(to);
            if(!d){safe_send(c,gcm_encrypt(c->key,"ERROR|user not online"));continue;}
            std::cout<<"[RELAY "<<c->user<<" -> "<<to<<"] "<<text<<"\n";
            safe_send(d,gcm_encrypt(d->key,"FROM|"+c->user+"|"+text));
        }
    }
cleanup:
    if(c->user.empty()==false)std::cout<<"[DISCONNECT] "<<c->user<<"\n";
    remove_client(c); shutdown(c->fd,SHUT_RDWR); close(c->fd);
    free_bn(p);free_bn(g);free_bn(priv);free_bn(pub);free_bn(peer);free_bn(secret); delete c;
}
int main(int argc,char**argv){
    int port=argc>1?std::stoi(argv[1]):5000; int s=socket(AF_INET,SOCK_STREAM,0); if(s<0){perror("socket");return 1;}
    int one=1;setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));sockaddr_in a{};a.sin_family=AF_INET;a.sin_addr.s_addr=INADDR_ANY;a.sin_port=htons(port);
    if(bind(s,(sockaddr*)&a,sizeof(a))<0){perror("bind");return 1;}if(listen(s,2)<0){perror("listen");return 1;}
    std::cout<<"Server listening on port "<<port<<"\n";
    while(true){sockaddr_in ca{};socklen_t n=sizeof(ca);int fd=accept(s,(sockaddr*)&ca,&n);if(fd<0)continue;
        {std::lock_guard<std::mutex>lk(cm);if(clients.size()>=2){send_all(fd,"SERVER_FULL\n");close(fd);continue;}}
        auto*c=new Client{fd};{std::lock_guard<std::mutex>lk(cm);clients.push_back(c);}std::thread(handle,c).detach();
    }
    close(s);
}
