/* lzf: (C) 2011 Ian Babrou <ibobrik@gmail.com>  */

// TODO: joinProxyThread -- atexit is too late. maybe there is some libuv hook we can ask?
// TODO: port to node12

// TODO: implement abortProxy for abort (fish it out of the thread queue).

// wfutil
#include <node_version.h>
#include <node_buffer.h>
#include <stdlib.h>
#include <iostream>
#include <iomanip>
#include <stdio.h>
#include <string.h>

#ifdef __APPLE__
#include <malloc/malloc.h>
#endif

#ifdef __linux__
#define ENABLE_PROXY
#include <arpa/inet.h>
#include <uv.h>
#endif

#ifdef _WIN32
#include <Winsock2.h>
#endif

#include "lzf/lzf.h"
#include "crc32/crc32.h"
#include "whirlpool/whirlpool.h"

#define StaticAssert(pred) switch(0){case 0:case pred:;}

#ifdef ENABLE_PROXY

#define ENABLE_ASYNC_PROXY
#define COALESCE_PROXY_OPERATION

//#pragma GCC diagnostic push
//#pragma GCC diagnostic ignored "-fpermissive"
//#pragma GCC diagnostic ignored "-pedantic"
#include <libiptc/libiptc.h>
//#pragma GCC diagnostic pop

#include <errno.h>
#include <time.h>

#include <linux/version.h>

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,13,0)
#define OLD_NETFILTER
#endif

#ifdef OLD_NETFILTER
#include <linux/netfilter_ipv4/nf_nat.h>
#else
//Ubuntu 18 workaround: headers have multiple definition of enum ip_conntrack_status
#define _NF_CONNTRACK_COMMON_H
#include <linux/netfilter/nf_nat.h>
#endif

#include <linux/netfilter/xt_tcpudp.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#endif

using namespace v8;
using namespace node;

typedef unsigned char uint8;
typedef unsigned short uint16;
#define ARRAY_COUNT(a)  (sizeof(a) / sizeof(a[0]))

static uint32 GetVarIntLZF(const uint8* src, uint32& csize);

// Note arguments reordered for structure packing
struct ProxySpec
{
    in_addr aAddr;
    in_addr bAddr;
    in_addr nAddr;
    uint16_t aPort;
    uint16_t bPort;
    uint16_t anPort;
    uint16_t bnPort;
};

std::ostream& operator<<(std::ostream& s, const ProxySpec& p)
{
    s << "(" << inet_ntoa(p.aAddr) << ":" << p.aPort;
    s << ", " << inet_ntoa(p.bAddr) << ":" << p.bPort;
    s << ", " << inet_ntoa(p.nAddr);
    s << ", " << p.anPort << ", " << p.bnPort << ")";
    return(s);
}

#if defined(ENABLE_PROXY) && defined(ENABLE_ASYNC_PROXY)
struct AsyncProxy;
struct AsyncProxy
{
    AsyncProxy() :
        add(false),
        result(false),
        next(NULL)
    {
        async.data = NULL;
    }

    ProxySpec spec;
    bool add; // or delete
    bool result;
    Persistent<Function> callback;
    uv_async_t async;
    timespec submitted;
    AsyncProxy* volatile next;
};
#endif // defined(ENABLE_PROXY) && defined(ENABLE_ASYNC_PROXY)

#ifndef ENABLE_PROXY
static bool flushProxies()
{
    std::cout << "flushProxies() not enabled\n";
    return(false);
}
static bool createProxy(const ProxySpec& proxy)
{
    std::cout << "createProxy" << proxy << " not enabled\n";
    return(false);
}
static bool abortProxy(const ProxySpec& proxy)
{
    std::cout << "abortProxy" << proxy << " not enabled\n";
    return(false);
}
static bool deleteProxy(const ProxySpec& proxy)
{
    std::cout << "deleteProxy" << proxy << " not enabled\n";
    return(false);
}
#else // ENABLE_PROXY

#pragma pack(push, 8) // __alignof__(struct _xt_align)
struct NatEntry
{
    ipt_entry entry;
    xt_entry_match match;
    xt_udp udp;
    // xt_standard_target target; for basic operations like ACCEPT/DROP
    xt_entry_target target;
#ifdef OLD_NETFILTER
    nf_nat_multi_range_compat nat;
#else
    nf_nat_ipv4_multi_range_compat nat;
#endif
};
#pragma pack(pop)

// Recycled to avoid initialization overhead
static NatEntry sDnatEntry;
static NatEntry sSnatEntry;
static unsigned char sMatchMask[sizeof(NatEntry)];

static void initNatEntry(NatEntry& e, const char* targetName)
{
    e.target.u.user.target_size = XT_ALIGN(sizeof(e.target)) + XT_ALIGN(sizeof(e.nat));
    strncpy(e.target.u.user.name, targetName, sizeof(e.target.u.user.name));

    e.entry.target_offset = offsetof(NatEntry, target);
    e.entry.next_offset = e.entry.target_offset + e.target.u.user.target_size;

    e.entry.ip.proto = IPPROTO_UDP;
    e.entry.ip.smsk.s_addr = 0xFFFFFFFF;
    e.entry.ip.dmsk.s_addr = 0xFFFFFFFF;

    e.match.u.match_size = XT_ALIGN(sizeof(e.match)) + XT_ALIGN(sizeof(e.udp));
    strncpy(e.match.u.user.name, "udp", sizeof(e.match.u.user.name));

    e.nat.rangesize = 1;

#ifdef OLD_NETFILTER
    e.nat.range[0].flags = IP_NAT_RANGE_MAP_IPS | IP_NAT_RANGE_PROTO_SPECIFIED;
#else
    e.nat.range[0].flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
#endif
}

static void initProxy()
{
    // Make sure that our payload will meet all of the alignment requirements
    StaticAssert(offsetof(NatEntry, match) == XT_ALIGN(offsetof(NatEntry, match)));
    StaticAssert(offsetof(NatEntry, match) == XT_ALIGN(offsetof(NatEntry, match)));
    StaticAssert(offsetof(NatEntry, match) + offsetof(xt_entry_match, data) == XT_ALIGN(offsetof(NatEntry, udp)));
    StaticAssert(offsetof(NatEntry, target) == XT_ALIGN(offsetof(NatEntry, target)));
    StaticAssert(offsetof(NatEntry, target) + offsetof(xt_entry_target, data) == XT_ALIGN(offsetof(NatEntry, nat)));
    StaticAssert(offsetof(NatEntry, nat) == XT_ALIGN(offsetof(NatEntry, nat)));

    initNatEntry(sDnatEntry, "DNAT");
    initNatEntry(sSnatEntry, "SNAT");

    memset(sMatchMask, 255, sizeof(sMatchMask));
}

static void setNatRule(NatEntry& e, const in_addr& s, uint16_t sport, const in_addr& d, uint16_t dport, const in_addr& to, uint16_t toport)
{
    e.entry.ip.src = s;
    e.udp.spts[0] = sport;
    e.udp.spts[1] = sport;

    e.entry.ip.dst = d;
    e.udp.dpts[0] = dport;
    e.udp.dpts[1] = dport;

    e.nat.range[0].min_ip = to.s_addr;
    e.nat.range[0].max_ip = to.s_addr;

    __be16 toport16 = htons(toport);
    e.nat.range[0].min.udp.port = toport16;
    e.nat.range[0].max.udp.port = toport16;
}

static bool flushProxies()
{
    xtc_handle* h = iptc_init("nat");

    if(!h)
    {
        std::cerr << "iptc_init: " << iptc_strerror(errno) << "\n";
        return(false);
    }

    bool rc = true;

    if
    (
        !iptc_flush_entries("INPUT", h) ||
        !iptc_flush_entries("OUTPUT", h) ||
        !iptc_flush_entries("PREROUTING", h) ||
        !iptc_flush_entries("POSTROUTING", h)
    )
    {
        std::cerr << "iptc_flush_entries: " << iptc_strerror(errno) << "\n";
        rc = false;
    }
    else if(!iptc_commit(h))
    {
        std::cerr << "iptc_commit: " << iptc_strerror(errno) << "\n";
        rc = false;
    }

    iptc_free(h);

    if(!rc)
    {
        return(false);
    }

    nfct_handle* ct = nfct_open(CONNTRACK, 0);

    if(!ct)
    {
        std::cerr << "nfct_open: " << strerror(errno) << "\n";
        return(false);
    }

    u_int8_t family = AF_INET;

    if(nfct_query(ct, NFCT_Q_FLUSH, &family) && (errno != ENOENT))
    {
        std::cerr << "nfct_query: " << strerror(errno) << "\n";
        rc = false;
    }

    nfct_close(ct);

    return(rc);
}

#ifdef COALESCE_PROXY_OPERATION
static void failProxyList(AsyncProxy* first)
{
    for(AsyncProxy* it = first; it; it = it->next)
    {
        it->result = false;
    }
}

static void flushProxyState(AsyncProxy* first)
{
    // TODO: hang onto these?
    nf_conntrack* cta = nfct_new();
    nf_conntrack* ctb = nfct_new();

    if(!cta || !ctb)
    {
        std::cerr << "nfct_new: " << strerror(errno) << "\n";
        // TODO: handle leaks
        failProxyList(first);
        return;
    }

    nfct_handle* h = nfct_open(CONNTRACK, 0);

    if(!h)
    {
        std::cerr << "nfct_open: " << strerror(errno) << "\n";
        failProxyList(first);
    }
    else
    {
        nfct_set_attr_u8(cta, ATTR_L3PROTO, AF_INET);
        nfct_set_attr_u8(ctb, ATTR_L3PROTO, AF_INET);
        nfct_set_attr_u8(cta, ATTR_L4PROTO, IPPROTO_UDP);
        nfct_set_attr_u8(ctb, ATTR_L4PROTO, IPPROTO_UDP);

        for(AsyncProxy* it = first; it; it = it->next)
        {
            if(!it->result)
            {
                continue; 
            }

            const ProxySpec& proxy = it->spec;
            
            nfct_set_attr_u32(cta, ATTR_IPV4_SRC, proxy.aAddr.s_addr);
            nfct_set_attr_u32(cta, ATTR_IPV4_DST, proxy.nAddr.s_addr);
            nfct_set_attr_u16(cta, ATTR_PORT_SRC, htons(proxy.aPort));
            nfct_set_attr_u16(cta, ATTR_PORT_DST, htons(proxy.bnPort));

            nfct_set_attr_u32(ctb, ATTR_IPV4_SRC, proxy.bAddr.s_addr);
            nfct_set_attr_u32(ctb, ATTR_IPV4_DST, proxy.nAddr.s_addr);
            
            nfct_set_attr_u16(ctb, ATTR_PORT_SRC, htons(proxy.bPort));
            nfct_set_attr_u16(ctb, ATTR_PORT_DST, htons(proxy.anPort));

            if
            (
                // ENOENT is returned if no connections match
                (nfct_query(h, NFCT_Q_DESTROY, cta) && (errno != ENOENT)) ||
                (nfct_query(h, NFCT_Q_DESTROY, ctb) && (errno != ENOENT))
            )
            {
                std::cerr << "nfct_query: " << strerror(errno) << "\n";
                it->result = false;
            }
            else
            {
                it->result = true;
            }
        }

        nfct_close(h);
    }

    nfct_destroy(ctb);
    nfct_destroy(cta);
}

#else // !COALESCE_PROXY_OPERATION

// NOTE: the original code was much more thorough:
// conntrack -D -p udp -d $nAddr --dport $anPort > /dev/null 2>&1
// conntrack -D -p udp -d $nAddr --dport $bnPort > /dev/null 2>&1
// IE: It would flush just about anything involved with the proxy ports.
//
// Sadly NFCT_Q_DESTROY does not accept wildcards; the way conntrack is implemented it actually
// scans the whole table which is probably very slow as the table size increases.
//
// The current code here deletes only the exact mappings that we intended; this is probably fine
// because as far as I can tell even after we delete the rules and state stray packets from
// a disconnecting host will still pop up in the table afterwards -- ie: overzealous flushing
// my not be necessary.

static bool flushProxyState(const ProxySpec& proxy)
{
    nf_conntrack* cta = nfct_new();
    nf_conntrack* ctb = nfct_new();

    if(!cta || !ctb)
    {
        std::cerr << "nfct_new: " << strerror(errno) << "\n";
        // TODO: handle leaks
        return(false);
    }

    nfct_set_attr_u8(cta, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u32(cta, ATTR_IPV4_SRC, proxy.aAddr.s_addr);
    nfct_set_attr_u32(cta, ATTR_IPV4_DST, proxy.nAddr.s_addr);
    
    nfct_set_attr_u8(cta, ATTR_L4PROTO, IPPROTO_UDP);
    nfct_set_attr_u16(cta, ATTR_PORT_SRC, htons(proxy.aPort));
    nfct_set_attr_u16(cta, ATTR_PORT_DST, htons(proxy.bnPort));

    nfct_set_attr_u8(ctb, ATTR_L3PROTO, AF_INET);
    nfct_set_attr_u32(ctb, ATTR_IPV4_SRC, proxy.bAddr.s_addr);
    nfct_set_attr_u32(ctb, ATTR_IPV4_DST, proxy.nAddr.s_addr);
    
    nfct_set_attr_u8(ctb, ATTR_L4PROTO, IPPROTO_UDP);
    nfct_set_attr_u16(ctb, ATTR_PORT_SRC, htons(proxy.bPort));
    nfct_set_attr_u16(ctb, ATTR_PORT_DST, htons(proxy.anPort));

    nfct_handle* h = nfct_open(CONNTRACK, 0);

    bool rc = false;

    if(!h)
    {
        std::cerr << "nfct_open: " << strerror(errno) << "\n";
    }
    else if
    (
        // ENOENT is returned if no connections match
        (nfct_query(h, NFCT_Q_DESTROY, cta) && (errno != ENOENT)) ||
        (nfct_query(h, NFCT_Q_DESTROY, ctb) && (errno != ENOENT))
    )
    {
        std::cerr << "nfct_query: " << strerror(errno) << "\n";
    }
    else
    {
        rc = true;
    }

    nfct_close(h);
    nfct_destroy(ctb);
    nfct_destroy(cta);

    return(rc);
}
#endif // COALESCE_PROXY_OPERATION

static bool addProxyRules(xtc_handle* h, const ProxySpec& proxy)
{
    setNatRule(sDnatEntry, proxy.aAddr, proxy.aPort, proxy.nAddr, proxy.bnPort, proxy.bAddr, proxy.bPort);
    
    if(!iptc_insert_entry("PREROUTING", &sDnatEntry.entry, 0, h))
    {
        std::cerr << "iptc_insert_entry: " << iptc_strerror(errno) << "\n";
        return(false);
    }

    setNatRule(sDnatEntry, proxy.bAddr, proxy.bPort, proxy.nAddr, proxy.anPort, proxy.aAddr, proxy.aPort);
    
    if(!iptc_insert_entry("PREROUTING", &sDnatEntry.entry, 0, h))
    {
        std::cerr << "iptc_insert_entry: " << iptc_strerror(errno) << "\n";
        return(false);
    }

    setNatRule(sSnatEntry, proxy.aAddr, proxy.aPort, proxy.bAddr, proxy.bPort, proxy.nAddr, proxy.anPort);
    
    if(!iptc_append_entry("POSTROUTING", &sSnatEntry.entry, h))
    {
        std::cerr << "iptc_append_entry: " << iptc_strerror(errno) << "\n";
        return(false);
    }

    setNatRule(sSnatEntry, proxy.bAddr, proxy.bPort, proxy.aAddr, proxy.aPort, proxy.nAddr, proxy.bnPort);
    
    if(!iptc_append_entry("POSTROUTING", &sSnatEntry.entry, h))
    {
        std::cerr << "iptc_append_entry: " << iptc_strerror(errno) << "\n";
        return(false);
    }

    return(true);
}

static bool deleteProxyRules(xtc_handle* h, const ProxySpec& proxy)
{
    setNatRule(sDnatEntry, proxy.aAddr, proxy.aPort, proxy.nAddr, proxy.bnPort, proxy.bAddr, proxy.bPort);
    
    if(!iptc_delete_entry("PREROUTING", &sDnatEntry.entry, sMatchMask, h))
    {
        std::cerr << "iptc_delete_entry: " << iptc_strerror(errno) << "\n";
        return(false);
    }

    setNatRule(sDnatEntry, proxy.bAddr, proxy.bPort, proxy.nAddr, proxy.anPort, proxy.aAddr, proxy.aPort);
    
    if(!iptc_delete_entry("PREROUTING", &sDnatEntry.entry, sMatchMask, h))
    {
        std::cerr << "iptc_delete_entry: " << iptc_strerror(errno) << "\n";
        return(false);
    }

    setNatRule(sSnatEntry, proxy.aAddr, proxy.aPort, proxy.bAddr, proxy.bPort, proxy.nAddr, proxy.anPort);
    
    if(!iptc_delete_entry("POSTROUTING", &sSnatEntry.entry, sMatchMask, h))
    {
        std::cerr << "iptc_delete_entry: " << iptc_strerror(errno) << "\n";
        return(false);
    }

    setNatRule(sSnatEntry, proxy.bAddr, proxy.bPort, proxy.aAddr, proxy.aPort, proxy.nAddr, proxy.bnPort);
    
    if(!iptc_delete_entry("POSTROUTING", &sSnatEntry.entry, sMatchMask, h))
    {
        std::cerr << "iptc_delete_entry: " << iptc_strerror(errno) << "\n";
        return(false);
    }

    return(true);
}

#ifndef ENABLE_ASYNC_PROXY
// :PREROUTING - [0:0]
// -I PREROUTING -p udp -s $aAddr --sport $aPort -d $nAddr --dport $bnPort -j DNAT --to $bAddr:$bPort
// -I PREROUTING -p udp -s $bAddr --sport $bPort -d $nAddr --dport $anPort -j DNAT --to $aAddr:$aPort
// :POSTROUTING - [0:0]
// -A POSTROUTING -p udp -s $aAddr --sport $aPort -d $bAddr --dport $bPort -j SNAT --to $nAddr:$anPort
// -A POSTROUTING -p udp -s $bAddr --sport $bPort -d $aAddr --dport $aPort -j SNAT --to $nAddr:$bnPort

static bool createProxy(const ProxySpec& proxy)
{
    xtc_handle* h = iptc_init("nat");

    if(!h)
    {
        std::cerr << "iptc_init: " << iptc_strerror(errno) << "\n";
        return(false);
    }

    bool rc = true;
        
    if(!addProxyRules(h, proxy))
    {
        rc = false;
    }
    else if(!iptc_commit(h))
    {
        std::cerr << "iptc_commit: " << iptc_strerror(errno) << "\n";
        rc = false;
    }

    iptc_free(h);

    if(rc)
    {
        rc = flushProxyState(proxy);
    }

    return(rc);
}

static bool abortProxy(const ProxySpec&)
{
    return(false); // Not supported if sync
}

static bool deleteProxy(const ProxySpec& proxy)
{
    xtc_handle* h = iptc_init("nat");

    if(!h)
    {
        std::cerr << "iptc_init: " << iptc_strerror(errno) << "\n";
        return(false);
    }

    bool rc = true;
        
    if(!deleteProxyRules(h, proxy))
    {
        rc = false;
    }
    else if(!iptc_commit(h))
    {
        std::cerr << "iptc_commit: " << iptc_strerror(errno) << "\n";
        rc = false;
    }

    iptc_free(h);

    if(rc)
    {
        rc = flushProxyState(proxy);
    }

    return(rc);
}
#else // ENABLE_ASYNC_PROXY

#define READWRITE_BARRIER() asm volatile("" ::: "memory")

class AsyncProxyQueue
{
public:
    AsyncProxyQueue() :
        mBegin(NULL),
        mEnd(NULL)
    {
        uv_mutex_init(&mMutex);
        uv_sem_init(&mPending, 0);
    }

    ~AsyncProxyQueue()
    {
        uv_sem_destroy(&mPending);
        uv_mutex_destroy(&mMutex);
    }

    void push(AsyncProxy* p)
    {
        uv_mutex_lock(&mMutex); 
        READWRITE_BARRIER();

        p->next = NULL;

        if(mEnd)
        {
            mEnd->next = p;
        }
        else
        {
            mBegin = p;
        }

        mEnd = p;

        READWRITE_BARRIER();
        uv_mutex_unlock(&mMutex); 

        uv_sem_post(&mPending);
    }

    AsyncProxy* pop()
    {
        AsyncProxy* next;

        uv_sem_wait(&mPending);

        uv_mutex_lock(&mMutex); 
        READWRITE_BARRIER();

        next = mBegin;

        mBegin = next->next;

        if(!mBegin)
        {
            mEnd = NULL;
        }

        READWRITE_BARRIER();
        uv_mutex_unlock(&mMutex); 

        return(next);
    }

    AsyncProxy* tryPop()
    {
        AsyncProxy* next;

        if(uv_sem_trywait(&mPending))
        {
            return(NULL);
        }

        uv_mutex_lock(&mMutex); 
        READWRITE_BARRIER();

        next = mBegin;

        mBegin = next->next;

        if(!mBegin)
        {
            mEnd = NULL;
        }

        READWRITE_BARRIER();
        uv_mutex_unlock(&mMutex); 

        return(next);
    }

private:
    uv_sem_t mPending;
    uv_mutex_t mMutex;

    AsyncProxy* volatile mBegin;
    AsyncProxy* volatile mEnd;
};

static uv_thread_t sProxyThread;
static AsyncProxyQueue sProxyQueue;

static void deleteAsyncProxy(uv_handle_t* req)
{
    AsyncProxy* ap = reinterpret_cast<AsyncProxy*>(req->data);
    delete ap;
}

#if NODE_MAJOR_VERSION >= 12
static void dispatchCallback(uv_async_t* req)
{
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    AsyncProxy* ap = reinterpret_cast<AsyncProxy*>(req->data);

    if(!ap->callback.IsEmpty()) // Not sure if this catches dangling?
    {
        const unsigned argc = 1;
        Local<Value> argv[argc] = { Boolean::New(isolate, ap->result) };

        Local<Context> context = isolate->GetCurrentContext();
        Local<Function> callback = Local<Function>::New(isolate, ap->callback);
        MaybeLocal<Value> cr = callback->Call(context, Null(isolate), argc, argv);
        (void)cr; // Ignoring return value of Call
    }

    ap->callback.Reset();

    uv_close(reinterpret_cast<uv_handle_t*>(req), deleteAsyncProxy);
}
#else // Node 10 & 8
static void dispatchCallback(uv_async_t* req)
{
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    AsyncProxy* ap = reinterpret_cast<AsyncProxy*>(req->data);

    if(!ap->callback.IsEmpty()) // Not sure if this catches dangling?
    {
        const unsigned argc = 1;
        Local<Value> argv[argc] = { Boolean::New(isolate, ap->result) };

        Local<Function> callback = Local<Function>::New(isolate, ap->callback);
        callback->Call(isolate->GetCurrentContext()->Global(), argc, argv);
    }

    ap->callback.Reset();

    uv_close(reinterpret_cast<uv_handle_t*>(req), deleteAsyncProxy);
}
#endif

#ifdef COALESCE_PROXY_OPERATION

static uint64_t nanoseconds(const timespec& ts)
{
    return((1000000000ULL * ts.tv_sec) + ts.tv_nsec);
}

static void proxyLoop(void*)
{
    bool run = true;
    while(run)
    {
        AsyncProxy* first = sProxyQueue.pop();

        if(!first)
        {
            run = false;
            break;
        }

        timespec batchStart;
        clock_gettime(CLOCK_MONOTONIC, &batchStart);

        xtc_handle* h = iptc_init("nat");
        bool rc = true;

        if(!h)
        {
            std::cerr << "iptc_init: " << iptc_strerror(errno) << "\n";
            first->result = false; 
            first->next = NULL;
        }
        else
        {
            // Allow up for some multiple the iptc_init time to accumulate operations;
            // this allows us to batch more when the table is very full but keeps latency
            // from getting out of control.

            timespec initEnd;
            clock_gettime(CLOCK_MONOTONIC, &initEnd);

            uint64_t batchStartNS = nanoseconds(batchStart);
            uint64_t batchCutoff = batchStartNS + 2 * (nanoseconds(initEnd) - batchStartNS);

            AsyncProxy* ap = first;
            AsyncProxy* prev = NULL;
            int n = 0;

            do
            {
                if(prev)
                {
                    prev->next = ap;
                }

                ap->next = NULL;
                prev = ap;
                ++n;

                if(ap->add)
                {
                    ap->result = addProxyRules(h, ap->spec);
                }
                else
                {
                    ap->result = deleteProxyRules(h, ap->spec);
                }

                if(!ap->result)
                {
                    rc = false;
                    break;
                }

                timespec now;
                clock_gettime(CLOCK_MONOTONIC, &now);

                if(nanoseconds(now) > batchCutoff)
                {
                    break;
                }

                ap = sProxyQueue.tryPop();
            } while(ap);

            if(rc && !iptc_commit(h))
            {
                std::cerr << "iptc_commit: " << iptc_strerror(errno) << "\n";
                rc = false;
                
                for(AsyncProxy* it = first; it; it = it->next)
                {
                    it->result = false;
                }
            }

#if 0
            if(n)
            {
                timespec now;
                clock_gettime(CLOCK_MONOTONIC, &now);
                uint64_t nowNS = nanoseconds(now);
                uint64_t latency = (nowNS - nanoseconds(prev->submitted)) / 1000000;
                uint64_t throughput = (n * 1000000000ULL) / (nowNS - batchStartNS);
                std::cout << "Commited " << n << " proxy ops in one batch (latency: " << latency << "ms, " << throughput << " p/s)\n";
            }
#endif

            iptc_free(h);
        }

        flushProxyState(first);

        for(AsyncProxy* it = first; it;)
        {
            AsyncProxy* next = it->next;

            if(!it->async.data)
            {
                delete it;
            }
            else
            {
                // Signal main thread that it can run the callback now
                uv_async_send(&it->async);
            }

            it = next;
        }
        
    }
}
#else // !COALESCE_PROXY_OPERATION
static void proxyLoop(void*)
{
    bool run = true;
    while(run)
    {
        AsyncProxy* ap = sProxyQueue.pop();

        if(!ap)
        {
            run = false;
            break;
        }

        const ProxySpec& proxy = ap->spec;

        xtc_handle* h = iptc_init("nat");

        if(!h)
        {
            std::cerr << "iptc_init: " << iptc_strerror(errno) << "\n";
            ap->result = false; 
        }
        else
        {
            if(ap->add)
            {
                ap->result = addProxyRules(h, proxy);
            }
            else
            {
                ap->result = deleteProxyRules(h, proxy);
            }

            if(ap->result && !iptc_commit(h))
            {
                std::cerr << "iptc_commit: " << iptc_strerror(errno) << "\n";
                ap->result = false; 
            }

            iptc_free(h);
        }

        if(ap->result)
        {
            ap->result = flushProxyState(proxy);
        }
        
        if(!ap->async.data)
        {
            delete ap;
        }
        else
        {
            // Signal main thread that it can run the callback now
            uv_async_send(&ap->async);
        }
    }
}
#endif // !COALESCE_PROXY_OPERATION

// TODO: push NULL isn't quit right
// because tryPop returning NULL is indestinguishable -- need sentinel
// static void joinProxyThread()
// {
//     sProxyQueue.push(NULL);
//     uv_thread_join(&sProxyThread);
// }

static void initAsyncProxy()
{
    uv_thread_create(&sProxyThread, proxyLoop, NULL);
}

static bool pushAsyncProxy(const ProxySpec& proxy, const Local<Function>& callback, bool add)
{
    AsyncProxy* async = new AsyncProxy;
    async->spec = proxy;
    async->add = add;
    clock_gettime(CLOCK_MONOTONIC, &async->submitted);

    if(callback.IsEmpty())
    {
        async->async.data = NULL;
    }
    else
    {
        uv_async_init(uv_default_loop(), &async->async, dispatchCallback);
        async->async.data = async;

#if NODE_MAJOR_VERSION >= 12
        async->callback.Reset(Isolate::GetCurrent(), callback);
#else // Node 10 & 8
        async->callback.Reset(Isolate::GetCurrent(), callback);
#endif
    }
    sProxyQueue.push(async);
    return(true);
}

static bool createProxy(const ProxySpec& proxy, const Local<Function>& callback)
{
    return(pushAsyncProxy(proxy, callback, true));
}

static bool abortProxy(const ProxySpec&)
{
    return(false);
}

static bool deleteProxy(const ProxySpec& proxy, const Local<Function>& callback)
{
    return(pushAsyncProxy(proxy, callback, false));
}
#endif // ENABLE_ASYNC_PROXY
#endif // ENABLE_PROXY 

#if NODE_MAJOR_VERSION >= 12
void ThrowNodeError(Isolate* isolate, const char* what = NULL) {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, what, NewStringType::kNormal).ToLocalChecked()));
}

void compress(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);
    Local<Context> context = isolate->GetCurrentContext();

    if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
        ThrowNodeError(isolate, "First argument must be a Buffer");
        return;
    }

    Local<Object> bufferIn = args[0]->ToObject(context).ToLocalChecked();
    size_t bytesIn         = Buffer::Length(bufferIn);
    char * dataPointer     = Buffer::Data(bufferIn);
    size_t bytesCompressed = bytesIn + 100;
    char * bufferOut        = (char*) malloc(bytesCompressed);

    unsigned result = lzf_compress(dataPointer, bytesIn, bufferOut, bytesCompressed);

    if (!result) {
        free(bufferOut);
        args.GetReturnValue().Set(Undefined(isolate));
        return;
    }

    v8::MaybeLocal<v8::Object> resultBuffer = Buffer::New(isolate, bufferOut, result);
    free(bufferOut);

    args.GetReturnValue().Set(resultBuffer.ToLocalChecked());
}

void decompress(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);
    Local<Context> context = isolate->GetCurrentContext();

    if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
        ThrowNodeError(isolate, "First argument must be a Buffer");
        return;
    }

    Local<Object> bufferIn = args[0]->ToObject(context).ToLocalChecked();

    size_t bytesUncompressed = 999 * 1024 * 1024; // it's about max size that V8 supports

    if (args.Length() > 1 && args[1]->IsNumber()) { // accept dest buffer size
        bytesUncompressed = args[1].As<Uint32>()->Value();
    }

    char * bufferOut = (char*) malloc(bytesUncompressed);
    if (!bufferOut) {
        ThrowNodeError(isolate, "LZF malloc failed!");
        return;
    }

    unsigned result = lzf_decompress(Buffer::Data(bufferIn), Buffer::Length(bufferIn), bufferOut, bytesUncompressed);

    if (!result) {
        args.GetReturnValue().Set(Undefined(isolate));
        return;
    }

    v8::MaybeLocal<v8::Object> resultBuffer = Buffer::New(isolate, bufferOut, result);

    free(bufferOut);

    args.GetReturnValue().Set(resultBuffer.ToLocalChecked());
}

void crc32(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);
    Local<Context> context = isolate->GetCurrentContext();

    if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
        ThrowNodeError(isolate, "First argument must be a Buffer");
        return;
    }

    Local<Object> bufferIn = args[0]->ToObject(context).ToLocalChecked();
    size_t bytesIn         = Buffer::Length(bufferIn);
    char * dataPointer     = Buffer::Data(bufferIn);

    uint32 prior = 0;
    if (args.Length() > 1 && args[1]->IsNumber()) {
        prior = args[1].As<Uint32>()->Value();
        unsigned char* f = (unsigned char*)&prior;
        prior = f[3] | (f[2] << 8) | (f[1] << 16) | (f[0] << 24);
    }

    uint32 result = CalcCrc32(dataPointer, bytesIn, prior);
    unsigned char* f = (unsigned char*)&result;
    result = f[3] | (f[2] << 8) | (f[1] << 16) | (f[0] << 24);

    args.GetReturnValue().Set(Number::New(isolate, result));
}

void whirlpool(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);
    Local<Context> context = isolate->GetCurrentContext();

    if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
        ThrowNodeError(isolate, "First argument must be a Buffer");
        return;
    }

    Local<Object> bufferIn = args[0]->ToObject(context).ToLocalChecked();

    Whirlpool wp;
    WhirlpoolHash wh;

    wp.Hash(Buffer::Data(bufferIn), Buffer::Length(bufferIn));
    wp.Get(wh);

    v8::MaybeLocal<v8::Object> resultBuffer = Buffer::New(isolate, (char*)&wh.bytes[0], 64);
    args.GetReturnValue().Set(resultBuffer.ToLocalChecked());
}

void verifyPacket(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);
    Local<Context> context = isolate->GetCurrentContext();

    if (args.Length() < 3 || !Buffer::HasInstance(args[0]) || !Buffer::HasInstance(args[1]) || !Buffer::HasInstance(args[2])) {
        ThrowNodeError(isolate, "First argument must be a Buffer");
        return;
    }

    Local<Object> bufferIn = args[0]->ToObject(context).ToLocalChecked();
    Local<Object> saltBuffer = args[1]->ToObject(context).ToLocalChecked();
    Local<Object> destBuffer = args[2]->ToObject(context).ToLocalChecked();

    size_t bytesIn              = Buffer::Length(bufferIn);
    uint8* dataPointer        = (uint8*)Buffer::Data(bufferIn);
    uint8* destDataPointer  = (uint8*)Buffer::Data(destBuffer);
    size_t destBytesSize     = Buffer::Length(destBuffer);

    if(bytesIn < 5) { // illegal size need at least varint byte & packet hash
        args.GetReturnValue().Set(Undefined(isolate));
        return;
    }

    uint32 csize = bytesIn;
    uint32 uncompressedSize = GetVarIntLZF(dataPointer, csize);
    
    uint8 packetBuffer[16384] = { 0 }; // static packet decomp buffer.
    if(uncompressedSize > ARRAY_COUNT(packetBuffer)) {
        args.GetReturnValue().Set(Undefined(isolate));
        return;
    }

    // strip varint heading
    if(uncompressedSize == 0)
    {
        dataPointer++;
        bytesIn--;
    }
    else
    {
        uint32 offset = static_cast<uint32>(bytesIn) - csize;
        dataPointer += offset;
        //std::cout << "Decompressing: " << uncompressedSize << " csize " << csize << "\n";
        uint32 result = lzf_decompress(dataPointer, csize, packetBuffer, uncompressedSize);
        if (!result) {
            args.GetReturnValue().Set(Undefined(isolate));
            return;
        }
        bytesIn = uncompressedSize;
        dataPointer = &packetBuffer[0];
    }

    //std::cout << "bytesIn: " << bytesIn << " csize " << csize << "\n";

    // saw off packet hash
    uint32 expectedHash = *(uint32*)dataPointer;
    dataPointer += 4; bytesIn -= 4;
    
    //std::cout << "expectedHash: " << std::hex << expectedHash << "\n";

    // calc hash of packet data plus salt
    uint32 crc = CalcCrc32(dataPointer, bytesIn, 0);
    crc =  CalcCrc32(Buffer::Data(saltBuffer), Buffer::Length(saltBuffer), crc); // add in salt.
    crc = (crc & 0x000000FFU) << 24 | (crc & 0x0000FF00U) << 8 | (crc & 0x00FF0000U) >> 8 | (crc & 0xFF000000U) >> 24;

    //std::cout << "crc: " << std::hex << crc << "\n";

    if(expectedHash != crc || destBytesSize < bytesIn) {
        //std::cout << "hashFail!\n";
        args.GetReturnValue().Set(Undefined(isolate));
        return;
    }

    //std::cout << "return new buffer: " << bytesIn << "\n";

    //Buffer* BufferOut = Buffer::New((char*)dataPointer, bytesIn);
    memcpy(destDataPointer, dataPointer, bytesIn);
    
    args.GetReturnValue().Set(Number::New(isolate, bytesIn));
}

void conditionPacket(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);
    Local<Context> context = isolate->GetCurrentContext();

    if (args.Length() < 3 || !Buffer::HasInstance(args[0]) || !Buffer::HasInstance(args[1]) || !Buffer::HasInstance(args[2])) {
        ThrowNodeError(isolate, "First 3 arguments must be a Buffers");
        return;
    }
    
    Local<Object> bufferIn = args[0]->ToObject(context).ToLocalChecked();
    Local<Object> saltBuffer = args[1]->ToObject(context).ToLocalChecked();
    Local<Object> destBuffer = args[2]->ToObject(context).ToLocalChecked();

    char* bytes = Buffer::Data(bufferIn);
    uint32 len = Buffer::Length(bufferIn);
    
    uint8* packetBuffer  = (uint8*)Buffer::Data(destBuffer);
    size_t destBytesSize     = Buffer::Length(destBuffer);
    
    const size_t HEADER_SIZE = 1 + 4 + 2 + 2 + 2;
    
    if (len > 1400 || (len + HEADER_SIZE) > destBytesSize) {
        // MTU explosions
        args.GetReturnValue().Set(Undefined(isolate));
        return;
    }
    
    // !! lots of endian assumptions here.
    uint8* outBytes = packetBuffer;
    
    // compression header 1 byte compression header = 0 = no compression
    *outBytes = 0; outBytes++;

    // hash header recall this position for hash
    uint32* crcPtr = (uint32*)outBytes; outBytes += 4; 
    
    // connectionless header
    *(uint16*)outBytes = 0; outBytes += 2; // 16 bit packet num
    *(uint16*)outBytes = (2 << 14); outBytes += 2; // 16 but chunk header
    *(uint16*)outBytes = len; outBytes += 2; // packet size

    // append payload data
    memcpy(outBytes, bytes, len);
    outBytes += len;

    ptrdiff_t totalBufferSize = (ptrdiff_t)outBytes - (ptrdiff_t)packetBuffer;

    // calc hash
    uint32 crc = CalcCrc32(packetBuffer + 5, totalBufferSize - 5, 0);
    crc =  CalcCrc32(Buffer::Data(saltBuffer), Buffer::Length(saltBuffer), crc); // add in salt.
    *crcPtr = (crc & 0x000000FFU) << 24 | (crc & 0x0000FF00U) << 8 | (crc & 0x00FF0000U) >> 8 | (crc & 0xFF000000U) >> 24;
    
    //std::cout << "crc: " << std::hex << *crcPtr << " " << totalBufferSize << "\n";

    //Buffer* BufferOut = Buffer::New(packetBuffer, totalBufferSize);
    //HandleScope scope;
    //return scope.Close(BufferOut->handle_);
    args.GetReturnValue().Set(Number::New(isolate, totalBufferSize));
}

static bool readAddressArg(in_addr& out, const FunctionCallbackInfo<Value>& args, int argIndex)
{
    const Local<Value>& arg = args[argIndex];
    Isolate* isolate = args.GetIsolate();
    Local<Context> context = isolate->GetCurrentContext();

    if(!arg->IsString())
    {
        ThrowNodeError(isolate, "Expected IP-address argument");
        return(false);
    }

    String::Utf8Value str(isolate, arg->ToString(context).ToLocalChecked());

    out.s_addr = inet_addr(*str);
    
    if(out.s_addr == INADDR_NONE)
    {
        Isolate* isolate = args.GetIsolate();
        ThrowNodeError(isolate, "Expected IP-address argument");
        return(false);
    }

    return(true);
}

static bool readPortArg(uint16_t& out, const FunctionCallbackInfo<Value>& args, int argIndex)
{
    const Local<Value>& arg = args[argIndex];

    if(!arg->IsInt32())
    {
        Isolate* isolate = args.GetIsolate();
        ThrowNodeError(isolate, "Expected int argument");
        return(false);
    }

    // TODO: check for > 16bit?
    out = static_cast<uint16_t>(arg.As<Int32>()->Value());
    return(true);
}

static bool readProxyArgs(ProxySpec& out, const FunctionCallbackInfo<Value>& args, Local<Function>* callback = NULL)
{
    if((args.Length() < 7) || (args.Length() > 8))
    {
        Isolate* isolate = args.GetIsolate();
        ThrowNodeError(isolate, "proxy requires 7 arguments: aAddr, aPort, bAddr, bPort, nAddr, anPort, bnPort, [callback]");
        return(false);
    }

    int i = 0;

    if(!readAddressArg(out.aAddr, args, i++)) { return(false); }
    if(!readPortArg(out.aPort, args, i++)) { return(false); }
    if(!readAddressArg(out.bAddr, args, i++)) { return(false); }
    if(!readPortArg(out.bPort, args, i++)) { return(false); }
    if(!readAddressArg(out.nAddr, args, i++)) { return(false); }
    if(!readPortArg(out.anPort, args, i++)) { return(false); }
    if(!readPortArg(out.bnPort, args, i++)) { return(false); }

    if(i >= args.Length())
    {
        return(true); 
    }

    if(callback)
    {
        if(!args[i]->IsFunction())
        {
            Isolate* isolate = args.GetIsolate();
            ThrowNodeError(isolate, "Expected function argument");
            return(false);
        }

        *callback = Local<Function>::Cast(args[i++]);
    }

    return(true);
}

void flushProxies(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);

    if(args.Length() != 0)
    {
        ThrowNodeError(isolate, "flush proxies takes no argument");
        return;
    }
    
    args.GetReturnValue().Set(Boolean::New(isolate, flushProxies()));
}

void createProxy(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);

    ProxySpec proxy;
    Local<Function> callback;

    if(!readProxyArgs(proxy, args, &callback))
    {
        return;
    }

#ifdef ENABLE_ASYNC_PROXY
    createProxy(proxy, callback);
#else
    bool result = createProxy(proxy);

    const unsigned argc = 1;
    Local<Value> argv[argc] = { Boolean::New(isolate, result) };

    callback->Call(isolate->GetCurrentContext()->Global(), argc, argv);
#endif
}

void abortProxy(const FunctionCallbackInfo<Value>& args)
{
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);

    ProxySpec proxy;

    if(!readProxyArgs(proxy, args))
    {
        return;
    }

    args.GetReturnValue().Set(Boolean::New(isolate, abortProxy(proxy)));
}

void deleteProxy(const FunctionCallbackInfo<Value>& args)
{
    Isolate* isolate = args.GetIsolate();
    HandleScope scope(isolate);

    ProxySpec proxy;
    Local<Function> callback;

    if(!readProxyArgs(proxy, args, &callback))
    {
        return;
    }

#ifdef ENABLE_ASYNC_PROXY
    deleteProxy(proxy, callback);
#else
    bool result = deleteProxy(proxy);

    const unsigned argc = 1;
    Local<Value> argv[argc] = { Boolean::New(isolate, result) };

    callback->Call(isolate->GetCurrentContext()->Global(), argc, argv);
#endif
}
#else // Node 10 & 8
Handle<Value> ThrowNodeError(const char* what = NULL) {
    return Isolate::GetCurrent()->ThrowException(Exception::Error(String::NewFromUtf8(Isolate::GetCurrent(), what)));
}

void compress(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
        args.GetReturnValue().Set(ThrowNodeError("First argument must be a Buffer"));
        return;
    }

    Local<Object> bufferIn = args[0]->ToObject();
    size_t bytesIn         = Buffer::Length(bufferIn);
    char * dataPointer     = Buffer::Data(bufferIn);
    size_t bytesCompressed = bytesIn + 100;
    char * bufferOut        = (char*) malloc(bytesCompressed);

    unsigned result = lzf_compress(dataPointer, bytesIn, bufferOut, bytesCompressed);

    if (!result) {
        free(bufferOut);
        args.GetReturnValue().Set(Undefined(Isolate::GetCurrent()));
        return;
    }

    v8::MaybeLocal<v8::Object> resultBuffer = Buffer::New(isolate, bufferOut, result);
    free(bufferOut);

    args.GetReturnValue().Set(resultBuffer.ToLocalChecked());
}

void decompress(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
        args.GetReturnValue().Set(ThrowNodeError("First argument must be a Buffer"));
        return;
    }

    Local<Object> bufferIn = args[0]->ToObject();

    size_t bytesUncompressed = 999 * 1024 * 1024; // it's about max size that V8 supports

    if (args.Length() > 1 && args[1]->IsNumber()) { // accept dest buffer size
        bytesUncompressed = args[1]->Uint32Value();
    }

    char * bufferOut = (char*) malloc(bytesUncompressed);
    if (!bufferOut) {
        args.GetReturnValue().Set(ThrowNodeError("LZF malloc failed!"));
        return;
    }

    unsigned result = lzf_decompress(Buffer::Data(bufferIn), Buffer::Length(bufferIn), bufferOut, bytesUncompressed);

    if (!result) {
        args.GetReturnValue().Set(Undefined(isolate));
        return;
    }

    v8::MaybeLocal<v8::Object> resultBuffer = Buffer::New(isolate, bufferOut, result);

    free(bufferOut);

    args.GetReturnValue().Set(resultBuffer.ToLocalChecked());
}

void crc32(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
        args.GetReturnValue().Set(ThrowNodeError("First argument must be a Buffer"));
        return;
    }

    Local<Object> bufferIn = args[0]->ToObject();
    size_t bytesIn         = Buffer::Length(bufferIn);
    char * dataPointer     = Buffer::Data(bufferIn);

    uint32 prior = 0;
    if (args.Length() > 1 && args[1]->IsNumber()) {
        prior = args[1]->Uint32Value();
        unsigned char* f = (unsigned char*)&prior;
        prior = f[3] | (f[2] << 8) | (f[1] << 16) | (f[0] << 24);
    }

    uint32 result = CalcCrc32(dataPointer, bytesIn, prior);
    unsigned char* f = (unsigned char*)&result;
    result = f[3] | (f[2] << 8) | (f[1] << 16) | (f[0] << 24);

    args.GetReturnValue().Set(Number::New(isolate, result));
}

void whirlpool(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    if (args.Length() < 1 || !Buffer::HasInstance(args[0])) {
        args.GetReturnValue().Set(ThrowNodeError("First argument must be a Buffer"));
        return;
    }

    Local<Object> bufferIn = args[0]->ToObject();

    Whirlpool wp;
    WhirlpoolHash wh;

    wp.Hash(Buffer::Data(bufferIn), Buffer::Length(bufferIn));
    wp.Get(wh);

    v8::MaybeLocal<v8::Object> resultBuffer = Buffer::New(isolate, (char*)&wh.bytes[0], 64);
    args.GetReturnValue().Set(resultBuffer.ToLocalChecked());
}

void verifyPacket(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    if (args.Length() < 3 || !Buffer::HasInstance(args[0]) || !Buffer::HasInstance(args[1]) || !Buffer::HasInstance(args[2])) {
        args.GetReturnValue().Set(ThrowNodeError("First argument must be a Buffer"));
        return;
    }

    Local<Object> bufferIn = args[0]->ToObject();
    Local<Object> saltBuffer = args[1]->ToObject();
    Local<Object> destBuffer = args[2]->ToObject();

    size_t bytesIn              = Buffer::Length(bufferIn);
    uint8* dataPointer        = (uint8*)Buffer::Data(bufferIn);
    uint8* destDataPointer  = (uint8*)Buffer::Data(destBuffer);
    size_t destBytesSize     = Buffer::Length(destBuffer);

    if(bytesIn < 5) { // illegal size need at least varint byte & packet hash
        args.GetReturnValue().Set(Undefined(isolate));
        return;
    }

    uint32 csize = bytesIn;
    uint32 uncompressedSize = GetVarIntLZF(dataPointer, csize);
    
    uint8 packetBuffer[16384] = { 0 }; // static packet decomp buffer.
    if(uncompressedSize > ARRAY_COUNT(packetBuffer)) {
        args.GetReturnValue().Set(Undefined(isolate));
        return;
    }

    // strip varint heading
    if(uncompressedSize == 0)
    {
        dataPointer++;
        bytesIn--;
    }
    else
    {
        uint32 offset = static_cast<uint32>(bytesIn) - csize;
        dataPointer += offset;
        //std::cout << "Decompressing: " << uncompressedSize << " csize " << csize << "\n";
        uint32 result = lzf_decompress(dataPointer, csize, packetBuffer, uncompressedSize);
        if (!result) {
            args.GetReturnValue().Set(Undefined(isolate));
            return;
        }
        bytesIn = uncompressedSize;
        dataPointer = &packetBuffer[0];
    }

    //std::cout << "bytesIn: " << bytesIn << " csize " << csize << "\n";

    // saw off packet hash
    uint32 expectedHash = *(uint32*)dataPointer;
    dataPointer += 4; bytesIn -= 4;
    
    //std::cout << "expectedHash: " << std::hex << expectedHash << "\n";

    // calc hash of packet data plus salt
    uint32 crc = CalcCrc32(dataPointer, bytesIn, 0);
    crc =  CalcCrc32(Buffer::Data(saltBuffer), Buffer::Length(saltBuffer), crc); // add in salt.
    crc = (crc & 0x000000FFU) << 24 | (crc & 0x0000FF00U) << 8 | (crc & 0x00FF0000U) >> 8 | (crc & 0xFF000000U) >> 24;

    //std::cout << "crc: " << std::hex << crc << "\n";

    if(expectedHash != crc || destBytesSize < bytesIn) {
        //std::cout << "hashFail!\n";
        args.GetReturnValue().Set(Undefined(isolate));
        return;
    }

    //std::cout << "return new buffer: " << bytesIn << "\n";

    //Buffer* BufferOut = Buffer::New((char*)dataPointer, bytesIn);
    memcpy(destDataPointer, dataPointer, bytesIn);
    
    args.GetReturnValue().Set(Number::New(isolate, bytesIn));
}

void conditionPacket(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    if (args.Length() < 3 || !Buffer::HasInstance(args[0]) || !Buffer::HasInstance(args[1]) || !Buffer::HasInstance(args[2])) {
        args.GetReturnValue().Set(ThrowNodeError("First 3 arguments must be a Buffers"));
        return;
    }
    
    Local<Object> bufferIn = args[0]->ToObject();
    Local<Object> saltBuffer = args[1]->ToObject();
    Local<Object> destBuffer = args[2]->ToObject();

    char* bytes = Buffer::Data(bufferIn);
    uint32 len = Buffer::Length(bufferIn);
    
    uint8* packetBuffer  = (uint8*)Buffer::Data(destBuffer);
    size_t destBytesSize     = Buffer::Length(destBuffer);
    
    const size_t HEADER_SIZE = 1 + 4 + 2 + 2 + 2;
    
    if (len > 1400 || (len + HEADER_SIZE) > destBytesSize) {
        // MTU explosions
        args.GetReturnValue().Set(Undefined(isolate));
        return;
    }
    
    // !! lots of endian assumptions here.
    uint8* outBytes = packetBuffer;
    
    // compression header 1 byte compression header = 0 = no compression
    *outBytes = 0; outBytes++;

    // hash header recall this position for hash
    uint32* crcPtr = (uint32*)outBytes; outBytes += 4; 
    
    // connectionless header
    *(uint16*)outBytes = 0; outBytes += 2; // 16 bit packet num
    *(uint16*)outBytes = (2 << 14); outBytes += 2; // 16 but chunk header
    *(uint16*)outBytes = len; outBytes += 2; // packet size

    // append payload data
    memcpy(outBytes, bytes, len);
    outBytes += len;

    ptrdiff_t totalBufferSize = (ptrdiff_t)outBytes - (ptrdiff_t)packetBuffer;

    // calc hash
    uint32 crc = CalcCrc32(packetBuffer + 5, totalBufferSize - 5, 0);
    crc =  CalcCrc32(Buffer::Data(saltBuffer), Buffer::Length(saltBuffer), crc); // add in salt.
    *crcPtr = (crc & 0x000000FFU) << 24 | (crc & 0x0000FF00U) << 8 | (crc & 0x00FF0000U) >> 8 | (crc & 0xFF000000U) >> 24;
    
    //std::cout << "crc: " << std::hex << *crcPtr << " " << totalBufferSize << "\n";

    //Buffer* BufferOut = Buffer::New(packetBuffer, totalBufferSize);
    //HandleScope scope;
    //return scope.Close(BufferOut->handle_);
    args.GetReturnValue().Set(Number::New(isolate, totalBufferSize));
}

static bool readAddressArg(in_addr& out, 
const Local<Value>& arg)
{
    if(!arg->IsString())
    {
        Isolate* isolate = Isolate::GetCurrent();
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,
            "Expected IP-address argument")));
        return(false);
    }

    String::Utf8Value str(arg->ToString());

    out.s_addr = inet_addr(*str);
    
    if(out.s_addr == INADDR_NONE)
    {
        Isolate* isolate = Isolate::GetCurrent();
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,
            "Expected IP-address argument")));
        return(false);
    }

    return(true);
}

static bool readPortArg(uint16_t& out, const Local<Value>& arg)
{
    if(!arg->IsInt32())
    {
        Isolate* isolate = Isolate::GetCurrent();
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,
            "Expected int argument")));
        return(false);
    }

    // TODO: check for > 16bit?
    out = static_cast<uint16_t>(arg->Int32Value());
    return(true);
}

static bool readProxyArgs(ProxySpec& out, const FunctionCallbackInfo<Value>& args, Local<Function>* callback = NULL)
{
    if((args.Length() < 7) || (args.Length() > 8))
    {
        Isolate* isolate = Isolate::GetCurrent();
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,
            "proxy requires 7 arguments: aAddr, aPort, bAddr, bPort, nAddr, anPort, bnPort, [callback] ")));
        return(false);
    }

    int i = 0;

    if(!readAddressArg(out.aAddr, args, i++)) { return(false); }
    if(!readPortArg(out.aPort, args, i++)) { return(false); }
    if(!readAddressArg(out.bAddr, args, i++)) { return(false); }
    if(!readPortArg(out.bPort, args, i++)) { return(false); }
    if(!readAddressArg(out.nAddr, args, i++)) { return(false); }
    if(!readPortArg(out.anPort, args, i++)) { return(false); }
    if(!readPortArg(out.bnPort, args, i++)) { return(false); }

    if(i >= args.Length())
    {
        return(true); 
    }

    if(callback)
    {
        if(!args[i]->IsFunction())
        {
            Isolate* isolate = Isolate::GetCurrent();
            isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,
                "Expected function argument")));
            return(false);
        }

        *callback = Local<Function>::Cast(args[i++]);
    }

    return(true);
}

void flushProxies(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    if(args.Length() != 0)
    {
        isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "flush proxies takes no argument")));
        return;
    }
    
    args.GetReturnValue().Set(Boolean::New(isolate, flushProxies()));
}

void createProxy(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    ProxySpec proxy;
    Local<Function> callback;

    if(!readProxyArgs(proxy, args, &callback))
    {
        return;
    }

#ifdef ENABLE_ASYNC_PROXY
    createProxy(proxy, callback);
#else
    bool result = createProxy(proxy);

    const unsigned argc = 1;
    Local<Value> argv[argc] = { Boolean::New(isolate, result) };

    callback->Call(isolate->GetCurrentContext()->Global(), argc, argv);
#endif
}

void abortProxy(const FunctionCallbackInfo<Value>& args)
{
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    ProxySpec proxy;

    if(!readProxyArgs(proxy, args))
    {
        return;
    }

    args.GetReturnValue().Set(Boolean::New(isolate, abortProxy(proxy)));
}

void deleteProxy(const FunctionCallbackInfo<Value>& args)
{
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    ProxySpec proxy;
    Local<Function> callback;

    if(!readProxyArgs(proxy, args, &callback))
    {
        return;
    }

#ifdef ENABLE_ASYNC_PROXY
    deleteProxy(proxy, callback);
#else
    bool result = deleteProxy(proxy);

    const unsigned argc = 1;
    Local<Value> argv[argc] = { Boolean::New(isolate, result) };

    callback->Call(isolate->GetCurrentContext()->Global(), argc, argv);
#endif
}

#endif // Node 12

// varint size encoding needed for perl's LZF compression
// NOTE: I am matching the LZF version but it is wrong for for large packet sizes (e.g. usize <= 0x7fffffff is wrong, varint of 0xffffffff fits in 5 bytes!)

// inline static uint8 TruncateByte(uint32 b)
// {
//     return(static_cast<uint8>(b & 0xff));
// }
// 
// static uint32 MakeVarIntLZF(uint32 usize, uint8 dst[5])
// {
//     uint32 skip = 0;
// 
//     if(usize <= 0x7f)
//     {
//         dst[skip++] = TruncateByte(usize);
//     }
//     else if(usize <= 0x7ff) 
//     {
//         dst[skip++] = TruncateByte(( usize >>  6)         | 0xc0);
//         dst[skip++] = TruncateByte(( usize        & 0x3f) | 0x80);
//     }
//     else if(usize <= 0xffff) 
//     {
//         dst[skip++] = TruncateByte(( usize >> 12)         | 0xe0);
//         dst[skip++] = TruncateByte(((usize >>  6) & 0x3f) | 0x80);
//         dst[skip++] = TruncateByte(( usize        & 0x3f) | 0x80);
//     }
//     else if(usize <= 0x1fffff) 
//     {
//         dst[skip++] = TruncateByte(( usize >> 18)         | 0xf0);
//         dst[skip++] = TruncateByte(((usize >> 12) & 0x3f) | 0x80);
//         dst[skip++] = TruncateByte(((usize >>  6) & 0x3f) | 0x80);
//         dst[skip++] = TruncateByte(( usize        & 0x3f) | 0x80);
//     }
//     else if(usize <= 0x3ffffff) 
//     {
//         dst[skip++] = TruncateByte(( usize >> 24)         | 0xf8);
//         dst[skip++] = TruncateByte(((usize >> 18) & 0x3f) | 0x80);
//         dst[skip++] = TruncateByte(((usize >> 12) & 0x3f) | 0x80);
//         dst[skip++] = TruncateByte(((usize >>  6) & 0x3f) | 0x80);
//         dst[skip++] = TruncateByte(( usize        & 0x3f) | 0x80);
//     }
//     else if(usize <= 0x7fffffff) 
//     {
//         dst[skip++] = TruncateByte(( usize >> 30)         | 0xfc);
//         dst[skip++] = TruncateByte(((usize >> 24) & 0x3f) | 0x80);
//         dst[skip++] = TruncateByte(((usize >> 18) & 0x3f) | 0x80);
//         dst[skip++] = TruncateByte(((usize >> 12) & 0x3f) | 0x80);
//         dst[skip++] = TruncateByte(((usize >>  6) & 0x3f) | 0x80);
//         dst[skip++] = TruncateByte(( usize        & 0x3f) | 0x80);
//     }
//     return(skip);
// }

static uint32 GetVarIntLZF(const uint8* src, uint32& csize)
{
    uint32 usize = 0;
    
    // check for zero = no compression
    if(!src[0])
    {
        usize = csize - 1;
        return(0);
    }

    // compressed, decomp the buffer with csize offset
    if (!(src[0] & 0x80) && csize >= 1)
    {
        csize -= 1;
        usize =                 *src++ & 0xff;
    }
    else if (!(src[0] & 0x20) && csize >= 2)
    {
        csize -= 2;
        usize =                 *src++ & 0x1f;
        usize = (usize << 6) | (*src++ & 0x3f);
    }
    else if (!(src[0] & 0x10) && csize >= 3)
    {
        csize -= 3;
        usize =                 *src++ & 0x0f;
        usize = (usize << 6) | (*src++ & 0x3f);
        usize = (usize << 6) | (*src++ & 0x3f);
    }
    else if (!(src[0] & 0x08) && csize >= 4)
    {
        csize -= 4;
        usize =                 *src++ & 0x07;
        usize = (usize << 6) | (*src++ & 0x3f);
        usize = (usize << 6) | (*src++ & 0x3f);
        usize = (usize << 6) | (*src++ & 0x3f);
    }
    else if (!(src[0] & 0x04) && csize >= 5)
    {
        csize -= 5;
        usize =                 *src++ & 0x03;
        usize = (usize << 6) | (*src++ & 0x3f);
        usize = (usize << 6) | (*src++ & 0x3f);
        usize = (usize << 6) | (*src++ & 0x3f);
        usize = (usize << 6) | (*src++ & 0x3f);
    }
    else if (!(src[0] & 0x02) && csize >= 6)
    {
        csize -= 6;
        usize =                 *src++ & 0x01;
        usize = (usize << 6) | (*src++ & 0x3f);
        usize = (usize << 6) | (*src++ & 0x3f);
        usize = (usize << 6) | (*src++ & 0x3f);
        usize = (usize << 6) | (*src++ & 0x3f);
        usize = (usize << 6) | (*src++ & 0x3f);
    }
    return(usize);
}

#if NODE_MAJOR_VERSION >= 12
extern "C" void init (Local<Object> target)
#else // Node 10 & 8
extern "C" void init (Handle<Object> target)
#endif
{
#ifdef ENABLE_PROXY
    initProxy();
#ifdef ENABLE_ASYNC_PROXY
    initAsyncProxy();
#endif
#endif

    NODE_SET_METHOD(target, "compress", compress);
    NODE_SET_METHOD(target, "decompress", decompress);
    NODE_SET_METHOD(target, "crc32", crc32);
    NODE_SET_METHOD(target, "whirlpool", whirlpool);
    NODE_SET_METHOD(target, "verifyPacket", verifyPacket);
    NODE_SET_METHOD(target, "conditionPacket", conditionPacket);
    NODE_SET_METHOD(target, "flushProxies", flushProxies);
    NODE_SET_METHOD(target, "createProxy", createProxy);
    NODE_SET_METHOD(target, "abortProxy", abortProxy);
    NODE_SET_METHOD(target, "deleteProxy", deleteProxy);
}

NODE_MODULE(wfutil, init)
