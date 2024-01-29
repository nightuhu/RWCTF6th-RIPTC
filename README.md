# RWCTF6th-RIPTC

## Preface

RIPTC is a hard (**1** solve/ 2291 teams) realworld linux kernel challenge in Real World CTF 5th.

And I managed to solve it after a day's hard work playing the CTF with Nu1L.

## Before we start

Because there's already some really cool and excellent material out there, I won’t go into Linux Traffic Control subsystem's detail here. If you are interested, read the links below and TC's manual.

[1] [Breaking the Code - Exploiting and Examining CVE-2023-1829 in cls_tcindex Classifier Vulnerability | STAR Labs](https://starlabs.sg/blog/2023/06-breaking-the-code-exploiting-and-examining-cve-2023-1829-in-cls_tcindex-classifier-vulnerability/)

[2] [kernelctf/CVE-2023-3776_cos_mitigation/docs/exploit.md](https://github.com/google/security-research/blob/master/pocs/linux/kernelctf/CVE-2023-3776_cos_mitigation/docs/exploit.md) and some other exploits against kernelCTF.

## Vulnerability

The vulnerability is caused by the reference count not being released correctly, causing UAF.

```c
// cls_tcindex.c
static int
tcindex_set_parms(struct net *net, struct tcf_proto *tp, unsigned long base,
		  u32 handle, struct tcindex_data *p,
		  struct tcindex_filter_result *r, struct nlattr **tb,
		  struct nlattr *est, u32 flags, struct netlink_ext_ack *extack)
    ...
	if (p->perfect) {
		int i;

		if (tcindex_alloc_perfect_hash(net, cp) < 0)
			goto errout;
		cp->alloc_hash = cp->hash;
		for (i = 0; i < min(cp->hash, p->hash); i++)			// [2]
			cp->perfect[i].res = p->perfect[i].res;
		balloc = 1;
	}
	cp->h = p->h;
	...
    if (tb[TCA_TCINDEX_CLASSID]) {
		cr.classid = nla_get_u32(tb[TCA_TCINDEX_CLASSID]);		// [1]
		tcf_bind_filter(tp, &cr, base);
	}
	...
```

[1] When adding a tcindex filter, if `tb[TCA_TCINDEX_CLASSID]` is set, we will go into `tcf_bind_filter()` and increase the corresponding class's `filter_cnt`.

```c
static unsigned long drr_bind_tcf(struct Qdisc *sch, unsigned long parent,
				  u32 classid)
{
	struct drr_class *cl = drr_find_class(sch, classid);

	if (cl != NULL)
		cl->filter_cnt++;

	return (unsigned long)cl;
}
```

[2] But when we update a tcindex filter with `p->perfect` set, we only copy the minimum number of res between `cp->hash` and `p->hash`. So later when we enter

[3] The `filter_cnt` is wrongly kept due to wrong res copy process design.

```c
static void tcindex_destroy(struct tcf_proto *tp, bool rtnl_held,
			    struct netlink_ext_ack *extack)
{
	struct tcindex_data *p = rtnl_dereference(tp->root);
	int i;

	pr_debug("tcindex_destroy(tp %p),p %p\n", tp, p);

	if (p->perfect) {
		for (i = 0; i < p->hash; i++) {						//	[3]
			struct tcindex_filter_result *r = p->perfect + i;
	...
			tcf_unbind_filter(tp, &r->res);
	...
		}
	}
	...
	tcf_queue_work(&p->rwork, tcindex_destroy_work);
}
```

## Exploit

1. Leak KASLR using `EntryBleed`, which is well described [here](https://www.willsroot.io/2022/12/entrybleed.html) by Will.

2. Trigger UAF by repeatedly adding multi res in a tcindex perfect filter, and later set a small `hash`.  

3. Spray `pg_vec` array to occupy the UAF `drr_class`. As the `pg_vec.buffer`will be automatically filled with the heap address in [4], we don't have to leak a kernel heap address in this way.

   ```c 
   // af_packet.c
   static struct pgv *alloc_pg_vec(struct tpacket_req *req, int order)
   {
   	...
   	pg_vec = kcalloc(block_nr, sizeof(struct pgv), GFP_KERNEL | __GFP_NOWARN);
   	if (unlikely(!pg_vec))
   		goto out;
   
   	for (i = 0; i < block_nr; i++) {
   		pg_vec[i].buffer = alloc_one_pg_vec_page(order);	//	[4]
   		if (unlikely(!pg_vec[i].buffer))
   			goto out_free_pgvec;
   	}
       ...
   }
   ```

4. Use `packet_mmap()` to mmap these buffers back into userspace, then we have fully control the `drr_class->qdisc`. You can learn more about this method by reading [AS-22-YongLiu-USMA-Share-Kernel-Code-With-Me](https://i.blackhat.com/Asia-22/Thursday-Materials/AS-22-YongLiu-USMA-Share-Kernel-Code.pdf).

   ```c
   static int packet_mmap(struct file *file, struct socket *sock,
   		struct vm_area_struct *vma)
   {
   ...
   
   	start = vma->vm_start;
   	for (rb = &po->rx_ring; rb <= &po->tx_ring; rb++) {
   		if (rb->pg_vec == NULL)
   			continue;
   
   		for (i = 0; i < rb->pg_vec_len; i++) {
   			struct page *page;
   			void *kaddr = rb->pg_vec[i].buffer;
   			int pg_num;
   
   			for (pg_num = 0; pg_num < rb->pg_vec_pages; pg_num++) {
   				page = pgv_to_page(kaddr);
   				err = vm_insert_page(vma, start, page);		//	here
   				if (unlikely(err))
   					goto out;
   				start += PAGE_SIZE;
   				kaddr += PAGE_SIZE;
   			}
   		}
   	}
   ...
   }
   ```

5.  Later send a packet, in `drr_enqueue` we trigger our hijacked `cl->qdisc->enqueue` to gain the ability to execute arbitrary kernel code. 

   ```c
   static int drr_enqueue(struct sk_buff *skb, struct Qdisc *sch,
   		       struct sk_buff **to_free)
   {
   	unsigned int len = qdisc_pkt_len(skb);
   	struct drr_sched *q = qdisc_priv(sch);
   	struct drr_class *cl;
   	int err = 0;
   	bool first;
   
   	cl = drr_classify(skb, sch, &err);
   	if (cl == NULL) {
   		if (err & __NET_XMIT_BYPASS)
   			qdisc_qstats_drop(sch);
   		__qdisc_drop(skb, to_free);
   		return err;
   	}
   
   	first = !cl->qdisc->q.qlen;
   	err = qdisc_enqueue(skb, cl->qdisc, to_free);	//	We all like ROP OvO
   ...
   }
   ```

6.  To save time, I use Kylebot's cool trick `Telefork` to return to user mode, which is what I learned by reading this his excellent KCTF walkthrough [[CVE-2022-1786\] A Journey To The Dawn | kylebot's Blog](https://blog.kylebot.net/2022/10/16/CVE-2022-1786/#Day-7-The-Dawn).

   

The sorted full exploit is provided and can be read it if you want to know more. 

If you feel this writeup is helpful, you can give me a follow on [twitter](https://twitter.com/__nightu__). Thanks for reading!
