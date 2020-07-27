#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/module.h>
#include<linux/moduleparam.h>


#include<asm/uaccess.h>
#include<linux/cdev.h>
#include<linux/proc_fs.h>
#include<linux/f2fs_fs.h>
#include<linux/vmalloc.h>
#define MAX_SIZE 100


#include<net/sock.h>
#include<linux/netlink.h>
#include<linux/skbuff.h>
#include<linux/bio.h>
#include<linux/kprobes.h>
#include<linux/kthread.h>
#include<linux/time.h>

#include<linux/mutex.h>
#include<linux/lzo.h>

#include<linux/mmc/mmc.h>
#include<linux/mmc/card.h>
#include<linux/mmc/host.h>
#include<linux/blkdev.h>
#include<linux/fs.h>

//for vma trace
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/rmap.h>
#include <linux/hugetlb.h>
#include <linux/stacktrace.h>

//for compswap
#include <linux/frontswap.h>
#include <linux/swapfile.h>

#ifndef COMMON_H
#define COMMON_H
#define DEBUG 1


#define debug_print(fmt, ...) \
    do {if(DEBUG) printk("%s:%d" fmt, __FUNCTION__, __LINE__, __VA_ARGS__); \
    }while(0)

#define CACHE_SIZE (3072)
#define HASH_SEED (1512356891)
typedef struct {
    unsigned char buffer[PAGE_SIZE];
    unsigned long int sector;
}page_buf;
extern int diff_interval[4];

enum {
	NONE,
	SHA1,			//1
	PG_COMPRESS,	//2
	BIO_COMPRESS,	//3
	DIFF,			//4
	SYNC_SHA_LZO,	//5
	NR_OPS
};


void get_page_filename(struct page *page, char* output);
void set_timestamp(struct timespec *cur_time, struct timespec *start_time);
int get_page_data(struct page *p, char *output);
void char_to_hex(char *in, char *out, int in_len);
void reposition(char *in, char* tmp);
int diff_4KB(unsigned long sector, unsigned char *a, unsigned char *b, int*logs);
unsigned int  murmur_hash(uint32_t seed, unsigned int hash_size,  uint32_t key, uint32_t key_length);

// bit operation
static inline void __set_bitmap(unsigned long offset, unsigned char *map)
{
	map[offset>>3] = map[offset>>3] | (1<<(offset&0x07));
}
static inline void __clr_bitmap(unsigned long offset, unsigned char *map)
{
	map[offset>>3] = map[offset>>3] & ~(1<<(offset&0x07));
}
static inline unsigned char __get_bitmap(unsigned long offset, unsigned char *map)
{
	return !!(map[offset>>3] & (1<<(offset&0x07)));
}
static inline void set_bitmap(unsigned long offset, unsigned char *map, spinlock_t *lock)
{
	spin_lock(lock);
	__set_bitmap(offset,map);
	spin_unlock(lock);
}
static inline void clr_bitmap(unsigned long offset, unsigned char *map, spinlock_t *lock)
{
	spin_lock(lock);
	__clr_bitmap(offset,map);
	spin_unlock(lock);
}
static inline unsigned char get_bitmap(unsigned long offset, unsigned char *map, spinlock_t *lock)
{
	unsigned char ret;
	spin_lock(lock);
	ret = __get_bitmap(offset,map);
	spin_unlock(lock);
	return ret;
}
static inline int find_first_set(unsigned char bit_8)
{
	int r=1;
	if (!bit_8)
		return 0;
	if (!(bit_8&0xf)) {
		bit_8>>=4;
		r+=4;
	}
	if (!(bit_8&3)) {
		bit_8>>=2;
		r+=2;
	}
	if (!(bit_8&1)) {
		bit_8>>=1;
		r+=1;
	}
	return r;
}
static inline int find_first_zero(unsigned char bit_8)
{
	return find_first_set(~bit_8); 
}

// for compswp
extern int rmap_walk(struct page *page, int (*rmap_one)(struct page *,
			struct vm_area_struct *, unsigned long, void *), void *arg);
extern const char *arch_vma_name(struct vm_area_struct *vma);
int get_lzo_zsize(struct page *);
void get_vma_name(struct task_struct *, struct mm_struct *, struct vm_area_struct *, char *);

struct cache {
	char *data;
	uint8_t *valid_table;
	uint32_t *rmap;
	uint32_t max_page;
	uint32_t nr_used;
	uint32_t writeback_bound;
	spinlock_t lock;
};
struct swp_map_entry {
	uint32_t map;
	uint8_t flag;
	struct mutex mutex;
};

// swp_map_entry and write_buffer map :
// ---------------------------------------------
// |         20 bits         |     12 bits     |
// ---------------------------------------------
// |       Page offset       | Compressed size |
// ---------------------------------------------
#define COMPSWP_BADDR(MAP) (MAP & ~(PAGE_SIZE-1))
#define COMPSWP_PGOFF(MAP) (MAP>>PAGE_SHIFT)
#define COMPSWP_ZSIZE(MAP) (MAP & (PAGE_SIZE-1))

// swp_map_entry.flag (8bit):
#define COMPSWP_BUFFER	(1<<0)	// in write buffer
#define COMPSWP_ISCOMP	(1<<1)	// has compressed
#define COMPSWP_NEEDWB	(1<<2)	// buffer slot need writeback
#define COMPSWP_0	(1<<3)	// reserve
#define COMPSWP_1	(1<<4)	// reserve
#define COMPSWP_2	(1<<5)	// reserve
#define COMPSWP_3	(1<<6)	// reserve
#define COMPSWP_4	(1<<7)	// reserve

#endif
