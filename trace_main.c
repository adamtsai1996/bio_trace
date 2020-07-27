#include "common.h"
#include "sha1.h"
static atomic_t atomic_key;

static int bio_log(int bi_rw,struct bio *bio)
{
	char filename[DNAME_INLINE_LEN];
	char blkdevname[BDEVNAME_SIZE];
	struct timespec ts;
	uint32_t addr, nr_pg;
	const char *sync, *rw;
	int key;

	getnstimeofday(&ts);
	key = atomic_inc_return(&atomic_key);
	memset(filename, '\0', DNAME_INLINE_LEN);
	memset(blkdevname, '\0', BDEVNAME_SIZE);
	bi_rw = bi_rw|bio->bi_rw;
	
	rw = bi_rw&WRITE? "write" : "read";
	sync = rw_is_sync(bi_rw)? "sync" : "async";
	addr = bio->bi_sector<<9;
	nr_pg = bio->bi_vcnt;
	get_page_filename(bio_iovec_idx(bio,0)->bv_page,filename);
	if (bio->bi_bdev) {
		bdevname(bio->bi_bdev, blkdevname);
	} else {
		sprintf(blkdevname, "NDEV");
	}

	printk("bio_trace,bio,%ld,%ld,%d,%s,%s,%s,0x%08x,%d,%s\n",
		ts.tv_sec, ts.tv_nsec, key, blkdevname, rw, sync, addr, nr_pg, filename);
	
	return 0;
}
static void submit_bio_prehandler(int rw, struct bio *bio)
{
	if (bio_has_data(bio)) bio_log(rw,bio);
	jprobe_return();
}
static struct jprobe submit_bio_probe = {
	.entry = submit_bio_prehandler,
	.kp = {
		.symbol_name = "submit_bio",
		.addr = NULL,
	},
};
static int init_jprobe(void)
{
	int ret = 0;
	ret = register_jprobe(&submit_bio_probe);
	if(ret <0){
		printk("bio_trace,ERR,%s:%i\n",__func__,__LINE__);
		return ret;
	}
	return 0;
}

static void cleanup_main(void)
{
	unregister_jprobe(&submit_bio_probe);
	printk("bio_trace,log,exit kernel\n");
}
static int init_main(void)
{
	int ret;

	atomic_set(&atomic_key, 0);
	ret = init_jprobe();
	if (ret<0) {
		printk("bio_trace,ERR,%s:%i\n",__func__,__LINE__);
		goto jprobe_fail;
	}
	printk("bio_trace,init done!\n");
	return 0;

jprobe_fail:
	return -EBUSY;
}

module_init(init_main);
module_exit(cleanup_main);
MODULE_LICENSE("GPL");

