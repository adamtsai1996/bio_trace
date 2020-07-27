#include "common.h"
void get_page_filename(struct page *page, char* output)
{
    int i, j, k; 
    struct dentry *p;

    unsigned char unknown[] = "unknown", null[]="NULL";
    unsigned char *pname;
    struct hlist_head *head;
    pname = null;
    i = j = k = 0;
    /* get filename */
    if(page && 
            page->mapping && 
            ((unsigned long) page->mapping & PAGE_MAPPING_ANON) == 0  && 
            page->mapping->host )
    {
        p = NULL ; 
        head = &(page->mapping->host->i_dentry);
        if( hlist_empty(head)) {
            goto END;
        }            
        p = hlist_entry_safe(head->first, struct dentry, d_alias);
        //p = list_first_entry(&(bio_page->mapping->host->i_dentry), struct dentry, d_alias);
        if(p != NULL ) {
            pname = p->d_iname;
            for(j = 0 ; j < strlen(p->d_iname); j++){
                if( (p->d_iname[j]!= '\0')  &&  ( (p->d_iname[j] < 32) || (p->d_iname[j] > 126))){ 
                    pname = unknown;
                    break;
                }
            }
			if(!strlen(pname))
				pname = null;
        }

    }
    if(pname != unknown &&  pname != null)
    {
        memcpy(output, pname, DNAME_INLINE_LEN);
		return;
    }
END:
    if(pname == unknown)
        memcpy(output, pname, 7 + 1);
    if(pname == null)
        memcpy(output, pname, 7 + 1);
    return;
}

void set_timestamp(struct timespec *cur_time, struct timespec *start_time)
{
    *cur_time = current_kernel_time();
    cur_time->tv_sec -= start_time->tv_sec;
    cur_time->tv_nsec -= start_time->tv_nsec;
    if(cur_time->tv_nsec < 0) {
        cur_time->tv_sec --;
        cur_time->tv_nsec += 1000000000L;
    }
    return;
}
int get_page_data(struct page *p, char *output)
{
    void *vpp = NULL;
    if(!p)
        return -1;
    vpp = kmap_atomic(p);
    if(!vpp)
        return -1;
    memcpy(output, (char *)vpp, PAGE_SIZE);
    kunmap_atomic(vpp);
    vpp = NULL;
    return 0;
}
void char_to_hex(char *in, char *out, int in_len)
{
    int i;
    for(i = 0; i < in_len ; i++) {
        sprintf(out+i*2, "%02x", in[i]); 
    }
    out[in_len*2] = '\0';
    return ;
}
unsigned int  murmur_hash(uint32_t seed, unsigned int hash_size,  uint32_t key, uint32_t key_length) 
{
  uint32_t m = 0x5bd1e995;
  uint32_t r = 24;
  uint32_t h = seed ^ key_length;
  char * data = (char *)&key;

  while(key_length >= 4) {
    uint32_t k = key;
    k *= m;
    k ^= k >> r;
    k *= m;
    h *= m;
    h ^= k;
    data += 4;
    key_length -= 4;
  }
  
  switch(key_length) {
    case 3: h ^= data[2] << 16;
    case 2: h ^= data[1] << 8;
    case 1: h ^= data[0];
            h *= m;
  };

  h ^= h >> 13;
  h *= m;
  h ^= h >> 15;
  return h % hash_size;
}

int get_lzo_zsize(struct page *page)
{
	unsigned char *wrkmem=NULL, *dst=NULL, *data=NULL;
	int len=0;

	wrkmem=vmalloc(LZO1X_1_MEM_COMPRESS);
	if (!wrkmem) {
		return 0;
	}
	dst = vmalloc(lzo1x_worst_compress(PAGE_SIZE));
	if (!dst) {
		vfree(wrkmem);
		return 0;
	}
	data=(unsigned char *)kmap_atomic(page);
	if (!data) {
		vfree(wrkmem);
		vfree(dst);
		return 0;
	}

	lzo1x_1_compress(data,PAGE_SIZE,dst,&len,wrkmem);
	kunmap_atomic(data);
	vfree(wrkmem);
	vfree(dst);

	return len;
}

// refer to fs/proc/task_mmu.c:show_map_vma
void get_vma_name(struct task_struct *task, struct mm_struct *mm,
		struct vm_area_struct *vma, char *vma_name)
{
	struct file *file=vma->vm_file;
	const char *const_name=NULL;
	
	if (file) {
		sprintf(vma_name,"%s",file->f_path.dentry->d_name.name);
		return;
	}

	const_name = arch_vma_name(vma);
	if (!const_name) {
		if (!mm) {
			const_name = "[vdso]";
		} else if (vma->vm_start <= mm->brk && vma->vm_end >= mm->start_brk) {
			const_name = "[heap]";
		} else {
			if (task&&vm_is_stack(task,vma,1)) {
				const_name = "[stack]";
			} else if (vma_get_anon_name(vma)) {
				const char __user *user_name = vma_get_anon_name(vma);
				unsigned long page_start_vaddr;
				unsigned long page_offset;
				unsigned long num_pages;
				unsigned long max_len=255;
				int write_len, i;

				page_start_vaddr = (unsigned long)user_name & PAGE_MASK;
				page_offset = (unsigned long)user_name - page_start_vaddr;
				num_pages = DIV_ROUND_UP(page_offset+max_len, PAGE_SIZE);

				write_len = sprintf(vma_name,"[anon:");
				for (i=0;i<num_pages;i++) {
					int len;
					const char *kaddr;
					long pages_pinned;
					struct page *page;

					pages_pinned = get_user_pages(NULL,mm,page_start_vaddr,1,0,0,&page,NULL);
					if (pages_pinned<1) {
						sprintf(vma_name+write_len,"<fault>]");
						return;
					}

					kaddr = (const char*)kmap(page);
					len = strnlen(kaddr+page_offset,min(max_len,PAGE_SIZE-page_offset));
					memcpy(vma_name+write_len,kaddr+page_offset,len);
					write_len+=len;
					kunmap(page);
					put_page(page);

					if (len!=min(max_len,PAGE_SIZE-page_offset)) break;

					max_len-=len;
					if(max_len<=0) break;

					page_offset=0;
					page_start_vaddr+=PAGE_SIZE;
				}
				sprintf(vma_name+write_len,"]");
				return;
			} else {
				const_name = "[anon]";
			}
		}
	}
	sprintf(vma_name,"%s",const_name);
}




