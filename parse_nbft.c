#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <asm/byteorder.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include <uuid/uuid.h>

#include "nbft_tables.h"

const unsigned char nbft_sig[4] = "NBFT";
const __u8 invalid_uuid[16] = {
	0xff, 0xff, 0xff, 0Xff,
	0xff, 0xff, 0xff, 0Xff,
	0xff, 0xff, 0xff, 0Xff,
	0xff, 0xff, 0xff, 0Xff
};

int fetch_nbft_heap_obj(void *map, nbft_heap_obj *obj, char *buf)
{
	struct nbft_header *hdr = map;

	if (obj->offset < hdr->heap_offset) {
		fprintf(stderr,"offset mismatch (heap %d, offset %d)\n",
			hdr->heap_offset, obj->offset);
		return -EINVAL;
	}
	if (obj->offset + obj->length > hdr->heap_offset + hdr->heap_length) {
		fprintf(stderr,"length mismatch (heap %d + %d, offset %d + %d)\n",
			hdr->heap_offset, hdr->heap_length,
			obj->offset, obj->length);
		return -EINVAL;
	}
	if (obj->length == 0)
		buf[0] = '\0';
	else
		memcpy(buf, map + obj->offset, obj->length);
	return obj->length;
}

int parse_nbft_control(void *map)
{
	struct nbft_control *nctrl;
	struct nbft_host_desc *hdesc;
	char id[64];
	char nqn[256];

  	nctrl = map + 64;
	printf("NBFT control len %d #HFI %d #NS %d #SEC %d #DISC %d\n",
	       nctrl->length, nctrl->hfi.num_desc, nctrl->ssns.num_desc,
	       nctrl->security.num_desc, nctrl->discovery.num_desc);

	hdesc = map + nctrl->host.offset;
	if (!memcmp(hdesc->identifier, invalid_uuid, 16))
		sprintf(id, "<invalid>");
	else
		uuid_unparse(hdesc->identifier, id);
	fetch_nbft_heap_obj(map, &hdesc->nqn, nqn); 
	printf("NBFT host: id %s nqn %s\n", id, nqn);
	return 0;
}

int parse_nbft(void *map, size_t map_len)
{
	struct nbft_header *hdr;

	hdr = map;
	if (memcmp(hdr->signature, nbft_sig, 4)) {
		printf("Invalid signature %c%c%c%c\n",
		       hdr->signature[0], hdr->signature[1],
		       hdr->signature[2], hdr->signature[3]);
		return -1;
	}
	printf("NBFT table, len %d\n", hdr->length);
	if (hdr->major_revision != 1) {
		printf("Unsupported NBFT major Revision %d\n",
		       hdr->major_revision);
		return -1;
	}
	printf("NBFT OEM '%s' table '%s'\n", hdr->oem_id, hdr->oem_table_id);
	printf("NBFT Heap offset %d len %d\n",
	       hdr->heap_offset, hdr->heap_length);
	return parse_nbft_control(map);
}

int main(int argc, char **argv)
{
	int fd, ret;
	struct stat st;
	void *fp;

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}
	if (fstat(fd, &st) < 0) {
		perror("stat");
		close(fd);
		return 1;
	}
	fp = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (fp == MAP_FAILED) {
		perror("mmap");
		close(fd);
		return 1;
	}
	close(fd);
	ret = parse_nbft(fp, st.st_size);
	munmap(fp, st.st_size);
	return ret ? 1 : 0;
}
