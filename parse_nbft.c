#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <asm/byteorder.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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

/*
 * Helper functions to parse data properly.
 */
static int parse_ipaddr(const __u8 *ip, char *buf)
{
	unsigned char in[sizeof(struct in6_addr)];
        int ret;

        if (ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 &&
            ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
            ip[8] == 0 && ip[9] == 0 && ip[10] == 0xff && ip[11] == 0xff) {
                /*
                 * IPV4
                 */
		memcpy(in, ip + 12, 4);
		if (!inet_ntop(AF_INET, in, buf, INET6_ADDRSTRLEN))
			ret = -1;
        } else {
                /*
                 * IPv6
                 */
		memcpy(in, ip, 16);
		if (!inet_ntop(AF_INET6, in, buf, INET6_ADDRSTRLEN))
			ret = -1;
        }
	return ret;
}

int fetch_nbft_heap_obj(void *map, nbft_heap_obj *obj, char *buf)
{
	struct nbft_header *hdr = map;

	if (obj->length == 0) {
		buf[0] = '\0';
		return 0;
	}
	if (obj->offset < hdr->heap_offset) {
		fprintf(stderr,"offset mismatch (heap %d, offset %d)\n",
			hdr->heap_offset, obj->offset);
		return -EINVAL;
	}
	if (obj->offset + obj->length > hdr->heap_offset + hdr->heap_length) {
		fprintf(stderr, "length mismatch (heap %d + %d, offset %d + %d)\n",
			hdr->heap_offset, hdr->heap_length,
			obj->offset, obj->length);
		return -EINVAL;
	}
	memcpy(buf, map + obj->offset, obj->length);
	return obj->length;
}

int parse_nbft_control(void *map)
{
	struct nbft_control *nctrl;
	struct nbft_host_desc *hdesc;
	struct nbft_hfi_desc *hfi;
	char id[64];
	char nqn[256];
	int len, hfi_idx;

  	nctrl = map + 64;
	printf("NBFT control len %d #HFI %d #NS %d #SEC %d #DISC %d\n",
	       nctrl->length, nctrl->hfi.num_desc, nctrl->ssns.num_desc,
	       nctrl->security.num_desc, nctrl->discovery.num_desc);

	hdesc = map + nctrl->host.offset;
	if (!memcmp(hdesc->identifier, invalid_uuid, 16))
		sprintf(id, "<invalid>");
	else if (uuid_is_null(hdesc->identifier))
		sprintf(id, "<unset>");
	else
		uuid_unparse(hdesc->identifier, id);
	len = fetch_nbft_heap_obj(map, &hdesc->nqn, nqn);
	if (len < 0 || !strlen(nqn))
		sprintf(nqn, "<invalid>");
	printf("NBFT host: id %s nqn %s\n", id, nqn);

	for (hfi_idx = 0; hfi_idx < nctrl->hfi.num_desc; hfi_idx++) {
		struct nbft_hfi_info_tcp_desc *hfi_tdesc;
		char ipaddr[INET6_ADDRSTRLEN];
		char gateway[INET6_ADDRSTRLEN];

		hfi = map + nctrl->hfi.offset + (hfi_idx * sizeof(*hfi));
		printf("HFI %d: transport %d\n",
		       hfi->index, hfi->transport_type);
		if (hfi->transport_type != 3 ||
		    hfi->transport_descriptor.offset == 0)
			continue;
		hfi_tdesc = map + hfi->transport_descriptor.offset;
		parse_ipaddr(hfi_tdesc->ip_address, ipaddr);
		parse_ipaddr(hfi_tdesc->ip_gateway, gateway);
		printf("HFI %d: address %s/%d gateway %s\n",
		       hfi_tdesc->hfi_index, ipaddr,
		       hfi_tdesc->subnet_mask_prefix, gateway);
	}
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
