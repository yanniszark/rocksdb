#define _GNU_SOURCE     // for O_DIRECT
#define _ISOC11_SOURCE  // for aligned_alloc(), posix_memalign()
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>   // for madvise()
#include <sys/param.h>  // for MAX()
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/mman.h>

#include "ebpf.h"
#include "rocksdb_parser.h"

const size_t huge_page_size = 1UL << 21UL;

static void die(const char *message) {
    perror(message);
    exit(1);
}

static void __attribute__((unused)) print_block_handle(struct block_handle *handle) {
    if (handle == NULL)
        return;

    printf("Offset: %lx\n", handle->offset);
    printf("Size: %lx\n", handle->size);
}

int load_bpf_program(char *path) {
    struct bpf_object *obj;
    int ret, progfd;

    ret = bpf_prog_load(path, BPF_PROG_TYPE_XRP, &obj, &progfd);
    if (ret) {
        printf("Failed to load bpf program\n");
        exit(1);
    }

    return progfd;
}

int main(int argc, char **argv) {
    int bpf_fd, sst_fd, out_fd;
    char *filename, *key;
    uint8_t *data_buf, *scratch_buf;
    uint64_t offset;
    struct stat st;
    struct rocksdb_ebpf_context ctx;

    if (argc != 3) {
        printf("usage: ./test <sst-file> <key>\n");
        exit(1);
    }

    filename = argv[1];
    key = argv[2];

    if (strlen(key) > MAX_KEY_LEN) {
        printf("error: key is longer than 63 chars\n");
        exit(1);
    }

    bpf_fd = -1234;

    if ((sst_fd = open(filename, O_RDONLY | O_DIRECT)) == -1)
        die("open() sst file failed");

    if (fstat(sst_fd, &st) == -1)
        die("fstat() failed");

    offset = ((st.st_size - MAX_FOOTER_LEN) / EBPF_BLOCK_SIZE) * EBPF_BLOCK_SIZE;
    printf("footer offset (aligned to 512): %ld\n", offset);

    if (posix_memalign((void **) &data_buf, EBPF_SCRATCH_BUFFER_SIZE, EBPF_SCRATCH_BUFFER_SIZE) != 0)
        die("posix_memalign() failed");

    if (posix_memalign((void **) &scratch_buf, EBPF_SCRATCH_BUFFER_SIZE, EBPF_SCRATCH_BUFFER_SIZE) != 0)
        die("posix_memalign() failed");

    sleep(2);

    for (int i = 0; i < 100000; i++) {
        memset(data_buf, 0, EBPF_SCRATCH_BUFFER_SIZE);
        memset(scratch_buf, 0, EBPF_SCRATCH_BUFFER_SIZE);

        memset(&ctx, 0, sizeof(ctx));
        ctx.footer_len = st.st_size - offset;
        printf("Footer len: %lu\n", ctx.footer_len);
        ctx.stage = kFooterStage;
        sprintf(ctx.key, "%015d", i);
        memcpy(scratch_buf, &ctx, sizeof(ctx));
        printf("Key: %s\n", ctx.key);

        long ret = syscall(SYS_READ_XRP, sst_fd, data_buf, 4096, offset, bpf_fd, scratch_buf);

        printf("Return: %ld\n", ret);
        printf("%s\n", strerror(errno));

        if (ret < 0)
            die("read_xrp() failed");

        if ((out_fd = open("outfile", O_RDWR | O_CREAT | O_TRUNC, 0666)) == -1)
            die("open() failed");

        if (write(out_fd, data_buf, EBPF_DATA_BUFFER_SIZE) == -1)
            die("write() failed");

        ctx = *(struct rocksdb_ebpf_context *)scratch_buf;

        if (ctx.found == 1)
            printf("Value found: %s\n", ctx.data_context.value);
        else
            printf("Value not found\n");
    }
    free(scratch_buf);
    free(data_buf);

    close(out_fd);
    // close(sst_fd);
    close(bpf_fd);
}