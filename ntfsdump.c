#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "ntfsdump.h"

int main(int argc, char *argv[]) { 
    int fd;
    struct stat sb;
    uint8_t *base;
    VolumeHeader *hdr;

    if(argc != 2) {
        puts("Usage: ./ntfsdump <path>");
        exit(1);
    }

    if((fd = open(argv[1], O_RDONLY)) == -1) {
        perror("open: ");
        exit(1);
    }

    if(fstat(fd, &sb) == -1) {
        perror("fstat: ");
        exit(1);
    }

    base = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);

    if(base == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    hdr = (VolumeHeader *)base;

    printf("BytesPerSector\tTotalNumberOfSectors\tSectorsPerCluster\tMFTCBN\tMFTEntrySize\n");
    printf(
        "%#x\t\t%#lx\t\t\t%#x\t\t\t%#lx\t%#x\n",
        hdr->BytesPerSector,
        hdr->TotalNumberOfSectors,
        sectors_per_cluster_block(hdr->SectorsPerClusterBlock),
        hdr->MFTClusterBlockNumber,
        entry_size(hdr->MFTEntrySize)
    );

    munmap((void *)base, sb.st_size);

    return 0;
}