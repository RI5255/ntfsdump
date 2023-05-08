#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <files.h>

#define PATH "sc2023_sd.dd"

int main(void) { 
    int fd;
    struct stat sb;
    uint8_t *base;
    VolumeHeader *hdr;


    if((fd = open(PATH, O_RDONLY)) == -1) {
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