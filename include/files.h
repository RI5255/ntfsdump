#ifndef __FILES_H__
#define __FILES_H__

#include <stdint.h>
#include <macros.h>

typedef struct __attribute__((packed)) {
    uint8_t     Entry[3];
    uint8_t     OEM[8];
    uint16_t    BytesPerSector;
    uint8_t     SectorsPerClusterBlock;
    uint16_t    Unknown;
    uint8_t     Unused;
    uint16_t    Unused;
    uint16_t    Unknown;
    uint8_t     MediaDescriptor;
    uint16_t    Unused;
    uint16_t    Unused;
    uint16_t    Unused;
    uint32_t    Unused;
    uint32_t    Unknown;
    uint8_t     Unknown;
    uint8_t     Unknown;
    uint8_t     Unknown;
    uint8_t     Unknown;
    uint64_t    TotalNumberOfSectors;
    uint64_t    MFTClusterBlockNumber;
    uint64_t    MirrorMFTClusterBlockNumber;
    uint8_t     MFTEntrySize;
    uint8_t     Unknown[3];
    uint8_t     IndexEntrySize;
    uint8_t     Unknown[3];
    uint64_t    NTFSVolumeSerialNumber;
    uint32_t    Unused;
    uint8_t     BootCode[426];
    uint16_t    SectorSignature;
} VolumeHeader;

#define entry_size(s) (128 <= (s) ? 1 << (256 - (s)) : (s))
#define sectors_per_cluster_block(s) (244 <= (s) ? 1<<(256 - (s)) : (s))

#endif 