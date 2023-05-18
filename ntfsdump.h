#ifndef __NTFS_DUMP_H__
#define __NTFS_DUMP_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <uchar.h>
#include <locale.h>
#include <time.h>
#include <string.h>

// useful macros
#define MERGE(a,b)  a##b
#define LABEL1(a) MERGE(_unknown, a)
#define LABEL2(a) MERGE(_unused, a)
#define Unknown LABEL1(__LINE__)
#define Unused  LABEL2(__LINE__)

// VolumeHeader is defined on 4
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
// hdrはVolumeHeader*型
#define cluster_size(hdr) (hdr->BytesPerSector * sectors_per_cluster_block(hdr->SectorsPerClusterBlock))
#define sectors_per_cluster_block(s) (244 <= (s) ? 1<<(256 - (s)) : (s))

// MFTEntryHeader dedined on 5
typedef struct __attribute__((packed)) {
    uint64_t    MFTEntryIndex   : 48;
    uint16_t    SequenceNumber  : 16;
} FileReference;

typedef struct __attribute__((packed)) {
    uint8_t         Signature[4]; 
    uint16_t        FixupValueOffset;
    uint16_t        NumberOfFixupValues;
    uint64_t        LSNOfLogfile;
    uint16_t        Sequence;
    uint16_t        RefCount;
    uint16_t        AttributeOffset;
    uint16_t        EntryFlags;
    uint32_t        UsedEntrySize;
    uint32_t        TotalEntrySize;
    FileReference   BaseRecordFileRefs;
    uint16_t        FirstAvailableAttributeIndentifer;
    uint16_t        Unknown;
    uint32_t        Unknown;
} MFTEntryHeader;

// hdrはMFTEntryHeader*型
#define attr_hdr(hdr) ((MFTAttributeHeader *)((uint8_t *)hdr + hdr->AttributeOffset))

// MFTAttributeHeader defined on 5.5.1
typedef struct __attribute__((packed)) {
    uint32_t    AttributeType;
    uint32_t    Size;
    uint8_t     NonRegidentFlag; // 0 = RESIDENT_FORM, 1 = NONRESIDENT_FORM
    uint8_t     NameSize;
    uint16_t    NameOffset;
    uint16_t    AttributeDataFlags;
    uint16_t    AttributeIdentifier; // or Instance
} MFTAttributeHeader;

// AttributeTypes defined on 6.1
typedef enum {
    STANDARD_INFORMATION    =   0x00000010,
    ATTRIBUTE_LIST          =   0x00000020,
    FILE_NAME               =   0x00000030,
    OBJECT_ID               =   0x00000040, 
    SECURITY_DESCRIPTOR     =   0x00000050,
    VOLUME_NAME             =   0x00000060,
    VOLUME_INFORMATION      =   0x00000070,
    DATA                    =   0x00000080,
    INDEX_ROOT              =   0x00000090,
    INDEX_ALLOCATION        =   0x000000a0,
    BITMAP                  =   0x000000b0,
    REPARSE_POINT           =   0x000000c0,
    EA_INFORMATION          =   0x000000d0,
    EA                      =   0x000000e0,
    LOGGED_UTILITY_STREAM   =   0x00000100,
    END_OF_ATTRIBUTE        =   0xffffffff,
} AttributeTypes;

typedef enum {
    ATTRIBUTE_FLAG_COMPRESSION_MASK = 0x00ff,
    ATTRIBUTE_FLAG_ENCRYPTED        = 0x4000,
    ATTRIBUTE_FLAG_SPARSE           = 0x8000
} MFTAttributeDataFlags;

// hdrはMFTAttributeHeader*型。
#define attr(hdr) ((uint8_t *)hdr + sizeof(MFTAttributeHeader))

// hdrはMFTAttributeHeader*型。
#define next_attr(hdr) ((MFTAttributeHeader *)((uint8_t *)hdr + hdr->Size))

// ResidentMFTAttribute defined on 5.5.2
typedef struct __attribute__((packed)) {
    uint32_t    DataSize;
    uint16_t    DataOffset; // from MFTAttributeHeader
    uint8_t     IndexedFlag;
    uint8_t     Padding;
} ResidentMFTAttribute;

// NonResidentMFTAttribute defined on 5.5.3
typedef struct __attribute__((packed)) {
    uint64_t    FirstVCNOfData;
    uint64_t    LastVCNOfData;
    uint16_t    DataRunsOffset;
    uint16_t    CompressionUnitSize;
    uint32_t    Padding;
    uint64_t    AllocatedDataSize;
    uint64_t    DataSize;
    uint64_t    ValidDataSize;
    // uint64_t    TotalAllocatedSize; used if CompressionUnitSize > 0
} NonResidentMFTAttribute;

// hdrはMFTEntryHeader*型。
#define data_run_list(hdr) ((uint8_t *)hdr + ((NonResidentMFTAttribute *)attr(hdr))->DataRunsOffset)

// FileNameAttribute defined on 6.4
typedef struct __attribute__((packed)) {
    uint64_t    ParentFileRef;
    time_t      CTime; // creation data and time
    time_t      WTime; // last written data and time
    time_t      MTime; // last modification data and time
    time_t      ATime; // last access data and time
    uint64_t    AllocatedFileSize;
    uint64_t    FileSize;
    uint32_t    FileAttributeFlags;
    uint32_t    ExtendedData;
    uint8_t     NameStringSize;
    uint8_t     Namespace;
    char16_t    Name[];
} FileNameAttribute;

// NameSpace defined on 6.4.1
typedef enum {
    POSIX,
    WINDOWS,
    DOS,
    DOS_WINDOWS
} NameSpace;

// hdrはMFTEntryHeader*型かつResident。
#define fname_attribute(hdr) ((FileNameAttribute *)((uint8_t *)hdr + ((ResidentMFTAttribute *)attr(hdr))->DataOffset))

typedef struct {
    int cap;
    int len;
    void **data;
} List;

typedef enum {
    D,  // Data
    A,  // Attribute
} ListType;

typedef struct {
    void        *p;
    uint64_t    size;
} Data;

typedef struct {
    uint8_t         *base;
    uint16_t        bytesPerSector;
    uint64_t        clusterSize;
    uint64_t        mftEntrySize;
    uint64_t        mftOffset;
} Volume;

typedef struct {
    char *name;
    char *CTIME;
    char *MTIME;
    List *attr; // Fileが持つ全てのAttributeのリスト
    List *data; // Fileが持つデータのリスト
} File;

#endif 