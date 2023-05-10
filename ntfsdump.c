#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "ntfsdump.h"

// update sequenceを比較して、一致していたら元の値を書き戻す。(とりあえず今は一致するか確認するだけ)
static void cmpAndRestore(uint16_t *fixup, uint16_t *end) {
    if(*fixup != *(end -1)) {
        printf(
            "\tcmp %.4x %.4x\n",
            *fixup,
            *(end -1)
        );
    }

    printf(
        "\tcmp %.4x %.4x\n",
        *fixup,
        *(end -1)
    );
    
    printf(
        "\toverwirte %.4x with %.4x\n",
        *(end - 1),
        *(fixup + 1)
    );
}

// MFTEntryFlagを文字列に変換
static char * printMFTEntryFlags(uint16_t flag) {
    switch(flag) {
        case MFT_RECORD_IN_USE:
            return "MFT_RECORD_IN_USE";
        case MFT_RECORD_IS_DIRECTORY:
            return "MFT_RECORD_IS_DIRECTORY";
        case MFT_RECORD_IN_EXTEND:
            return "MFT_RECORD_IN_EXTEND";
        case MFT_RECORD_IS_VIEW_INDEX:
            return "MFT_RECORD_IS_VIEW_INDEX";
        default:
            return "";
    }
}

// AttributeTypeを文字列に変換
static char * printAttributeType(uint32_t ty) {
    switch(ty) {
        case STANDARD_INFORMATION:
            return "STANDARD_INFORMATION";
        case ATTRIBUTE_LIST:
            return "ATTRIBUTE_LIST";
        case FILE_NAME:
            return "FILE_NAME";
        case OBJECT_ID:
            return "OBJECT_ID";
        case SECURITY_DESCRIPTOR:
            return "SECURITY_DESCRIPTOR";
        case VOLUME_NAME:
            return "VOLUME_NAME";
        case VOLUME_INFORMATION:
            return "VOLUME_INFORMATION";
        case DATA:
            return "DATA";
        case INDEX_ROOT:
            return "INDEX_ROOT";
        case INDEX_ALLOCATION:
            return "INDEX_ALLOCATION";
        case BITMAP:
            return "BITMAP";
        case REPARSE_POINT:
            return "REPARSE_POINT";
        case EA_INFORMATION:
            return "EA_INFORMATION";
        case EA:
            return "EA";
        case LOGGED_UTILITY_STREAM:
            return "LOGGED_UTILITY_STREAM";
        case END_OF_ATTRIBUTE:
            return "END_OF_ATTRIBUTE";
        default:
            return "";
    }
}

// NameSpaceを文字列に変換
static char * printNameSpace(uint8_t v) {
    switch(v) {
        case POSIX:
            return "POSIX";
        case WINDOWS:
            return "WINDOWS";
        case DOS:
            return "DOS";
        case DOS_WINDOWS:
            return "DOS_WINDOS";
        default:
            return "";
    }
}

int main(int argc, char *argv[]) { 
    int fd;
    struct stat sb;

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

    uint8_t *base;
    VolumeHeader *vhdr;
    uint64_t clusterSize;
    uint64_t offset = 0;

    base = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);

    if(base == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    vhdr = (VolumeHeader *)base;
    clusterSize = vhdr->BytesPerSector * sectors_per_cluster_block(vhdr->SectorsPerClusterBlock);
    printf("VolumeHeader(+%#lx)\n", offset);
    printf(
        "BytesPerSector: %#x\nTotalNumberOfSectors: %#lx\nSectorsPerCluster: %#x\nMFTCBN: %#lx\nMFTEntrySize: %#x\n\n",
        vhdr->BytesPerSector,
        vhdr->TotalNumberOfSectors,
        sectors_per_cluster_block(vhdr->SectorsPerClusterBlock),
        vhdr->MFTClusterBlockNumber,
        entry_size(vhdr->MFTEntrySize)
    );

    // read MFT
    offset = clusterSize * vhdr->MFTClusterBlockNumber;
    MFTEntryHeader *enthdr = (MFTEntryHeader *)(base + offset);

    printf("MFT Entry(+%lx)\n", offset);
    printf(
        "Signature: %.4s\n",
        enthdr->Signature
    );
    puts("FixupValue:");
    printf(
        "\toffset: %#x\n\tnum: %#x\n",
        enthdr->FixupValueOffset,
        enthdr->NumberOfFixupValues
    );

    cmpAndRestore(
        (uint16_t *)((uint8_t *)enthdr + enthdr->FixupValueOffset),
        (uint16_t *)((uint8_t *)enthdr + enthdr->TotalEntrySize)
    );
    
    printf(
        "AttributeOffset: %#x\nUsedEntrySize: %#x\nTotalEntrySize: %#x\n",
        enthdr->AttributeOffset,
        enthdr->UsedEntrySize,
        enthdr->TotalEntrySize
    );

    printf(
        "EntryFlags: %#x(%s)\n\n",
        enthdr->EntryFlags,
        printMFTEntryFlags(enthdr->EntryFlags)
    );

    // read MFTAttributes
    offset += enthdr->AttributeOffset;
    MFTAttributeHeader *attrhdr = (MFTAttributeHeader *)(base + offset);
    NonResidentMFTAttribute *nonResidentAttr;
    ResidentMFTAttribute *regidentAttr;
    FileNameAttribute *fnameAttr;

    printf("MFT Attributes(+%#lx)\n", offset);

    while(attrhdr->AttributeType != END_OF_ATTRIBUTE) {
        printf("+%#lx\n", offset);
        printf(
            "type: %#x(%s)\nSize: %#x\nNon-resident: %#x\n",
            attrhdr->AttributeType,
            printAttributeType(attrhdr->AttributeType),
            attrhdr->Size,
            attrhdr->NonRegidentFlag
        );

        if(attrhdr->NonRegidentFlag) {
            // Non-residentだった場合
            nonResidentAttr = (NonResidentMFTAttribute *)((uint8_t *)attrhdr + sizeof(MFTAttributeHeader));
            printf(
                "Data Runs Offset: %#x\nDataSize: %#lx\n",
                nonResidentAttr->DataRunsOffset,
                nonResidentAttr->DataSize
            );
        } else {
            // Residentだった場合
            regidentAttr = (ResidentMFTAttribute *)((uint8_t *)attrhdr + sizeof(MFTAttributeHeader));
            printf(
                "DataSize: %#x\nData Offset: %#x\n",
                regidentAttr->DataSize,
                regidentAttr->DataOffset
            );
            // FileName属性がNon-residentになることはあるのか？
            if(attrhdr->AttributeType == FILE_NAME) {
                fnameAttr = (FileNameAttribute *)((uint8_t *)attrhdr + regidentAttr->DataOffset);
            }
        }

        putchar('\n');

        offset += attrhdr->Size;
        attrhdr = (MFTAttributeHeader *)(base + offset);
    }

    // ファイル名を表示
    printf(
        "NameSpace: %#x(%s)\nFileName : ",
        fnameAttr->Namespace,
        printNameSpace(fnameAttr->Namespace)
    );
    for(int i = 0; i < fnameAttr->NameStringSize; i++) {
        printf("%c", fnameAttr->Name[i * 2]);
    }
    putchar('\n');

    munmap((void *)base, sb.st_size);
    close(fd);

    return 0;
}