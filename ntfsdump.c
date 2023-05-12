#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "ntfsdump.h"

Info info;

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

// Non-residentだったときに使う。
static void parseRunsList(uint8_t *l) {
    // 先頭1byteの下位4bitがdataの長さを、上位4bitがoffsetの長さをbyte単位で表す。
    int i = 0;
    uint8_t dataLen, deltaLen;
    uint64_t len = 0;
    // delataは符号付で、前のrunsのoffsetからの相対値(クラスタ単位)になる。
    int64_t delta = 0, offset = 0;

    puts("Data run list");
    dataLen  = l[i] & 0x0f;
    deltaLen = (l[i]>>4) & 0x0f;
    i++;

    while(dataLen && deltaLen) {
        for(int j = 0; j < dataLen; j++) {
            len += l[i++] << 8 * j;
        }
        for(int j = 0; j < deltaLen; j++) {
            delta += l[i++] << 8 * j;
        }
        offset += delta;
        printf(
            "dataLen: %#lx delta: %+ld offset: %+ld\n",
            len,
            delta,
            offset
        );
        len = delta = 0;
        dataLen  = l[i] & 0x0f;
        deltaLen = (l[i]>>4) & 0x0f;
        i++;
    };
}

static void parseFnameAttribute(FileNameAttribute *attr) {
    // ファイル名を表示
    printf(
        "NameSpace: %#x(%s)\nFileName : ",
        attr->Namespace,
        printNameSpace(attr->Namespace)
    );
    for(int i = 0; i < attr->NameStringSize; i++) {
        printf("%c", attr->Name[i * 2]);
    }
    putchar('\n');
}

static void parseFname(MFTAttributeHeader *hdr) {
    ResidentMFTAttribute *regidentAttr;
    FileNameAttribute *fnameAttr;
    
    if(hdr->NonRegidentFlag) {
        // Non-residentだった場合はとりあえずData run listを表示するだけ
        parseRunsList(data_run_list(hdr));
    } else {
        parseFnameAttribute(fname_attribute(hdr));
    }
}

static void parseData(MFTAttributeHeader *hdr) {
    if(hdr->NonRegidentFlag) {
        // Non-residentだった場合はとりあえずData run listを表示するだけ
        parseRunsList(data_run_list(hdr));
    } else {
        // Residentだった場合はデータがある。
        printf(
            "Data offset: %#x Data size: %#x\n",
            ((ResidentMFTAttribute *)attr(hdr))->DataOffset,
            ((ResidentMFTAttribute *)attr(hdr))->DataSize
        );
    }
}

// MFTAttributeの基本情報を表示
static void printMFTAttributeInfo(MFTAttributeHeader *hdr) {
    // 全てのAttribute共通の情報を表示
    printf(
        "type: %#x(%s)\nSize: %#x\nNon-resident: %#x\n",
        hdr->AttributeType,
        printAttributeType(hdr->AttributeType),
        hdr->Size,
        hdr->NonRegidentFlag
    );
}

static void parseMFTAttribute(MFTAttributeHeader *hdr) {
    printMFTAttributeInfo(hdr);

    // Attributeの種類に応じて追加の処理を行う。
    switch (hdr->AttributeType) {
        case FILE_NAME:
            parseFname(hdr);
            break;
        case DATA:
            parseData(hdr);
            break;
    }
}

// 壊れたファイルの場合に使用する。
static void tryToParseMFTAttribute(MFTAttributeHeader *hdr) {
    printMFTAttributeInfo(hdr);

    if(hdr->NonRegidentFlag) {
        // Non-residentだった場合はとりあえずData run listを表示するだけ
        parseRunsList(data_run_list(hdr));
    } else {
        // Residentだった場合はデータがある。
        printf(
            "Data offset: %#x Data size: %#x\n",
            ((ResidentMFTAttribute *)attr(hdr))->DataOffset,
            ((ResidentMFTAttribute *)attr(hdr))->DataSize
        );
    }
}

static void parseMFTAttributes(MFTAttributeHeader *hdr) {
    puts("MFT Attributes");

    while(hdr->AttributeType != END_OF_ATTRIBUTE) {
        printf("+%#lx\n", (uint8_t *)hdr - info.Base);
        parseMFTAttribute(hdr);
        putchar('\n');
        hdr = next_attr(hdr);
    }
}

// 壊れたファイルの場合に使用する。
static void tryToParseMFTAttributes(MFTAttributeHeader *hdr) {
    while(hdr->AttributeType && hdr->AttributeType != END_OF_ATTRIBUTE) {
        printf("+%#lx\n", (uint8_t *)hdr - info.Base);
        tryToParseMFTAttribute(hdr);
        putchar('\n');
        hdr = next_attr(hdr);
    }
}

static void parseMFTEntry(uint64_t i) {
    MFTEntryHeader *hdr = (MFTEntryHeader *)((uint8_t *)info.EntryTable.Hdr[0] + info.MFTEntrySize * i);
    printf(
        "MFT Entry(+%#lx)\n",
        (uint8_t *)hdr - info.Base
    );
    printf(
        "Signature: %.4s\n",
        hdr->Signature
    );
    puts("FixupValue:");
    printf(
        "\toffset: %#x\n\tnum: %#x\n",
        hdr->FixupValueOffset,
        hdr->NumberOfFixupValues
    );

    cmpAndRestore(
        (uint16_t *)((uint8_t *)hdr + hdr->FixupValueOffset),
        (uint16_t *)((uint8_t *)hdr + hdr->TotalEntrySize)
    );
    
    printf(
        "AttributeOffset: %#x\nUsedEntrySize: %#x\nTotalEntrySize: %#x\n",
        hdr->AttributeOffset,
        hdr->UsedEntrySize,
        hdr->TotalEntrySize
    );

    printf(
        "EntryFlags: %#x(%s)\n\n",
        hdr->EntryFlags,
        printMFTEntryFlags(hdr->EntryFlags)
    );

    MFTAttributeHeader *attrhdr = (MFTAttributeHeader *)((uint8_t *)hdr + hdr->AttributeOffset);

    if(hdr->EntryFlags == MFT_RECORD_IN_USE || hdr->EntryFlags == 0x0003) {
        parseMFTAttributes(attrhdr);
    } else {
        tryToParseMFTAttributes(attrhdr);
    }
}

// MFTEntryに含まれるAttributeから指定した種類のものを探す
static MFTAttributeHeader * findAttribute(MFTEntryHeader *hdr, AttributeTypes ty) {
    MFTAttributeHeader *attr = (MFTAttributeHeader *)((uint8_t *)hdr + hdr->AttributeOffset);
    int64_t remain = hdr->UsedEntrySize - hdr->AttributeOffset;

    while(1) {
        if(attr->AttributeType == ty)
            return attr;
        
        remain -= attr->Size;
        if(remain <= 0)
            return NULL;
        
        attr = (MFTAttributeHeader *)((uint8_t *)attr + attr->Size);        
    }
}

static void collectInfo(VolumeHeader *hdr) {
    // 重要な情報をグローバルに保存
    info = (Info){
        .Base           = (uint8_t *)hdr,
        .ClusterSize    = cluster_size(hdr),
        .MFTEntrySize   = entry_size(hdr->MFTEntrySize)
    };

    // 最初のエントリは$MFT。
    MFTEntryHeader *entry = (MFTEntryHeader *)((uint8_t *)hdr + info.ClusterSize * hdr->MFTClusterBlockNumber);
    MFTAttributeHeader *data = findAttribute(entry, DATA);
   
    if(!data)
        exit(1);

    info.EntryTable.NonResidentFlag = data->NonRegidentFlag;

    if(info.EntryTable.NonResidentFlag) {
        // 先頭1byteの下位4bitがdataの長さを、上位4bitがoffsetの長さをbyte単位で表す。
        int i = 0;
        uint8_t dataLen, deltaLen;
        uint64_t len = 0;
        // delataは符号付で、前のrunsのoffsetからの相対値(クラスタ単位)になる。
        int64_t offset = 0;
        uint8_t *l = data_run_list(data);

        dataLen  = l[i] & 0x0f;
        deltaLen = (l[i]>>4) & 0x0f;
        i++;

        // とりあえず一番最初のdata runのみ読む。
        for(int j = 0; j < dataLen; j++) {
            len += l[i++] << 8 * j;
        }
        for(int j = 0; j < deltaLen; j++) {
            offset += l[i++] << 8 * j;
        }

        info.EntryTable.NumEntry = len * info.ClusterSize / info.MFTEntrySize;
        info.EntryTable.Hdr[0] = (MFTEntryHeader *)((uint8_t *)hdr +  offset * info.ClusterSize);

    } else {
        info.EntryTable.NumEntry = ((ResidentMFTAttribute *)attr(data))->DataSize / info.MFTEntrySize;
        info.EntryTable.Hdr[0] = (MFTEntryHeader *)((uint8_t *)data + ((ResidentMFTAttribute *)attr(data))->DataOffset);
    }
}

static void parseVolume(VolumeHeader *hdr) {
    collectInfo(hdr);
    uint64_t i;
    printf(
        "Cluster size: %#lx\nMFTEntrySize: %#lx\nNumEntry: %#lx\n",
        info.ClusterSize,
        info.MFTEntrySize,
        info.EntryTable.NumEntry
    );

    while(true) {
        printf("index: ");

        scanf("%lu", &i);
        putchar('\n');
        
        if(info.EntryTable.NumEntry <= i) {
            puts("invalid index");
            continue;
        }

        // 指定されたindexのMFTEntryを解析
        parseMFTEntry(i);
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

    base = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);

    if(base == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    parseVolume((VolumeHeader *)base);

    munmap((void *)base, sb.st_size);
    close(fd);

    return 0;
}