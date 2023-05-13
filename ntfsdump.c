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

// DATAがNon-residentだったときに使う。
static void printDataList(uint8_t *l) {
    // 先頭1byteの下位4bitがdataの長さを、上位4bitがoffsetの長さをbyte単位で表す。
    int i = 0;
    uint8_t dataLen, deltaLen;
    uint64_t len = 0;
    // delataは符号付で、前のrunsのoffsetからの相対値(クラスタ単位)になる。
    int64_t delta = 0, offset = 0;

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
            "+%#lx %#lx\n",
            offset * info.ClusterSize,
            len * info.ClusterSize
        );
        len = delta = 0;
        dataLen  = l[i] & 0x0f;
        deltaLen = (l[i]>>4) & 0x0f;
        i++;
    };
}

// Windows時間を文字列に変換する。(秒単位の誤差が出る)
static char * time2str(time_t t) {
    struct tm *p;
    char *buf = calloc(1, 30);

    t /= 0x989680L; // 秒単位に直す
    t -= 0x20e76L * 0x15180L; // unix timeに変換

    p = localtime(&t);

    snprintf(
        buf,
        30,
        "%d-%d-%d %d:%d:%d (JST)",
        p->tm_year + 1900,
        p->tm_mon + 1,
        p->tm_mday,
        p->tm_hour,
        p->tm_min,
        p->tm_sec
    );

    return buf;
}

static void parseFnameAttribute(MFTAttributeHeader *hdr) {
    puts("FILE_NAME:");

     // Non-residentだった場合はとりあえず何もしない
    if(hdr->NonRegidentFlag)
        return;
    
    FileNameAttribute *attr = fname_attribute(hdr);
    
    // 使い方合ってるかは知らん。まあ動いてるのでヨシ!
    setlocale(LC_ALL, "en_US.UTF-8");
    size_t n = 0;
    char fname[100] = {0};
    mbstate_t ps = {0};

    size_t len = 0;
    for(int i = 0; i < attr->NameStringSize; i++) {
        n  = c16rtomb(fname + len, attr->Name[i], &ps);
        len += n;
    }
    printf("name: %s\n", fname);

    // 作成日時と最終変更日時を表示(秒は誤差がある。)
    printf(
        "CTime: %s\nMTime: %s\n\n",
        time2str(attr->CTime),
        time2str(attr->MTime)
    );
}

static void parseDataAttribute(MFTAttributeHeader *hdr) {
    puts("Data:");
    puts("offset size");

    if(hdr->NonRegidentFlag) {
       printDataList(data_run_list(hdr));
    } else {
        printf(
            "+%#lx %#x\n",
            (uint8_t *)hdr - info.Base + ((ResidentMFTAttribute *)attr(hdr))->DataOffset,
            ((ResidentMFTAttribute *)attr(hdr))->DataSize
        );
    }
    putchar('\n');
}

static void parseMFTEntry(uint64_t i) {
    MFTEntryHeader *ehdr = (MFTEntryHeader *)((uint8_t *)info.EntryTable.Hdr[0] + info.MFTEntrySize * i);
    // 未使用の領域なら、AttributeOffsetは0になっているだろうという予想。本当は$BITMAPを読むべき。
    if(!ehdr->AttributeOffset) {
        puts("unused entry");
        return;
    }

    printf(
        "MFT Entry(+%#lx)\n",
        (uint8_t *)ehdr - info.Base
    );
    printf(
        "Signature: %.4s\n",
        ehdr->Signature
    );
    puts("FixupValue:");
    printf(
        "\toffset: %#x\n\tnum: %#x\n",
        ehdr->FixupValueOffset,
        ehdr->NumberOfFixupValues
    );

    cmpAndRestore(
        (uint16_t *)((uint8_t *)ehdr + ehdr->FixupValueOffset),
        (uint16_t *)((uint8_t *)ehdr + ehdr->TotalEntrySize)
    );
    
    printf(
        "UsedEntrySize: %#x\nTotalEntrySize: %#x\n",
        ehdr->UsedEntrySize,
        ehdr->TotalEntrySize
    );

    printf(
        "EntryFlags: %#x\n\n",
        ehdr->EntryFlags
    );


    MFTAttributeHeader *ahdr = (MFTAttributeHeader *)((uint8_t *)ehdr + ehdr->AttributeOffset);
    MFTAttributeHeader *fname = NULL, *data = NULL;
    
    // MFTEntryに含まれるMFTAttributeの一覧を表示する。
    puts("Attributes:");
    puts("offset type size non-resident?");
    while(ahdr->AttributeType != END_OF_ATTRIBUTE) {
        printf(
            "+%#lx: %#x(%s) %#x %d\n",
            (uint8_t *)ahdr - info.Base,
            ahdr->AttributeType,
            printAttributeType(ahdr->AttributeType),
            ahdr->Size,
            ahdr->NonRegidentFlag
        );
        
        switch(ahdr->AttributeType) {
            case FILE_NAME:
                fname = ahdr;
                break;
            case DATA:
                data = ahdr;
                break;
        }

        ahdr = next_attr(ahdr);
    }
    putchar('\n');

    if(fname)
        parseFnameAttribute(fname);
    if(data)
        parseDataAttribute(data);
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