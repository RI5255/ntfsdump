#include "ntfsdump.h"

static Volume volume;
static File *mft;

static List * newList(int n) {
    List *l = calloc(1, sizeof(List));

    l->cap  = n;
    l->data = calloc(n, sizeof(void *));

    return l;
}

static Data * newData(void *p, uint64_t size) {
    Data *d =  calloc(1, sizeof(Data));
    
    *d = (Data){
        .p = p,
        .size   = size
    };

    return d;
}

static void deleteList(List *l, ListType ty) {
    switch(ty) {
        case D:
            for(int i = 0; i < l->cap; i++) {
                free(l->data[i]);
            }
        case A:
            free(l->data);
    }
    free(l);
}

#define try_free(p) if(p) free(p);

static void deleteFile(File *f) {
    try_free(f->name);
    try_free(f->CTIME);
    try_free(f->MTIME);
    deleteList(f->attr, A);
    deleteList(f->data, D);
    free(f);
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

// Entryの全てのattributeをリストに登録して返す
static List * collectAttributes(MFTEntryHeader *hdr) {
    List *l = newList(10);
    MFTAttributeHeader *ahdr = attr_hdr(hdr);

    while(ahdr->AttributeType != END_OF_ATTRIBUTE) {
        if(l->len < l->cap) {
             l->data[l->len++] = ahdr;
        }
        ahdr = next_attr(ahdr);
    }

    return l;
}

// リストから指定したタイプのAttributeのリストを返す
// O(n)だけど、nは小さいのでヨシ!
static List * getAttribute(List *l, AttributeTypes ty) {
    List *list = newList(10);

    for(int i = 0; i < l->len; i++) {
        if(((MFTAttributeHeader *)l->data[i])->AttributeType == ty && list->len < list->cap) {
            list->data[list->len++] = l->data[i];     
        }
    }

    return list;
}

// DataRunsを解析してリストに登録(Non-residentの場合に使う)
static void parseDataRuns(uint8_t *r, List *l) {
    // 先頭1byteの下位4bitがdataの長さを、上位4bitがoffsetの長さをbyte単位で表す。
    int i = 0;
    uint8_t dataLen, deltaLen;
    uint64_t len = 0;
    // delataは符号付で、前のrunsのoffsetからの相対値(クラスタ単位)になる。
    uint64_t delta = 0, offset = 0;

    dataLen  = r[i] & 0x0f;
    deltaLen = (r[i]>>4) & 0x0f;
    i++;

    while(dataLen != 0 ||  deltaLen != 0) {
        for(int j = 0; j < dataLen; j++) {
            len += r[i++] << 8 * j;
        }
        for(int j = 0; j < deltaLen; j++) {
            delta += r[i++] << 8 * j;
        }

        // 負の値だった場合
        if(delta>>(8*deltaLen-1)){
            offset -= ((1<<deltaLen*8) - delta);
        } else {
            offset += delta;
        }

        if(l->len < l->cap) {
            l->data[l->len++] = newData(
                (void *)(volume.base + offset * volume.clusterSize)
                , len * volume.clusterSize
            );
        }
        len = delta = 0;
        dataLen  = r[i] & 0x0f;
        deltaLen = (r[i]>>4) & 0x0f;
        i++;
    };
}   

// fileのDATAを解析してサイズとポインタをリストに登録
static void parseDataAttributes(File *f) {
    // DATAのリストを取得する
    List *d = getAttribute(f->attr, DATA);

    // DATAを順に解析してリストに格納。
    List *l = newList(10);
    MFTAttributeHeader *hdr;
    for(int i = 0; i < d->len; i++) {
        hdr = d->data[i];
        switch(hdr->NonRegidentFlag) {
            case 0:
                if(l->len < l->cap) {
                    l->data[l->len++] = newData(
                        (uint8_t *)hdr + ((ResidentMFTAttribute *)attr(hdr))->DataOffset,
                        ((ResidentMFTAttribute *)attr(hdr))->DataSize
                    );
                }
                break;
            case 1:
                parseDataRuns(
                    data_run_list(hdr),
                    l
                );
                break;
        }
    }

    f->data = l;
    deleteList(d, A);
}

// fileのFILE_NAMEを解析して得た情報をFile構造体に登録
static void parseFnameAttribute(File *f) {
    List *l = getAttribute(f->attr, FILE_NAME);
    if(!l->len) 
        goto end;
    
    MFTAttributeHeader *hdr = l->data[0];

    // Non-residentだった場合はとりあえず何もしない
    if(hdr->NonRegidentFlag)
        return;
    
    FileNameAttribute *attr = fname_attribute(hdr);
    
    // 使い方合ってるかは知らん。まあ動いてるのでヨシ!
    setlocale(LC_ALL, "en_US.UTF-8");
    size_t n = 0;
    char *fname = calloc(1, 100);
    mbstate_t ps = {0};

    size_t len = 0;
    for(int i = 0; i < attr->NameStringSize; i++) {
        n  = c16rtomb(fname + len, attr->Name[i], &ps);
        len += n;
    }

    f->name     = fname;
    f->CTIME    =  time2str(attr->CTime);
    f->MTIME    = time2str(attr->MTime);

    end:
        deleteList(l, A);
}

// Fileが持つAttributeの一覧を表示
static void printAttributes(File *f) {
    puts("Attributes:");

    List *l = f->attr;
    for(int i = 0; i < l->len; i++) {
        MFTAttributeHeader *hdr = l->data[i];
        printf(
            "+%#lx: %#x(%s) %#x %d\n",
            (uint8_t *)hdr - volume.base,
            hdr->AttributeType,
            printAttributeType(hdr->AttributeType),
            hdr->Size,
            hdr->NonRegidentFlag
        );
    }
}

// Fileが持つdataの一覧を表示
static void printDataList(File *f) {
    List *l = f->data;
   
    if(!l->len)
        return;
    
    puts("Data list:");
    Data *d;

    for(int i = 0; i < l->len; i++) {
        d = l->data[i];
        printf(
            "+%#lx %#lx\n",
            (uint8_t *)d->p - volume.base,
            d->size
        );
    }
}

// fileの情報を表示
static void printFileInfo(File *f) {
    printf(
        "name: %s\nCTime: %s\nMTime: %s\n",
        f->name,
        f->CTIME,
        f->MTIME
    );
    printAttributes(f);
    printDataList(f);
}

// 指定されたindexのEntryを解析。未使用で無ければデータを収集してFile構造体に格納して返す。
static File * parseMFTEntry(MFTEntryHeader *hdr) {
    // AttributeOffsetが0なら未使用と判断する。本当は$BITMAPを読むべき
    if(!hdr->AttributeOffset) {
        return NULL;
    }

    // TODO: update sequeceの比較処理を関数として実装する。

    File *f = calloc(1, sizeof(File));
    f->attr = collectAttributes(hdr);

    parseDataAttributes(f);
    parseFnameAttribute(f);
    
    return f;
}

// volumeの情報をグローバルに保存
static void collectVolumeInfo(VolumeHeader *hdr) {
    volume = (Volume) {
        .base = (uint8_t *)hdr,
        .clusterSize    = cluster_size(hdr),
        .mftEntrySize   = entry_size(hdr->MFTEntrySize)
    };
    volume.mftOffset    = volume.clusterSize * hdr->MFTClusterBlockNumber;
}

// 指定されたindexへのポインタを返す。
static MFTEntryHeader * idx2entry(uint64_t i) {
    List *d = mft->data;
    uint64_t numEntry = ((Data *)(d->data[0]))->size / volume.mftEntrySize;

    if(numEntry <= i) {
        return NULL;
    }

    // MFTのDATAが複数存在する場合は考慮してない。
    return (MFTEntryHeader *)((uint8_t *)((Data *)(d->data[0]))->p + i * volume.mftEntrySize);
}

// ファイルが持っているデータをファイルに保存する
static void saveData(File *f) {
    List *l = f->data;
    Data *d;
    int fd;
    ssize_t n;

    char *fname = calloc(1, strlen(f->name) + 10);

    for(int i = 0; i < l->len; i++) {
        d = l->data[i];
        sprintf(
            fname, 
            "%s%d", 
            f->name,
            i
        );

        fd = open(
            fname,
            O_WRONLY|O_CREAT,
            S_IRUSR|S_IWUSR
        );

        if(fd == -1) {
            perror("open: ");
            continue;
        }

        n = write(fd, d->p, d->size);

        if(n == -1) {
            perror("write: ");
            close(fd);
            continue;
        }

        printf(
            "%d -> %s(%#lx bytes)\n",
            i,
            fname,
            n
        );

        close(fd);
    }

    free(fname);
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

    collectVolumeInfo((VolumeHeader *)base);
    printf(
        "base: %p\nclusterSize: %#lx\nmftEntrySize: %#lx\nmftOffset: %#lx\n",
        volume.base,
        volume.clusterSize,
        volume.mftEntrySize,
        volume.mftOffset
    );

    mft = parseMFTEntry((MFTEntryHeader *)(base + volume.mftOffset));
    if(!mft || !mft->data->len) {
        exit(1);
    }

    uint64_t i;
    MFTEntryHeader *e;
    File *f;

    while(true) {
        printf("index: ");

        scanf("%lu", &i);

        e = idx2entry(i);

        if(!e) {
            puts("invalid index");
            continue;
        }        

        f = parseMFTEntry(e);

        if(!f) {
            puts("unused entry");
            continue;
        }

        printFileInfo(f);

        if(f->data->len) {
            saveData(f);
        }

        deleteFile(f);
    }

    deleteFile(mft);
    munmap((void *)base, sb.st_size);
    close(fd);

    return 0;
}