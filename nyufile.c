#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#include <openssl/sha.h>

#define SHA_DIGEST_LENGTH 20


#pragma pack(push,1)
typedef struct BootEntry {
  unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
  unsigned char  BS_OEMName[8];     // OEM Name in ASCII
  unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
  unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
  unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
  unsigned char  BPB_NumFATs;       // Number of FATs
  unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
  unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
  unsigned char  BPB_Media;         // Media type
  unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
  unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
  unsigned short BPB_NumHeads;      // Number of heads in storage device
  unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
  unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
  unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
  unsigned short BPB_ExtFlags;      // A flag for FAT
  unsigned short BPB_FSVer;         // The major and minor version number
  unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
  unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
  unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
  unsigned char  BPB_Reserved[12];  // Reserved
  unsigned char  BS_DrvNum;         // BIOS INT13h drive number
  unsigned char  BS_Reserved1;      // Not used
  unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
  unsigned int   BS_VolID;          // Volume serial number
  unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
  unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)


#pragma pack(push,1)
typedef struct DirEntry {
  unsigned char  DIR_Name[11];      // File name
  unsigned char  DIR_Attr;          // File attributes
  unsigned char  DIR_NTRes;         // Reserved
  unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
  unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
  unsigned short DIR_CrtDate;       // Created day
  unsigned short DIR_LstAccDate;    // Accessed day
  unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
  unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
  unsigned short DIR_WrtDate;       // Written day
  unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
  unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)


unsigned char * files;
int * pos_entry;
BootEntry b;
DirEntry *d;
char * infor;       //error information
char * arg1;
char * arg2;
int count_entry=0;
char * diskname;
int * s;
unsigned char ** contents;
int * unallocated;


//string to hex
void string2hexString(unsigned char* input, char* output)
{
    int loop;
    int i;
    i=0;
    loop=0;
    while(input[loop] != '\0')
    {
        sprintf((char*)(output+i),"%02x", input[loop]);
        loop+=1;
        i+=2;
    }
    //insert NULL at the end of the output string
    output[i++] = '\0';
}

int sha(unsigned char * content){
    //sha1
    unsigned char md[SHA_DIGEST_LENGTH];
    size_t length = strlen((char *) content);
    SHA1(content, length, md);
    
    //str to hex
    int len = strlen((char *)md);
    char md1[(len*2)+1];
    string2hexString(md, md1);
    if (strcmp(arg2,md1)==0){
        return 1;
    }
    else{
        return 0;
    }
}


int entry(int * num_entry, int find){
    int i=0;
    //traverse root dir
    while(i<count_entry){
        //deleted file
        if (d[i].DIR_Name[0]==0xE5){
            //file name
            int n=1;
            char * filename = malloc(13*sizeof(char));
            filename[0]=arg1[0];
            
            int j=1;
            while(d[i].DIR_Name[j]!=' ' && j<=7){
                filename[n]=d[i].DIR_Name[j];
                n++;
                j++;
            }
            if (d[i].DIR_Name[8]!=' '){
                filename[n]='.';
                n++;
                j=8;
                while((j<=10) && (d[i].DIR_Name[j]!=' ')){
                    filename[n] = d[i].DIR_Name[j];
                    n++;
                    j++;
                }
            }
            filename[n]='\0';
            
            //compare arg1 and filename
            if (strcmp(filename,arg1)==0){
                num_entry[find]=i;
                num_entry=realloc(num_entry,(find+2)*sizeof(int));
                find++;
            }
            free(filename);
        }
        i++;
    }
    return find;
}



void con(unsigned char * content, int clus){
    int c=0;
    
    //location of content
    unsigned int loc=b.BPB_BytsPerSec * (b.BPB_RsvdSecCnt + b.BPB_NumFATs * b.BPB_FATSz32 + (clus-2)*b.BPB_SecPerClus);
    unsigned int j=loc;
    //before next cluster and not NULL
    while((j<(b.BPB_BytsPerSec * (b.BPB_RsvdSecCnt + b.BPB_NumFATs * b.BPB_FATSz32 + (clus+1-2)*b.BPB_SecPerClus))) && files[j]){
        content[c]=files[j];
        content=realloc(content,(c+2)*sizeof(unsigned char));
        c++;
        j++;
    }
    content[c]='\0';
}



void recover(int num_entry){
    //recover filename
    files[pos_entry[num_entry]]=arg1[0];
    
    //recover fat
    int clus = (d[num_entry].DIR_FstClusHI<<16) | (d[num_entry].DIR_FstClusLO);
    
    if(clus!=0){
        unsigned int num_cluster1 = d[num_entry].DIR_FileSize/(b.BPB_BytsPerSec*b.BPB_SecPerClus);
        
        if(d[num_entry].DIR_FileSize % (b.BPB_BytsPerSec*b.BPB_SecPerClus)==0){
            num_cluster1--;
        }
        
        int num_cluster = (int) num_cluster1;
        
        int m=0;
        while(m<b.BPB_NumFATs){
            int fat_pos = b.BPB_BytsPerSec * (b.BPB_RsvdSecCnt + m * b.BPB_FATSz32) + 32/8 * clus;
            
            int i=0;
            while (i<num_cluster){
                int n=clus+i+1;
                files[fat_pos+i*4] = n & 0xFF;
                files[fat_pos+1+i*4] = (n >> 8) & 0xFF;
                files[fat_pos+2+i*4] = (n >> 16) & 0xFF;
                files[fat_pos+3+i*4] = (n >> 24) & 0xFF;
                i++;
            }
            
            files[fat_pos+i*4] = 0xFF;
            files[fat_pos+1+i*4] = (char) 0xFF;
            files[fat_pos+2+i*4] = (char) 0xFF;
            files[fat_pos+3+i*4] = (char) 0x0F;
            m++;
        }
    }
    
    //write to fat32.disk
    int fd;
    fd = open(diskname, O_WRONLY);
    write(fd, files, b.BPB_TotSec16*b.BPB_BytsPerSec);
    close(fd);
}



void recover1(int num_entry,int num_cluster){
    
    //recover filename
    files[pos_entry[num_entry]]=arg1[0];
    
    //recover fat
    int clus = (d[num_entry].DIR_FstClusHI<<16) | (d[num_entry].DIR_FstClusLO);
    
    if(clus!=0){
        int m=0;
        while(m<b.BPB_NumFATs){
            int fat_pos;
            
            int i=0;
            while (i<num_cluster){
                fat_pos = b.BPB_BytsPerSec * (b.BPB_RsvdSecCnt + m * b.BPB_FATSz32) + 32/8 * unallocated[s[i]];
                int n = unallocated[s[i+1]];
                files[fat_pos] = n & 0xFF;;
                files[fat_pos+1] = (n >> 8) & 0xFF;
                files[fat_pos+2] = (n >> 16) & 0xFF;
                files[fat_pos+3] = (n >> 24) & 0xFF;
                i++;
            }
            fat_pos = b.BPB_BytsPerSec * (b.BPB_RsvdSecCnt + m * b.BPB_FATSz32) + 32/8 * unallocated[s[i]];
            files[fat_pos] = 0xFF;
            files[fat_pos+1] = (char) 0xFF;
            files[fat_pos+2] = (char) 0xFF;
            files[fat_pos+3] = (char) 0x0F;
            m++;
        }
    }
    
    //write to fat32.disk
    int fd;
    fd = open(diskname, O_WRONLY);
    write(fd, files, b.BPB_TotSec16*b.BPB_BytsPerSec);
    close(fd);
}



//boot sector
void showinfor(){
    printf("Number of FATs = %d\nNumber of bytes per sector = %d\nNumber of sectors per cluster = %d\nNumber of reserved sectors = %d\n", b.BPB_NumFATs, b.BPB_BytsPerSec, b.BPB_SecPerClus, b.BPB_RsvdSecCnt);
}



//list root dir
void listroot(){
    int i=0;
    int count=0;
    while(i<count_entry){
        if (d[i].DIR_Name[0]!=0xE5){
            //print name
            int j=0;
            while(d[i].DIR_Name[j]!=' ' && j<=7){
                printf("%c",d[i].DIR_Name[j]);
                j++;
            }
            if (d[i].DIR_Name[8]!=' '){
                printf(".");
                j=8;
                while(d[i].DIR_Name[j]!=' ' && j<=10){
                    printf("%c",d[i].DIR_Name[j]);
                    j++;
                }
            }
            else{
                if (d[i].DIR_Attr==0x10){
                    printf("/");
                }
            }
            
            //print size
            printf(" (size = %d,",d[i].DIR_FileSize);
            
            //print cluster
            int clus = (d[i].DIR_FstClusHI<<16) | (d[i].DIR_FstClusLO);
            printf(" starting cluster = %d)\n",clus);
            count++;
        }
        
        i++;
    }
    
    printf("Total number of entries = %d\n",count);
}

//recover file
void resmall(){
    
    int find=0;
    int num_entry=0;
    
    int i=0;
    
    //traverse root dir
    while(i<count_entry){
        
        //deleted file
        if (d[i].DIR_Name[0]==0xE5){
            //file name
            int n=1;
            char * filename = malloc(13*sizeof(char));
            filename[0]=arg1[0];
            
            int j=1;
            while(d[i].DIR_Name[j]!=' ' && j<=7){
                filename[n]=d[i].DIR_Name[j];
                n++;
                j++;
            }
            if (d[i].DIR_Name[8]!=' '){
                filename[n]='.';
                n++;
                j=8;
                while((j<=10) && (d[i].DIR_Name[j]!=' ')){
                    filename[n] = d[i].DIR_Name[j];
                    n++;
                    j++;
                }
            }
            filename[n]='\0';
            
            //compare arg1 and filename
            if (strcmp(filename,arg1)==0){
                num_entry=i;
                find++;
            }
            free(filename);
        }
        i++;
    }
    
    //multiple
    if (find>1){
        printf("%s: multiple candidates found\n",arg1);
        exit(-1);
    }
    //not found
    else if (find==0){
        printf("%s: file not found\n",arg1);
        exit(-1);
    }
    
    //recover
    recover(num_entry);
    printf("%s: successfully recovered\n",arg1);
}


void resha(){
    
    int find=0;
    int * num_entry=malloc(sizeof(int));
    
    int i=0;
    
    find = entry(num_entry,find);
    
    //possible result
    i=0;
    while(i<find){
        //content
        int c=0;
        unsigned char * content=malloc(sizeof(unsigned char));
        
        //first cluster
        int clus = (d[num_entry[i]].DIR_FstClusHI<<16) | (d[num_entry[i]].DIR_FstClusLO);
        int num_cluster = d[num_entry[i]].DIR_FileSize/(b.BPB_BytsPerSec*b.BPB_SecPerClus);
        if(d[num_entry[i]].DIR_FileSize % (b.BPB_BytsPerSec*b.BPB_SecPerClus)==0){
            num_cluster--;
        }
        
        //add to content
        int x=0;
        while(x<=num_cluster){
            //location of content
            unsigned int loc=b.BPB_BytsPerSec * (b.BPB_RsvdSecCnt + b.BPB_NumFATs * b.BPB_FATSz32 + (clus-2)*b.BPB_SecPerClus);
            unsigned int j=loc;
            //before next cluster and not NULL
            while((j<(b.BPB_BytsPerSec * (b.BPB_RsvdSecCnt + b.BPB_NumFATs * b.BPB_FATSz32 + (clus+1-2)*b.BPB_SecPerClus))) && files[j]){
                content[c]=files[j];
                content=realloc(content,(c+2)*sizeof(unsigned char));
                c++;
                j++;
            }
            clus++;
            x++;
        }
        content[c]='\0';
        
        //sha1
        if (sha(content)==1){
            break;
        }
        i++;
    }
    
    //no file
    if(i==find){
        printf("%s: file not found\n",arg1);
        exit(-1);
    }
    
    //recover
    recover(num_entry[i]);
    printf("%s: successfully recovered with SHA-1\n",arg1);
}


int dfs(int i1, int num, int num_cluster, int uc){
    
    s[num]=i1;
    
    if(num_cluster==num+1){
        //merge contents
        unsigned char * r = malloc((num_cluster*b.BPB_BytsPerSec*b.BPB_SecPerClus+1)*sizeof(unsigned char));
        
        int m=0;int m1=0;int m2=0;
        while(m<num_cluster){
            m1=0;
            while(contents[s[m]][m1]){
                r[m2]=contents[s[m]][m1];
                m1++;
                m2++;
            }
            m++;
        }
        r[m2]='\0';
        
        if (sha(r)){
            return 1;
        }
        else{
            return 0;
        }
    }
    else{
        for(int i2=0;i2<uc;i2++){
            int ss=0;
            for(int i3=0;i3<num+1;i3++){
                if(s[i3]==i2){
                    ss=1;
                }
            }
            if(ss==0){
                if(dfs(i2,num+1,num_cluster,uc)){
                    return 1;
                }
            }
        }
        return 0;
    }
}



void rencon(){
    
    //possible entry
    int find=0;
    int * num_entry=malloc(sizeof(int));
    int i=0;
    find=entry(num_entry,find);
    
    //unallocated first 12 cluster
    unallocated = malloc(sizeof(int));
    int uc=0;
    for(i=2;i<=11;i++){
        int fat_pos = b.BPB_BytsPerSec * (b.BPB_RsvdSecCnt) + 32/8 * i;
        int clus_entry = files[fat_pos] << 24 | files[fat_pos+1]<<16 | files[fat_pos+2]<<8 | files[fat_pos+3];
        if(clus_entry==0){
            unallocated[uc]=i;
            unallocated=realloc(unallocated,(uc+2)*sizeof(int));
            uc++;
        }
    }
    
    //unallocated cluster contents
    contents=malloc(11*sizeof(unsigned char *));
    for(int j=0;j<uc;j++){
        contents[j]=malloc((b.BPB_BytsPerSec*b.BPB_SecPerClus+1) *sizeof(unsigned char));
        con(contents[j],unallocated[j]);
    }
    
    //cluster position in unallocated order
    int result=0;
    int s1[]={0,0,0,0,0,0,0,0,0,0,0,0}; //next clus
    s=s1;
    
    int num_cluster=0;
    
    //possible files
    i=0;
    while(i<find){
        
        num_cluster = d[num_entry[i]].DIR_FileSize/(b.BPB_BytsPerSec*b.BPB_SecPerClus);
        
        if(d[num_entry[i]].DIR_FileSize % (b.BPB_BytsPerSec*b.BPB_SecPerClus)!=0){
            num_cluster++;
        }
        
        //first cluster
        int clus = (d[num_entry[i]].DIR_FstClusHI<<16) | (d[num_entry[i]].DIR_FstClusLO);
        
        if(clus!=0){
            for(int j=0;j<uc;j++){
                if(unallocated[j]==clus){
                    s[0]=j;
                    break;
                }
            }
            
            if(num_cluster==1){
                if (sha(contents[clus])){
                    result=1;
                    break;
                }
            }
            else{
                for(int i1=0;i1<uc;i1++){
                    if(i1!=s[0]){
                        if(dfs(i1,1,num_cluster,uc)){
                            result=1;
                            break;
                        }
                    }
                }
            }
        }
        else{
            unsigned char * empt = malloc(sizeof(unsigned char));
            empt[0]='\0';
            if(sha(empt)){
                result=1;
                break;
            }
        }
        
        if(result!=0){
            break;
        }
        i++;
    }
    
    //no file
    if(i==find){
        printf("%s: file not found\n",arg1);
        exit(-1);
    }
    
    //recover
    recover1(num_entry[i],num_cluster-1);
        
    printf("%s: successfully recovered with SHA-1\n",arg1);
}



void failed(){
    printf("%s\n",infor);
    exit(EXIT_FAILURE);
}




//The main function
int main(int argc, char *argv[])
{
    //error information
    char infor1[]="Usage: ./nyufile disk <options>\n  -i                     Print the file system information.\n  -l                     List the root directory.\n  -r filename [-s sha1]  Recover a contiguous file.\n  -R filename -s sha1    Recover a possibly non-contiguous file.";
    infor=infor1;
    
    //-s
    char strs[] = "-s";
    
    //no disk
    if (argc<3){
        failed();
    }
    
    //third is not option
    char ch = '-';
    if (strchr(argv[2],ch)==NULL){
        failed();
    }
    
    //read command
    int option;
    int existi=0;int existl=0;int existr=0;int existR=0;int exists=0;
    while ((option = getopt (argc, argv, "ilr:R:s:")) != -1){
        switch (option)
        {
            case 'i':
                if (existi==1 || existl==1 || existr==1 || existR==1 || exists==1 || argc!=3){
                    failed();
                }
                existi=1;
                break;
            case 'l':
                if (existi==1 || existl==1 || existr==1 || existR==1 || exists==1 || argc!=3){
                    failed();
                }
                existl=1;
                break;
            case 'r':
                if (existi==1 || existl==1 || existr==1 || existR==1 || exists==1 || (argc!=4 && argc!=6)){
                    failed();
                }
                if (argc==6 && strcmp(argv[argc-2],strs)!=0){
                    failed();
                }
                arg1=optarg;
                existr=1;
                break;
            case 'R':
                if (existi==1 || existl==1 || existr==1 || existR==1 || exists==1 || strcmp(argv[argc-2],strs)!=0 || argc!=6){
                    failed();
                }
                arg1=optarg;
                existR=1;
                break;
            case 's':
                if (existi==1 || existl==1 || (existr==0 && existR==0) || exists==1){
                    failed();
                }
                arg2=optarg;
                exists=1;
                break;
            default :
                failed();
        }
    }
    
    //no options
    if (existi==0 && existl==0 && existr==0 && existR==0){
        failed();
    }
    
    diskname=argv[optind];
    
    //map disk
    int fd;
    struct stat s;
    fd = open(argv[optind], O_RDONLY);
    fstat (fd, & s);
    files = mmap (0, s.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);
    
    //get boot sector
    memcpy(&b, &files[0], sizeof(BootEntry));
    
    //root dir
    pos_entry = malloc(sizeof(int));
    
    int pos = b.BPB_BytsPerSec * (b.BPB_RsvdSecCnt + b.BPB_NumFATs * b.BPB_FATSz32 + (b.BPB_RootClus-2)*b.BPB_SecPerClus);
    int end_pos = b.BPB_BytsPerSec * (b.BPB_RsvdSecCnt + b.BPB_NumFATs * b.BPB_FATSz32 + (b.BPB_RootClus-2+1)*b.BPB_SecPerClus);
    
    d=malloc(sizeof(DirEntry));
    
    int i=pos;
    while(i<end_pos && files[i]){
        pos_entry[count_entry] = i;
        pos_entry = realloc(pos_entry,(count_entry+2)*sizeof(int));
        memcpy(&d[count_entry], &files[i], sizeof(DirEntry));
        d=realloc(d,(count_entry+2)*sizeof(DirEntry));
        count_entry++;
        i=i+32;
    }
    
    int next = b.BPB_BytsPerSec * (b.BPB_RsvdSecCnt) + (b.BPB_RootClus)*4;
    int next_clus = files[next+3]<<24 | files[next+2]<<16 | files[next+1]<<8 | files[next];
    
    while(next_clus<0x0ffffff8){
        pos = b.BPB_BytsPerSec * (b.BPB_RsvdSecCnt + b.BPB_NumFATs * b.BPB_FATSz32 + (next_clus-2)*b.BPB_SecPerClus);
        
        end_pos = b.BPB_BytsPerSec * (b.BPB_RsvdSecCnt + b.BPB_NumFATs * b.BPB_FATSz32 + (next_clus-2+1)*b.BPB_SecPerClus);
        
        i=pos;
        while(i<end_pos && files[i]){
            pos_entry[count_entry] = i;
            pos_entry = realloc(pos_entry,(count_entry+2)*sizeof(int));
            memcpy(&d[count_entry], &files[i], sizeof(DirEntry));
            d=realloc(d,(count_entry+2)*sizeof(DirEntry));
            count_entry++;
            i=i+32;
        }
        
        next = b.BPB_BytsPerSec * (b.BPB_RsvdSecCnt) + (next_clus)*4;
        next_clus = files[next+3]<<24 | files[next+2]<<16 | files[next+1]<<8 | files[next];
    }
    
    //-i
    if (existi==1){
        showinfor();
    }
    //-l
    else if(existl==1){
        listroot();
    }
    //-r
    else if(existr==1 && exists==0){
        resmall();
    }
    //-r -s
    else if(existr==1 && exists==1){
        resha();
    }
    //-R -s
    else if(existR==1 && exists==1){
        rencon();
    }
    
}
